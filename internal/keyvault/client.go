/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package keyvault keeps a certificate in an Azure Key Vault in sync with the
// controller-managed certificate. It authenticates as the identity's Entra app
// using that identity's certificate (client-certificate credential), so the app
// service principal — not the controller — must have get and import permissions
// on the vault.
package keyvault

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
)

const pemContentType = "application/x-pem-file"

// Cloud selects the Azure sovereign cloud.
type Cloud string

const (
	// CloudPublic is the Azure public cloud.
	CloudPublic Cloud = "Public"
	// CloudUSGov is the Azure US Government cloud.
	CloudUSGov Cloud = "USGov"
)

type cloudConfig struct {
	azureCloud  cloud.Configuration
	vaultSuffix string
}

var cloudConfigs = map[Cloud]cloudConfig{
	CloudPublic: {cloud.AzurePublic, "vault.azure.net"},
	CloudUSGov:  {cloud.AzureGovernment, "vault.usgovcloudapi.net"},
}

// certOps is the subset of *azcertificates.Client the sync uses; it is an
// interface so tests can substitute a fake.
type certOps interface {
	GetCertificate(ctx context.Context, name, version string, options *azcertificates.GetCertificateOptions) (azcertificates.GetCertificateResponse, error)
	ImportCertificate(ctx context.Context, name string, parameters azcertificates.ImportCertificateParameters, options *azcertificates.ImportCertificateOptions) (azcertificates.ImportCertificateResponse, error)
}

// Client syncs a certificate into a single Azure Key Vault.
type Client struct {
	certs certOps
}

// NewClient builds a Key Vault certificate client for the named vault in the
// given cloud, authenticating as the Entra app (tenantID/appID) with the
// identity's certificate and RSA private key.
func NewClient(vaultName, tenantID, appID string, cl Cloud, cert *x509.Certificate, key *rsa.PrivateKey) (*Client, error) {
	cfg, ok := cloudConfigs[cl]
	if !ok {
		return nil, fmt.Errorf("keyvault: unknown cloud %q", cl)
	}
	cred, err := azidentity.NewClientCertificateCredential(
		tenantID,
		appID,
		[]*x509.Certificate{cert},
		crypto.PrivateKey(key),
		&azidentity.ClientCertificateCredentialOptions{
			ClientOptions: azcore.ClientOptions{Cloud: cfg.azureCloud},
		},
	)
	if err != nil {
		return nil, err
	}
	vaultURL := fmt.Sprintf("https://%s.%s", vaultName, cfg.vaultSuffix)
	certs, err := azcertificates.NewClient(vaultURL, cred, &azcertificates.ClientOptions{
		ClientOptions: azcore.ClientOptions{Cloud: cfg.azureCloud},
	})
	if err != nil {
		return nil, err
	}
	return &Client{certs: certs}, nil
}

// CertificateMatches reports whether the vault's current certificate has the
// given SHA-1 thumbprint (uppercase hex). A missing certificate reports false.
func (c *Client) CertificateMatches(ctx context.Context, certName, thumbprint string) (bool, error) {
	resp, err := c.certs.GetCertificate(ctx, certName, "", nil)
	if err != nil {
		var re *azcore.ResponseError
		if errors.As(err, &re) && re.StatusCode == http.StatusNotFound {
			return false, nil
		}
		return false, err
	}
	if len(resp.CER) == 0 {
		return false, nil
	}
	sum := sha1.Sum(resp.CER)
	return strings.EqualFold(thumbprint, hex.EncodeToString(sum[:])), nil
}

// ImportCertificate imports a PEM bundle (certificate chain plus private key)
// into the vault under certName, creating or updating it.
func (c *Client) ImportCertificate(ctx context.Context, certName string, pemBundle []byte) error {
	b64 := base64.StdEncoding.EncodeToString(pemBundle)
	contentType := pemContentType
	_, err := c.certs.ImportCertificate(ctx, certName, azcertificates.ImportCertificateParameters{
		Base64EncodedCertificate: &b64,
		CertificatePolicy: &azcertificates.CertificatePolicy{
			SecretProperties: &azcertificates.SecretProperties{ContentType: &contentType},
		},
	}, nil)
	return err
}
