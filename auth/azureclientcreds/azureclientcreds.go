// Package azurecreds implements AAD Username/Password Auth Flow
// See more:
//   - https://docs.microsoft.com/en-us/azure/developer/go/azure-sdk-authorization#use-file-based-authentication
//
// Amongst supported platform versions are:
//   - SharePoint Online + Azure
package azureclientcreds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/koltyakov/gosip"
	"github.com/koltyakov/gosip/cpass"
	"github.com/patrickmn/go-cache"
)

var (
	storage = cache.New(5*time.Minute, 10*time.Minute)
)

// AuthCnfg - AAD Client Credential Auth Flow
// To use this strategy public client flows mobile and desktop should be enabled in the app registration
/* Config sample:
{
  "siteUrl": "https://contoso.sharepoint.com/sites/test",
	"tenantId": "e4d43069-8ecb-49c4-8178-5bec83c53e9d",
  "clientId": "e2763c6d-7ee6-41d6-b15c-dd1f75f90b8f",
  "clientSecret": "OqDSAAuBChzI+uOX0OUhXxiOYo1g6X7mjXCVA9mSF/0="
}
*/
type AuthCnfg struct {
	SiteURL      string `json:"siteUrl"`      // SPSite or SPWeb URL, which is the context target for the API calls
	TenantID     string `json:"tenantId"`     // Azure Tenant ID
	ClientID     string `json:"clientId"`     // Azure Client ID
	ClientSecret string `json:"clientSecret"` // Azure Client secret

	masterKey string
}

// SetMasterkey defines custom masterkey
func (c *AuthCnfg) SetMasterkey(masterKey string) { c.masterKey = masterKey }

// ReadConfig reads private config with auth options
func (c *AuthCnfg) ReadConfig(privateFile string) error {
	f, err := os.Open(privateFile)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	byteValue, _ := io.ReadAll(f)
	return c.ParseConfig(byteValue)
}

// ParseConfig parses credentials from a provided JSON byte array content
func (c *AuthCnfg) ParseConfig(byteValue []byte) error {
	if err := json.Unmarshal(byteValue, &c); err != nil {
		return err
	}
	crypt := cpass.Cpass(c.masterKey)
	secret, err := crypt.Decode(c.ClientSecret)
	if err == nil {
		c.ClientSecret = secret
	}
	return nil
}

// WriteConfig writes private config with auth options
func (c *AuthCnfg) WriteConfig(privateFile string) error {
	crypt := cpass.Cpass(c.masterKey)
	secret, err := crypt.Encode(c.ClientSecret)
	if err != nil {
		return err
	}
	config := &AuthCnfg{
		SiteURL:      c.SiteURL,
		TenantID:     c.TenantID,
		ClientID:     c.ClientID,
		ClientSecret: secret,
	}
	file, _ := json.MarshalIndent(config, "", "  ")
	return os.WriteFile(privateFile, file, 0644)
}

// GetAuth authenticates, receives access token
func (c *AuthCnfg) GetAuth() (string, int64, error) {
	// Get from cache
	parsedURL, err := url.Parse(c.SiteURL)
	if err != nil {
		return "", 0, err
	}
	cacheKey := parsedURL.Host + "@" + c.GetStrategy() + "@" + c.TenantID + "@" + c.ClientID
	if accessToken, exp, found := storage.GetWithExpiration(cacheKey); found {
		return accessToken.(string), exp.Unix(), nil
	}

	resource := fmt.Sprintf("https://%s", parsedURL.Host)

	cred, err := azidentity.NewClientSecretCredential(c.TenantID, c.ClientID, c.ClientSecret, nil)
	if err != nil {
		return "", 0, err
	}

	tokenOpts := policy.TokenRequestOptions{
		Scopes: []string{fmt.Sprintf("%s/.default", resource)},
	}
	token, err := cred.GetToken(context.Background(), tokenOpts)
	if err != nil {
		return "", 0, err
	}

	// Save to cache
	exp := token.ExpiresOn.Add(-60 * time.Second)
	storage.Set(cacheKey, token.Token, time.Until(exp))

	return token.Token, exp.Unix(), nil
}

// GetSiteURL gets SharePoint siteURL
func (c *AuthCnfg) GetSiteURL() string { return c.SiteURL }

// GetStrategy gets auth strategy name
func (c *AuthCnfg) GetStrategy() string { return "azureclientcreds" }

// SetAuth authenticates request
// noinspection GoUnusedParameter
func (c *AuthCnfg) SetAuth(req *http.Request, httpClient *gosip.SPClient) error {
	authToken, _, err := c.GetAuth()
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	return err
}

// Preparer implements autorest.Preparer interface
type preparer struct{}

// Prepare satisfies autorest.Preparer interface
func (p preparer) Prepare(req *http.Request) (*http.Request, error) { return req, nil }
