// Package ebay implements the OAuth2 protocol for authenticating users through
// eBay.
package ebay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/markbates/goth"

	"golang.org/x/oauth2"
)

// Provider is the implementation of `goth.Provider` for accessing eBay.
type Provider struct {
	AuthURL      string
	TokenURL     string
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
}

// New creates a new eBay provider and sets up important connection details.
// You should always call `cloudfoundry.New` to get a new provider.  Never try
// to create one manually.
func New(ebayAPI, clientKey, secret, callbackURL string, scopes ...string) *Provider {
	ebayAPI = strings.TrimSuffix(ebayAPI, "/")

	apiURL, err := url.Parse(ebayAPI)
	if err != nil {
		// ?
		panic(err)
	}

	hostname := strings.TrimPrefix(apiURL.Hostname(), "api.")
	authURL := fmt.Sprintf("%s://signin.%s/authorize", apiURL.Scheme, hostname)

	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		AuthURL:      authURL,
		TokenURL:     ebayAPI + "/identity/v1/oauth2/token",
		providerName: "ebay",
	}
	p.config = newConfig(p, scopes)
	return p
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple
// providers of 1 type).
func (p *Provider) SetName(name string) {
	p.providerName = name
}

func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is no-op.
func (*Provider) Debug(bool) {}

// BeginAuth asks eBay for an authentication endpoint.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

// FetchUser will go to Cloud Foundry and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	s := session.(*Session)
	user := goth.User{
		AccessToken:  s.AccessToken,
		Provider:     p.Name(),
		RefreshToken: s.RefreshToken,
		ExpiresAt:    s.ExpiresAt,
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}
	return user, nil
}

// RefreshTokenAvailable refresh token is provided by auth provider or not.
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

// RefreshToken get new access token based on the refresh token.
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ctx := context.WithValue(goth.ContextForClient(p.Client()), oauth2.HTTPClient, goth.HTTPClientWithFallBack(p.Client()))
	ts := p.config.TokenSource(ctx, token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}

func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  provider.AuthURL,
			TokenURL: provider.TokenURL,
		},
		Scopes: scopes,
	}

	return c
}

// Session stores data during the auth process with eBay.
type Session struct {
	AuthURL      string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

var _ goth.Session = &Session{}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the
// eBay provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New("an AuthURL has not been set")
	}
	return s.AuthURL, nil
}

// Authorize the session with eBay and return the access token to be stored for
// future use.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	ctx := context.WithValue(goth.ContextForClient(p.Client()), oauth2.HTTPClient, p.Client())
	token, err := p.config.Exchange(ctx, params.Get("code"))
	if err != nil {
		return "", err
	}

	if !token.Valid() {
		return "", errors.New("Invalid token received from provider")
	}

	s.AccessToken = token.AccessToken
	s.RefreshToken = token.RefreshToken
	s.ExpiresAt = token.Expiry
	return token.AccessToken, err
}

// Marshal the session into a string
func (s Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s Session) String() string {
	return s.Marshal()
}

// UnmarshalSession wil unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	s := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(s)
	return s, err
}
