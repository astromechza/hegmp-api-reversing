// NOTES
// basically what we see is that underneath everything there is a semi-reasonable oauth based API which is documented here
// https://developers.hyundai.com/web/v1/hyundai/specification/account/account_token albiet in korean. You go through a flow
// to get an auth code which you can then provide back to the service to get an access, refresh, and id token.
// It's unclear, possibly a bit unlikely that you need the cookie once you've got the access token. This remains to be
// tested. It's very likely that it's just the oauth flow used by the bluelink apps that are fragile, while the core ccapi
// is fairly stable.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

const (
	oauthClientId     = "6d477c38-3ca4-4cf3-9557-2a1929a94654"
	oauthClientSecret = "KUy49XxPzLpLuoK0xhBC77W6VXhmtQR9iQhmIFjjoY4IpxsV"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))

	client := &(*http.DefaultClient)
	client.Transport = &TransportWithRequestLogging{Inner: http.DefaultTransport}
	client.Jar, _ = cookiejar.New(&cookiejar.Options{PublicSuffixList: nil})
	slog.Info(fmt.Sprintf("%v", client))
	baseCcApiUrl, _ := url.Parse(`https://prd.eu-ccapi.hyundai.com:8080/api/v1`)

	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()

	conf := oauth2.Config{
		ClientID:     oauthClientId,
		ClientSecret: oauthClientSecret,
		Scopes:       []string{},
		RedirectURL:  baseCcApiUrl.JoinPath("user", "oauth2", "redirect").String(),
		Endpoint: oauth2.Endpoint{
			AuthURL:   baseCcApiUrl.JoinPath("user", "oauth2", "authorize").String(),
			TokenURL:  baseCcApiUrl.JoinPath("user", "oauth2", "token").String(),
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}

	stateNonce2 := uuid.New().String()
	authCodeUrl2 := conf.AuthCodeURL(stateNonce2, oauth2.SetAuthURLParam("lang", "en"))
	slog.Info(authCodeUrl2)

	authCode, err := oauth2AcceptAndLogin(ctx, client, authCodeUrl2, baseCcApiUrl.JoinPath("user", "signin").String(), os.Getenv("EMAIL"), os.Getenv("PASSWORD"), stateNonce2)
	if err != nil {
		log.Fatal(err.Error())
	}
	slog.Info("Received authorization code", "code", authCode)

	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{
		Transport: &TransportWithHeadAuth{ClientId: oauthClientId, ClientSecret: oauthClientSecret, Inner: client.Transport},
	})
	tokens, err := conf.Exchange(ctx, authCode)
	if err != nil {
		log.Fatal(err.Error())
	}
	slog.Info("Received token", "token", tokens)

	client3 := conf.Client(ctx, tokens)

	req, _ := http.NewRequest(http.MethodGet, baseCcApiUrl.JoinPath("spa", "vehicles").String(), nil)
	req.Header.Set("ccsp-service-id", oauthClientId)
	req.Header.Set("ccsp-application-id", "014d2225-8495-4735-812d-2616334fd15d")

	resp, err := client3.Do(req)
	if err != nil {
		log.Fatal(err.Error())
	}
	slog.Info("vehicles response received", "code", resp.StatusCode)

}

type TransportWithHeadAuth struct {
	ClientId     string
	ClientSecret string
	Inner        http.RoundTripper
}

func (t *TransportWithHeadAuth) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Header.Get("Authorization") == "" {
		request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", t.ClientId, t.ClientSecret))))
	}
	return t.Inner.RoundTrip(request)
}

type TransportWithRequestLogging struct {
	Inner http.RoundTripper
}

func (t *TransportWithRequestLogging) RoundTrip(req *http.Request) (*http.Response, error) {
	var bodyCopy = []byte(``)
	if req.Body != nil {
		bodyCopy, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(bodyCopy))
	}
	headers := new(bytes.Buffer)
	_ = req.Header.Write(headers)
	encodedHeaders := strings.TrimSpace(strings.ReplaceAll(headers.String(), "\r\n", "\n"))
	logBody := string(bodyCopy)
	for _, k := range []string{"PASSWORD", "EMAIL"} {
		if v := os.Getenv(k); v != "" {
			logBody = strings.ReplaceAll(logBody, v, "<"+k+">")
		}
	}
	slog.Debug("sending http request", "method", req.Method, "url", req.URL.String(), "headers", encodedHeaders, "body", logBody)

	resp, err := t.Inner.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	bodyCopy = []byte(``)
	if resp.Body != nil {
		var err error
		if bodyCopy, err = io.ReadAll(resp.Body); err != nil {
			resp.Body = io.NopCloser(&errorReader{err: err})
		} else {
			resp.Body = io.NopCloser(bytes.NewReader(bodyCopy))
		}
	}
	headers = new(bytes.Buffer)
	_ = resp.Header.Write(headers)
	encodedHeaders = strings.TrimSpace(strings.ReplaceAll(headers.String(), "\r\n", "\n"))
	slog.Debug("received http response", "code", resp.StatusCode, "headers", encodedHeaders, "body", string(bodyCopy))
	return resp, nil
}

func oauth2AcceptAndLogin(ctx context.Context, client *http.Client, prepareUrl, signinUrl, email, password, expectedStateNonce string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, prepareUrl, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	if resp, err := client.Do(req.WithContext(ctx)); err != nil {
		return "", fmt.Errorf("failed to make request: %w", err)
	} else {
		defer func() {
			if err := resp.Body.Close(); err != nil {
				slog.Error("failed to close response body", "err", err)
			}
		}()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"email":    email,
		"password": password,
	})
	req, err = http.NewRequest(http.MethodPost, signinUrl, bytes.NewBuffer(payload))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if resp, err := client.Do(req.WithContext(ctx)); err != nil {
		return "", fmt.Errorf("failed to make request: %w", err)
	} else {
		defer func() {
			if err := resp.Body.Close(); err != nil {
				slog.Error("failed to close response body", "err", err)
			}
		}()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}
		var out struct {
			RedirectUrl string `json:"redirectUrl"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return "", fmt.Errorf("failed to decode body: %w", err)
		}
		if parsedUrl, err := url.Parse(out.RedirectUrl); err != nil {
			return "", fmt.Errorf("failed to parse redirect url: %w", err)
		} else if stateV := parsedUrl.Query().Get("state"); stateV != expectedStateNonce {
			return "", fmt.Errorf("redirect url was missing the correct state nonce '%s' != '%s'", stateV, expectedStateNonce)
		} else if v := parsedUrl.Query().Get("code"); v == "" {
			return "", fmt.Errorf("redirect url was missing code")
		} else {
			return v, nil
		}
	}
}

type errorReader struct {
	err error
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	return 0, r.err
}
