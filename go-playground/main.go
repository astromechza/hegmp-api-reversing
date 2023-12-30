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
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))

	h := &(*http.DefaultClient)
	h.Jar, _ = cookiejar.New(&cookiejar.Options{PublicSuffixList: nil})
	slog.Info(fmt.Sprintf("%v", h))
	baseCcApiUrl, _ := url.Parse(`https://prd.eu-ccapi.hyundai.com:8080/api/v1`)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	stateNonce, err := oauthPrepareLogin(ctx, h, baseCcApiUrl)
	if err != nil {
		log.Fatal(err.Error())
	}

	authCode, err := oauthLogin(ctx, h, baseCcApiUrl, os.Getenv("EMAIL"), os.Getenv("PASSWORD"), stateNonce)
	if err != nil {
		log.Fatal(err.Error())
	}
	slog.Info("Received authorization code", "code", authCode)
}

const (
	oauthClientId = "6d477c38-3ca4-4cf3-9557-2a1929a94654"
)

// oauthPrepareLogin loads the initial login session and sets up the state nonce and oauth params for the
// authorization server. This is required to set the cookies containing the oauth state.
func oauthPrepareLogin(ctx context.Context, client *http.Client, baseUrl *url.URL) (string, error) {
	stateNonce := uuid.New().String()
	u := baseUrl.JoinPath("user/oauth2/authorize")
	u.RawQuery = url.Values{
		"response_type": []string{"code"},
		"client_id":     []string{oauthClientId},
		"redirect_uri":  []string{baseUrl.JoinPath("user/oauth2/redirect").String()},
		"state":         []string{stateNonce},
		"lang":          []string{"en"},
	}.Encode()
	req, err := http.NewRequest(
		http.MethodGet,
		u.String(),
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	logHttpRequest(req)
	if resp, err := client.Do(req.WithContext(ctx)); err != nil {
		return "", fmt.Errorf("failed to make request: %w", err)
	} else {
		defer func() {
			if err := resp.Body.Close(); err != nil {
				slog.Error("failed to close response body", "err", err)
			}
		}()
		logHttpResponse(resp)
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}
		return stateNonce, nil
	}
}

// oauthLogin does the actual login to the authorization server and extracts the expected redirect url from the
// response body.
func oauthLogin(ctx context.Context, client *http.Client, baseUrl *url.URL, email, password, expectedStateNonce string) (string, error) {
	payload, _ := json.Marshal(map[string]interface{}{
		"email":    email,
		"password": password,
	})
	u := baseUrl.JoinPath("user", "signin")
	req, err := http.NewRequest(
		http.MethodPost,
		u.String(),
		bytes.NewBuffer(payload),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	logHttpRequest(req)
	if resp, err := client.Do(req.WithContext(ctx)); err != nil {
		return "", fmt.Errorf("failed to make request: %w", err)
	} else {
		defer func() {
			if err := resp.Body.Close(); err != nil {
				slog.Error("failed to close response body", "err", err)
			}
		}()
		logHttpResponse(resp)
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

func logHttpRequest(req *http.Request) {
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
}

type errorReader struct {
	err error
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	return 0, r.err
}

func logHttpResponse(resp *http.Response) {
	var bodyCopy = []byte(``)
	if resp.Body != nil {
		var err error
		if bodyCopy, err = io.ReadAll(resp.Body); err != nil {
			resp.Body = io.NopCloser(&errorReader{err: err})
		} else {
			resp.Body = io.NopCloser(bytes.NewReader(bodyCopy))
		}
	}
	headers := new(bytes.Buffer)
	_ = resp.Header.Write(headers)
	encodedHeaders := strings.TrimSpace(strings.ReplaceAll(headers.String(), "\r\n", "\n"))
	slog.Debug("received http response", "code", resp.StatusCode, "headers", encodedHeaders, "body", string(bodyCopy))
}
