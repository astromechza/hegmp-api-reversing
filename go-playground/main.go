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

	"github.com/astromechza/hegmp-api-reversing/go-playground/hyundaiclient"
)

// All the constants that a client application needs to know and has pre-registered with the Hyundai APIs.
// Getting any of these wrong will result in requests failing since they don't match the expected state on the remote
// end.
const (
	//
	oauthClientId     = "6d477c38-3ca4-4cf3-9557-2a1929a94654"
	oauthClientSecret = "KUy49XxPzLpLuoK0xhBC77W6VXhmtQR9iQhmIFjjoY4IpxsV"
	//
	appId       = "014d2225-8495-4735-812d-2616334fd15d"
	appStampKey = "\x44\x5b\x68\x46\xaf\xef\x0d\x72\x66\x46\x77\x68\x65\xa6\x50" +
		"\xc9\xf3\xa8\xb7\xb3\xab\x22\xa1\x95\x16\x3f\x7a\x89\x8d\x96" +
		"\x2f\x7c\xb2\x1f\x96\x7f\xa5\x4b\xe5\x52\x1a\xa6\x0b\x10\xf6" +
		"\xb7\xe0\xfa\xe5\x24"
	// This push type is presumably unique to the app id, since if the app id was sniffed from an android app it would be GCM, but if
	// sniffed from an iOS app it may be APNS.
	appNotificationPushType = "GCM"
)

func ref[k any](input k) *k {
	return &input
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))

	client := &(*http.DefaultClient)
	client.Transport = &TransportWithRequestLogging{Inner: http.DefaultTransport}
	client.Jar, _ = cookiejar.New(&cookiejar.Options{PublicSuffixList: nil})
	slog.Info(fmt.Sprintf("%v", client))
	baseCcApiUrl, _ := url.Parse(`https://prd.eu-ccapi.hyundai.com:8080/api`)
	usersApiUrl := baseCcApiUrl.JoinPath("v1", "user")

	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()

	conf := oauth2.Config{
		ClientID:     oauthClientId,
		ClientSecret: oauthClientSecret,
		Scopes:       []string{},
		RedirectURL:  usersApiUrl.JoinPath("oauth2", "redirect").String(),
		Endpoint: oauth2.Endpoint{
			AuthURL:   usersApiUrl.JoinPath("oauth2", "authorize").String(),
			TokenURL:  usersApiUrl.JoinPath("oauth2", "token").String(),
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}

	stateNonce2 := uuid.New().String()
	authCodeUrl2 := conf.AuthCodeURL(stateNonce2, oauth2.SetAuthURLParam("lang", "en"))
	slog.Info(authCodeUrl2)

	authCode, err := oauth2AcceptAndLogin(ctx, client, authCodeUrl2, usersApiUrl.JoinPath("signin").String(), os.Getenv("EMAIL"), os.Getenv("PASSWORD"), stateNonce2)
	if err != nil {
		log.Fatal(err.Error())
	}
	slog.Info("Received authorization code", "code", authCode)

	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{
		Transport: &TransportWithRequestModifier{
			Modifier: func(req *http.Request) *http.Request {
				if req.Header.Get("Authorization") == "" {
					req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", conf.ClientID, conf.ClientSecret))))
				}
				return req
			},
			Inner: client.Transport,
		},
	})
	tokens, err := conf.Exchange(ctx, authCode)
	if err != nil {
		log.Fatal(err.Error())
	}
	slog.Info("Received token", "token", tokens)

	client3 := conf.Client(ctx, tokens)
	client3.Transport = &TransportWithRequestModifier{
		Modifier: func(req *http.Request) *http.Request {
			req.Header.Set("ccsp-service-id", conf.ClientID)
			req.Header.Set("ccsp-application-id", appId)
			req.Header.Set("Stamp", generateStamp(appId, appStampKey))
			return req
		},
		Inner: client3.Transport,
	}

	hClient, err := hyundaiclient.NewClientWithResponses(baseCcApiUrl.String(), hyundaiclient.WithHTTPClient(client3))
	if err != nil {
		log.Fatal(err.Error())
	}

	if r, err := hClient.CreatePushNotificationsDeviceWithResponse(ctx, hyundaiclient.CreatePushNotificationsDeviceJSONRequestBody{
		PushType:  appNotificationPushType,
		PushRegId: uuid.NewString(),
		Uuid:      uuid.NewString(),
	}); err != nil {
		log.Fatal(err.Error())
	} else if r.StatusCode() != http.StatusOK {
		if r.JSONDefault == nil {
			log.Fatalf("request failed for unknown reason: %d %s", r.StatusCode(), string(r.Body))
		}
		log.Fatalf("request failed: %d %s %s", r.StatusCode(), r.JSONDefault.ResCode, r.JSONDefault.ResMsg)
	} else {
		deviceId := r.JSON200.ResMsg.DeviceId
		client3.Transport = &TransportWithRequestModifier{
			Modifier: func(req *http.Request) *http.Request {
				req.Header.Set("ccsp-device-id", deviceId)
				return req
			},
			Inner: client3.Transport,
		}
	}

	var vehicleId string
	if r, err := hClient.ListVehiclesWithResponse(ctx); err != nil {
		log.Fatal(err.Error())
	} else if r.StatusCode() != http.StatusOK {
		if r.JSONDefault == nil {
			log.Fatalf("request failed for unknown reason: %d %s", r.StatusCode(), string(r.Body))
		}
		log.Fatalf("request failed: %d %s %s", r.StatusCode(), r.JSONDefault.ResCode, r.JSONDefault.ResMsg)
	} else {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(r.JSON200.ResMsg.Vehicles)
		vehicleId = r.JSON200.ResMsg.Vehicles[0].VehicleId
	}

	if r, err := hClient.GetLastVehicleStatusWithResponse(ctx, vehicleId); err != nil {
		log.Fatal(err.Error())
	} else if r.StatusCode() != http.StatusOK {
		if r.JSONDefault == nil {
			log.Fatalf("request failed for unknown reason: %d %s", r.StatusCode(), string(r.Body))
		}
		log.Fatalf("request failed: %d %s %s", r.StatusCode(), r.JSONDefault.ResCode, r.JSONDefault.ResMsg)
	} else {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(r.JSON200.ResMsg)
	}

	if r, err := hClient.QueryVehicleTripInfoWithResponse(ctx, vehicleId, hyundaiclient.QueryVehicleTripInfoJSONRequestBody{
		TripPeriodType: 0,
		SetTripMonth:   ref(time.Now().Format("200601")),
	}); err != nil {
		log.Fatal(err.Error())
	} else if r.StatusCode() != http.StatusOK {
		if r.JSONDefault == nil {
			log.Fatalf("request failed for unknown reason: %d %s", r.StatusCode(), string(r.Body))
		}
		log.Fatalf("request failed: %d %s %s", r.StatusCode(), r.JSONDefault.ResCode, r.JSONDefault.ResMsg)
	} else {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(r.JSON200.ResMsg)
	}

	if r, err := hClient.QueryVehicleTripInfoWithResponse(ctx, vehicleId, hyundaiclient.QueryVehicleTripInfoJSONRequestBody{
		TripPeriodType: 1,
		SetTripMonth:   ref(time.Now().Format("20060102")),
	}); err != nil {
		log.Fatal(err.Error())
	} else if r.StatusCode() != http.StatusOK {
		if r.JSONDefault == nil {
			log.Fatalf("request failed for unknown reason: %d %s", r.StatusCode(), string(r.Body))
		}
		log.Fatalf("request failed: %d %s %s", r.StatusCode(), r.JSONDefault.ResCode, r.JSONDefault.ResMsg)
	} else {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(r.JSON200.ResMsg)
	}

	if r, err := hClient.QueryVehicleDrivingHistoryWithResponse(ctx, vehicleId, hyundaiclient.QueryVehicleDrivingHistoryJSONRequestBody{
		PeriodTarget: 0,
	}); err != nil {
		log.Fatal(err.Error())
	} else if r.StatusCode() != http.StatusOK {
		if r.JSONDefault == nil {
			log.Fatalf("request failed for unknown reason: %d %s", r.StatusCode(), string(r.Body))
		}
		log.Fatalf("request failed: %d %s %s", r.StatusCode(), r.JSONDefault.ResCode, r.JSONDefault.ResMsg)
	} else {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(r.JSON200.ResMsg)
	}

	if r, err := hClient.QueryVehicleDrivingHistoryWithResponse(ctx, vehicleId, hyundaiclient.QueryVehicleDrivingHistoryJSONRequestBody{
		PeriodTarget: 1,
	}); err != nil {
		log.Fatal(err.Error())
	} else if r.StatusCode() != http.StatusOK {
		if r.JSONDefault == nil {
			log.Fatalf("request failed for unknown reason: %d %s", r.StatusCode(), string(r.Body))
		}
		log.Fatalf("request failed: %d %s %s", r.StatusCode(), r.JSONDefault.ResCode, r.JSONDefault.ResMsg)
	} else {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(r.JSON200.ResMsg)
	}
}

type TransportWithRequestModifier struct {
	Modifier func(req *http.Request) *http.Request
	Inner    http.RoundTripper
}

func (t *TransportWithRequestModifier) RoundTrip(request *http.Request) (*http.Response, error) {
	request = t.Modifier(request)
	return t.Inner.RoundTrip(t.Modifier(request))
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

func xor(plainText []byte, key []byte) []byte {
	output := make([]byte, len(plainText))
	for i, b := range plainText {
		output[i] = b ^ key[i%len(key)]
	}
	return output
}

// generateStamp calculates an appropriate generateStamp header value for requests to the auth gateway and other API requests. This
// is an xor of the presumably pre-shared ccspAppId and a timestamp. Presumably, it looks up the shared key by ccspAppId, checks
// that it can xor this successfully and verify that the timestamp is within a reasonable range to prevent replay.
func generateStamp(appId string, appKey string) string {
	// TODO: can you change the appId?
	return base64.StdEncoding.EncodeToString(xor(
		[]byte(fmt.Sprintf("%s:%d", appId, time.Now().Unix())),
		[]byte(appKey),
	))
}
