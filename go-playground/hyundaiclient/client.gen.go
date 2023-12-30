// Package hyundaiclient provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen/v2 version v2.0.0 DO NOT EDIT.
package hyundaiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/oapi-codegen/runtime"
)

// CurrentVehicleStatusResponse defines model for CurrentVehicleStatusResponse.
type CurrentVehicleStatusResponse struct {
	MsgId   string                 `json:"msgId"`
	ResCode string                 `json:"resCode"`
	ResMsg  map[string]interface{} `json:"resMsg"`
	RetCode string                 `json:"retCode"`
}

// ErrorResponse defines model for ErrorResponse.
type ErrorResponse struct {
	MsgId   string `json:"msgId"`
	ResCode string `json:"resCode"`
	ResMsg  string `json:"resMsg"`
	RetCode string `json:"retCode"`
}

// LastVehicleStatusResponse defines model for LastVehicleStatusResponse.
type LastVehicleStatusResponse struct {
	MsgId   string                 `json:"msgId"`
	ResCode string                 `json:"resCode"`
	ResMsg  map[string]interface{} `json:"resMsg"`
	RetCode string                 `json:"retCode"`
}

// PushNotificationsDeviceResponse defines model for PushNotificationsDeviceResponse.
type PushNotificationsDeviceResponse struct {
	MsgId   string `json:"msgId"`
	ResCode string `json:"resCode"`
	ResMsg  struct {
		DeviceId string `json:"deviceId"`
	} `json:"resMsg"`
	RetCode string `json:"retCode"`
}

// VehicleDrivingHistoryResponse defines model for VehicleDrivingHistoryResponse.
type VehicleDrivingHistoryResponse struct {
	MsgId   string                 `json:"msgId"`
	ResCode string                 `json:"resCode"`
	ResMsg  map[string]interface{} `json:"resMsg"`
	RetCode string                 `json:"retCode"`
}

// VehicleTripInfoResponse defines model for VehicleTripInfoResponse.
type VehicleTripInfoResponse struct {
	MsgId   string                 `json:"msgId"`
	ResCode string                 `json:"resCode"`
	ResMsg  map[string]interface{} `json:"resMsg"`
	RetCode string                 `json:"retCode"`
}

// VehiclesListResponse defines model for VehiclesListResponse.
type VehiclesListResponse struct {
	MsgId   string `json:"msgId"`
	ResCode string `json:"resCode"`
	ResMsg  struct {
		Vehicles []VehiclesListResponseVehicle `json:"vehicles"`
	} `json:"resMsg"`
	RetCode string `json:"retCode"`
}

// VehiclesListResponseVehicle defines model for VehiclesListResponseVehicle.
type VehiclesListResponseVehicle struct {
	CarShare   *int `json:"carShare,omitempty"`
	DetailInfo *struct {
		InColor  *string `json:"inColor,omitempty"`
		OutColor *string `json:"outColor,omitempty"`
	} `json:"detailInfo,omitempty"`
	Master      *bool   `json:"master,omitempty"`
	Nickname    string  `json:"nickname"`
	RegDate     *string `json:"regDate,omitempty"`
	Type        string  `json:"type"`
	VehicleId   string  `json:"vehicleId"`
	VehicleName string  `json:"vehicleName"`
	Vin         string  `json:"vin"`
	Year        *string `json:"year,omitempty"`
}

// CreatePushNotificationsDeviceJSONBody defines parameters for CreatePushNotificationsDevice.
type CreatePushNotificationsDeviceJSONBody struct {
	PushRegId string `json:"pushRegId"`

	// PushType Which type of push notifications (GCN or APNS)
	PushType string `json:"pushType"`
	Uuid     string `json:"uuid"`
}

// QueryVehicleDrivingHistoryJSONBody defines parameters for QueryVehicleDrivingHistory.
type QueryVehicleDrivingHistoryJSONBody struct {
	// PeriodTarget Which period to query, 0 == 30 days, 1 == all time
	PeriodTarget int `json:"periodTarget"`
}

// QueryVehicleTripInfoJSONBody defines parameters for QueryVehicleTripInfo.
type QueryVehicleTripInfoJSONBody struct {
	SetTripDay   *string `json:"setTripDay,omitempty"`
	SetTripMonth *string `json:"setTripMonth,omitempty"`

	// TripPeriodType Which period to query, 0 == monthly, 1 == daily
	TripPeriodType int `json:"tripPeriodType"`
}

// CreatePushNotificationsDeviceJSONRequestBody defines body for CreatePushNotificationsDevice for application/json ContentType.
type CreatePushNotificationsDeviceJSONRequestBody CreatePushNotificationsDeviceJSONBody

// QueryVehicleDrivingHistoryJSONRequestBody defines body for QueryVehicleDrivingHistory for application/json ContentType.
type QueryVehicleDrivingHistoryJSONRequestBody QueryVehicleDrivingHistoryJSONBody

// QueryVehicleTripInfoJSONRequestBody defines body for QueryVehicleTripInfo for application/json ContentType.
type QueryVehicleTripInfoJSONRequestBody QueryVehicleTripInfoJSONBody

// RequestEditorFn  is the function signature for the RequestEditor callback function
type RequestEditorFn func(ctx context.Context, req *http.Request) error

// Doer performs HTTP requests.
//
// The standard http.Client implements this interface.
type HttpRequestDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client which conforms to the OpenAPI3 specification for this service.
type Client struct {
	// The endpoint of the server conforming to this interface, with scheme,
	// https://api.deepmap.com for example. This can contain a path relative
	// to the server, such as https://api.deepmap.com/dev-test, and all the
	// paths in the swagger spec will be appended to the server.
	Server string

	// Doer for performing requests, typically a *http.Client with any
	// customized settings, such as certificate chains.
	Client HttpRequestDoer

	// A list of callbacks for modifying requests which are generated before sending over
	// the network.
	RequestEditors []RequestEditorFn
}

// ClientOption allows setting custom parameters during construction
type ClientOption func(*Client) error

// Creates a new Client, with reasonable defaults
func NewClient(server string, opts ...ClientOption) (*Client, error) {
	// create a client with sane default values
	client := Client{
		Server: server,
	}
	// mutate client and add all optional params
	for _, o := range opts {
		if err := o(&client); err != nil {
			return nil, err
		}
	}
	// ensure the server URL always has a trailing slash
	if !strings.HasSuffix(client.Server, "/") {
		client.Server += "/"
	}
	// create httpClient, if not already present
	if client.Client == nil {
		client.Client = &http.Client{}
	}
	return &client, nil
}

// WithHTTPClient allows overriding the default Doer, which is
// automatically created using http.Client. This is useful for tests.
func WithHTTPClient(doer HttpRequestDoer) ClientOption {
	return func(c *Client) error {
		c.Client = doer
		return nil
	}
}

// WithRequestEditorFn allows setting up a callback function, which will be
// called right before sending the request. This can be used to mutate the request.
func WithRequestEditorFn(fn RequestEditorFn) ClientOption {
	return func(c *Client) error {
		c.RequestEditors = append(c.RequestEditors, fn)
		return nil
	}
}

// The interface specification for the client above.
type ClientInterface interface {
	// CreatePushNotificationsDeviceWithBody request with any body
	CreatePushNotificationsDeviceWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	CreatePushNotificationsDevice(ctx context.Context, body CreatePushNotificationsDeviceJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// ListVehicles request
	ListVehicles(ctx context.Context, reqEditors ...RequestEditorFn) (*http.Response, error)

	// QueryVehicleDrivingHistoryWithBody request with any body
	QueryVehicleDrivingHistoryWithBody(ctx context.Context, vehicleId string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	QueryVehicleDrivingHistory(ctx context.Context, vehicleId string, body QueryVehicleDrivingHistoryJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// GetCurrentVehicleLocation request
	GetCurrentVehicleLocation(ctx context.Context, vehicleId string, reqEditors ...RequestEditorFn) (*http.Response, error)

	// GetCurrentVehicleStatus request
	GetCurrentVehicleStatus(ctx context.Context, vehicleId string, reqEditors ...RequestEditorFn) (*http.Response, error)

	// GetLastVehicleStatus request
	GetLastVehicleStatus(ctx context.Context, vehicleId string, reqEditors ...RequestEditorFn) (*http.Response, error)

	// QueryVehicleTripInfoWithBody request with any body
	QueryVehicleTripInfoWithBody(ctx context.Context, vehicleId string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	QueryVehicleTripInfo(ctx context.Context, vehicleId string, body QueryVehicleTripInfoJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)
}

func (c *Client) CreatePushNotificationsDeviceWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewCreatePushNotificationsDeviceRequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) CreatePushNotificationsDevice(ctx context.Context, body CreatePushNotificationsDeviceJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewCreatePushNotificationsDeviceRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) ListVehicles(ctx context.Context, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewListVehiclesRequest(c.Server)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) QueryVehicleDrivingHistoryWithBody(ctx context.Context, vehicleId string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewQueryVehicleDrivingHistoryRequestWithBody(c.Server, vehicleId, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) QueryVehicleDrivingHistory(ctx context.Context, vehicleId string, body QueryVehicleDrivingHistoryJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewQueryVehicleDrivingHistoryRequest(c.Server, vehicleId, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) GetCurrentVehicleLocation(ctx context.Context, vehicleId string, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewGetCurrentVehicleLocationRequest(c.Server, vehicleId)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) GetCurrentVehicleStatus(ctx context.Context, vehicleId string, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewGetCurrentVehicleStatusRequest(c.Server, vehicleId)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) GetLastVehicleStatus(ctx context.Context, vehicleId string, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewGetLastVehicleStatusRequest(c.Server, vehicleId)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) QueryVehicleTripInfoWithBody(ctx context.Context, vehicleId string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewQueryVehicleTripInfoRequestWithBody(c.Server, vehicleId, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) QueryVehicleTripInfo(ctx context.Context, vehicleId string, body QueryVehicleTripInfoJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewQueryVehicleTripInfoRequest(c.Server, vehicleId, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

// NewCreatePushNotificationsDeviceRequest calls the generic CreatePushNotificationsDevice builder with application/json body
func NewCreatePushNotificationsDeviceRequest(server string, body CreatePushNotificationsDeviceJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewCreatePushNotificationsDeviceRequestWithBody(server, "application/json", bodyReader)
}

// NewCreatePushNotificationsDeviceRequestWithBody generates requests for CreatePushNotificationsDevice with any type of body
func NewCreatePushNotificationsDeviceRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v1/spa/notifications/register")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

// NewListVehiclesRequest generates requests for ListVehicles
func NewListVehiclesRequest(server string) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v1/spa/vehicles")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewQueryVehicleDrivingHistoryRequest calls the generic QueryVehicleDrivingHistory builder with application/json body
func NewQueryVehicleDrivingHistoryRequest(server string, vehicleId string, body QueryVehicleDrivingHistoryJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewQueryVehicleDrivingHistoryRequestWithBody(server, vehicleId, "application/json", bodyReader)
}

// NewQueryVehicleDrivingHistoryRequestWithBody generates requests for QueryVehicleDrivingHistory with any type of body
func NewQueryVehicleDrivingHistoryRequestWithBody(server string, vehicleId string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "vehicleId", runtime.ParamLocationPath, vehicleId)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v1/spa/vehicles/%s/drvhistory", pathParam0)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

// NewGetCurrentVehicleLocationRequest generates requests for GetCurrentVehicleLocation
func NewGetCurrentVehicleLocationRequest(server string, vehicleId string) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "vehicleId", runtime.ParamLocationPath, vehicleId)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v1/spa/vehicles/%s/location", pathParam0)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewGetCurrentVehicleStatusRequest generates requests for GetCurrentVehicleStatus
func NewGetCurrentVehicleStatusRequest(server string, vehicleId string) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "vehicleId", runtime.ParamLocationPath, vehicleId)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v1/spa/vehicles/%s/status", pathParam0)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewGetLastVehicleStatusRequest generates requests for GetLastVehicleStatus
func NewGetLastVehicleStatusRequest(server string, vehicleId string) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "vehicleId", runtime.ParamLocationPath, vehicleId)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v1/spa/vehicles/%s/status/latest", pathParam0)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewQueryVehicleTripInfoRequest calls the generic QueryVehicleTripInfo builder with application/json body
func NewQueryVehicleTripInfoRequest(server string, vehicleId string, body QueryVehicleTripInfoJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewQueryVehicleTripInfoRequestWithBody(server, vehicleId, "application/json", bodyReader)
}

// NewQueryVehicleTripInfoRequestWithBody generates requests for QueryVehicleTripInfo with any type of body
func NewQueryVehicleTripInfoRequestWithBody(server string, vehicleId string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "vehicleId", runtime.ParamLocationPath, vehicleId)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v1/spa/vehicles/%s/tripinfo", pathParam0)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

func (c *Client) applyEditors(ctx context.Context, req *http.Request, additionalEditors []RequestEditorFn) error {
	for _, r := range c.RequestEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	for _, r := range additionalEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

// ClientWithResponses builds on ClientInterface to offer response payloads
type ClientWithResponses struct {
	ClientInterface
}

// NewClientWithResponses creates a new ClientWithResponses, which wraps
// Client with return type handling
func NewClientWithResponses(server string, opts ...ClientOption) (*ClientWithResponses, error) {
	client, err := NewClient(server, opts...)
	if err != nil {
		return nil, err
	}
	return &ClientWithResponses{client}, nil
}

// WithBaseURL overrides the baseURL.
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) error {
		newBaseURL, err := url.Parse(baseURL)
		if err != nil {
			return err
		}
		c.Server = newBaseURL.String()
		return nil
	}
}

// ClientWithResponsesInterface is the interface specification for the client with responses above.
type ClientWithResponsesInterface interface {
	// CreatePushNotificationsDeviceWithBodyWithResponse request with any body
	CreatePushNotificationsDeviceWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*CreatePushNotificationsDeviceResponse, error)

	CreatePushNotificationsDeviceWithResponse(ctx context.Context, body CreatePushNotificationsDeviceJSONRequestBody, reqEditors ...RequestEditorFn) (*CreatePushNotificationsDeviceResponse, error)

	// ListVehiclesWithResponse request
	ListVehiclesWithResponse(ctx context.Context, reqEditors ...RequestEditorFn) (*ListVehiclesResponse, error)

	// QueryVehicleDrivingHistoryWithBodyWithResponse request with any body
	QueryVehicleDrivingHistoryWithBodyWithResponse(ctx context.Context, vehicleId string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*QueryVehicleDrivingHistoryResponse, error)

	QueryVehicleDrivingHistoryWithResponse(ctx context.Context, vehicleId string, body QueryVehicleDrivingHistoryJSONRequestBody, reqEditors ...RequestEditorFn) (*QueryVehicleDrivingHistoryResponse, error)

	// GetCurrentVehicleLocationWithResponse request
	GetCurrentVehicleLocationWithResponse(ctx context.Context, vehicleId string, reqEditors ...RequestEditorFn) (*GetCurrentVehicleLocationResponse, error)

	// GetCurrentVehicleStatusWithResponse request
	GetCurrentVehicleStatusWithResponse(ctx context.Context, vehicleId string, reqEditors ...RequestEditorFn) (*GetCurrentVehicleStatusResponse, error)

	// GetLastVehicleStatusWithResponse request
	GetLastVehicleStatusWithResponse(ctx context.Context, vehicleId string, reqEditors ...RequestEditorFn) (*GetLastVehicleStatusResponse, error)

	// QueryVehicleTripInfoWithBodyWithResponse request with any body
	QueryVehicleTripInfoWithBodyWithResponse(ctx context.Context, vehicleId string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*QueryVehicleTripInfoResponse, error)

	QueryVehicleTripInfoWithResponse(ctx context.Context, vehicleId string, body QueryVehicleTripInfoJSONRequestBody, reqEditors ...RequestEditorFn) (*QueryVehicleTripInfoResponse, error)
}

type CreatePushNotificationsDeviceResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *PushNotificationsDeviceResponse
	JSONDefault  *ErrorResponse
}

// Status returns HTTPResponse.Status
func (r CreatePushNotificationsDeviceResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r CreatePushNotificationsDeviceResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type ListVehiclesResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *VehiclesListResponse
	JSONDefault  *ErrorResponse
}

// Status returns HTTPResponse.Status
func (r ListVehiclesResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r ListVehiclesResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type QueryVehicleDrivingHistoryResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *VehicleDrivingHistoryResponse
	JSONDefault  *ErrorResponse
}

// Status returns HTTPResponse.Status
func (r QueryVehicleDrivingHistoryResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r QueryVehicleDrivingHistoryResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type GetCurrentVehicleLocationResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *map[string]interface{}
	JSONDefault  *ErrorResponse
}

// Status returns HTTPResponse.Status
func (r GetCurrentVehicleLocationResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r GetCurrentVehicleLocationResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type GetCurrentVehicleStatusResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *CurrentVehicleStatusResponse
	JSONDefault  *ErrorResponse
}

// Status returns HTTPResponse.Status
func (r GetCurrentVehicleStatusResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r GetCurrentVehicleStatusResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type GetLastVehicleStatusResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *LastVehicleStatusResponse
	JSONDefault  *ErrorResponse
}

// Status returns HTTPResponse.Status
func (r GetLastVehicleStatusResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r GetLastVehicleStatusResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type QueryVehicleTripInfoResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *VehicleTripInfoResponse
	JSONDefault  *ErrorResponse
}

// Status returns HTTPResponse.Status
func (r QueryVehicleTripInfoResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r QueryVehicleTripInfoResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

// CreatePushNotificationsDeviceWithBodyWithResponse request with arbitrary body returning *CreatePushNotificationsDeviceResponse
func (c *ClientWithResponses) CreatePushNotificationsDeviceWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*CreatePushNotificationsDeviceResponse, error) {
	rsp, err := c.CreatePushNotificationsDeviceWithBody(ctx, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseCreatePushNotificationsDeviceResponse(rsp)
}

func (c *ClientWithResponses) CreatePushNotificationsDeviceWithResponse(ctx context.Context, body CreatePushNotificationsDeviceJSONRequestBody, reqEditors ...RequestEditorFn) (*CreatePushNotificationsDeviceResponse, error) {
	rsp, err := c.CreatePushNotificationsDevice(ctx, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseCreatePushNotificationsDeviceResponse(rsp)
}

// ListVehiclesWithResponse request returning *ListVehiclesResponse
func (c *ClientWithResponses) ListVehiclesWithResponse(ctx context.Context, reqEditors ...RequestEditorFn) (*ListVehiclesResponse, error) {
	rsp, err := c.ListVehicles(ctx, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseListVehiclesResponse(rsp)
}

// QueryVehicleDrivingHistoryWithBodyWithResponse request with arbitrary body returning *QueryVehicleDrivingHistoryResponse
func (c *ClientWithResponses) QueryVehicleDrivingHistoryWithBodyWithResponse(ctx context.Context, vehicleId string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*QueryVehicleDrivingHistoryResponse, error) {
	rsp, err := c.QueryVehicleDrivingHistoryWithBody(ctx, vehicleId, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseQueryVehicleDrivingHistoryResponse(rsp)
}

func (c *ClientWithResponses) QueryVehicleDrivingHistoryWithResponse(ctx context.Context, vehicleId string, body QueryVehicleDrivingHistoryJSONRequestBody, reqEditors ...RequestEditorFn) (*QueryVehicleDrivingHistoryResponse, error) {
	rsp, err := c.QueryVehicleDrivingHistory(ctx, vehicleId, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseQueryVehicleDrivingHistoryResponse(rsp)
}

// GetCurrentVehicleLocationWithResponse request returning *GetCurrentVehicleLocationResponse
func (c *ClientWithResponses) GetCurrentVehicleLocationWithResponse(ctx context.Context, vehicleId string, reqEditors ...RequestEditorFn) (*GetCurrentVehicleLocationResponse, error) {
	rsp, err := c.GetCurrentVehicleLocation(ctx, vehicleId, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseGetCurrentVehicleLocationResponse(rsp)
}

// GetCurrentVehicleStatusWithResponse request returning *GetCurrentVehicleStatusResponse
func (c *ClientWithResponses) GetCurrentVehicleStatusWithResponse(ctx context.Context, vehicleId string, reqEditors ...RequestEditorFn) (*GetCurrentVehicleStatusResponse, error) {
	rsp, err := c.GetCurrentVehicleStatus(ctx, vehicleId, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseGetCurrentVehicleStatusResponse(rsp)
}

// GetLastVehicleStatusWithResponse request returning *GetLastVehicleStatusResponse
func (c *ClientWithResponses) GetLastVehicleStatusWithResponse(ctx context.Context, vehicleId string, reqEditors ...RequestEditorFn) (*GetLastVehicleStatusResponse, error) {
	rsp, err := c.GetLastVehicleStatus(ctx, vehicleId, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseGetLastVehicleStatusResponse(rsp)
}

// QueryVehicleTripInfoWithBodyWithResponse request with arbitrary body returning *QueryVehicleTripInfoResponse
func (c *ClientWithResponses) QueryVehicleTripInfoWithBodyWithResponse(ctx context.Context, vehicleId string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*QueryVehicleTripInfoResponse, error) {
	rsp, err := c.QueryVehicleTripInfoWithBody(ctx, vehicleId, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseQueryVehicleTripInfoResponse(rsp)
}

func (c *ClientWithResponses) QueryVehicleTripInfoWithResponse(ctx context.Context, vehicleId string, body QueryVehicleTripInfoJSONRequestBody, reqEditors ...RequestEditorFn) (*QueryVehicleTripInfoResponse, error) {
	rsp, err := c.QueryVehicleTripInfo(ctx, vehicleId, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseQueryVehicleTripInfoResponse(rsp)
}

// ParseCreatePushNotificationsDeviceResponse parses an HTTP response from a CreatePushNotificationsDeviceWithResponse call
func ParseCreatePushNotificationsDeviceResponse(rsp *http.Response) (*CreatePushNotificationsDeviceResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &CreatePushNotificationsDeviceResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest PushNotificationsDeviceResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && true:
		var dest ErrorResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSONDefault = &dest

	}

	return response, nil
}

// ParseListVehiclesResponse parses an HTTP response from a ListVehiclesWithResponse call
func ParseListVehiclesResponse(rsp *http.Response) (*ListVehiclesResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &ListVehiclesResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest VehiclesListResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && true:
		var dest ErrorResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSONDefault = &dest

	}

	return response, nil
}

// ParseQueryVehicleDrivingHistoryResponse parses an HTTP response from a QueryVehicleDrivingHistoryWithResponse call
func ParseQueryVehicleDrivingHistoryResponse(rsp *http.Response) (*QueryVehicleDrivingHistoryResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &QueryVehicleDrivingHistoryResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest VehicleDrivingHistoryResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && true:
		var dest ErrorResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSONDefault = &dest

	}

	return response, nil
}

// ParseGetCurrentVehicleLocationResponse parses an HTTP response from a GetCurrentVehicleLocationWithResponse call
func ParseGetCurrentVehicleLocationResponse(rsp *http.Response) (*GetCurrentVehicleLocationResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &GetCurrentVehicleLocationResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && true:
		var dest ErrorResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSONDefault = &dest

	}

	return response, nil
}

// ParseGetCurrentVehicleStatusResponse parses an HTTP response from a GetCurrentVehicleStatusWithResponse call
func ParseGetCurrentVehicleStatusResponse(rsp *http.Response) (*GetCurrentVehicleStatusResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &GetCurrentVehicleStatusResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest CurrentVehicleStatusResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && true:
		var dest ErrorResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSONDefault = &dest

	}

	return response, nil
}

// ParseGetLastVehicleStatusResponse parses an HTTP response from a GetLastVehicleStatusWithResponse call
func ParseGetLastVehicleStatusResponse(rsp *http.Response) (*GetLastVehicleStatusResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &GetLastVehicleStatusResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest LastVehicleStatusResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && true:
		var dest ErrorResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSONDefault = &dest

	}

	return response, nil
}

// ParseQueryVehicleTripInfoResponse parses an HTTP response from a QueryVehicleTripInfoWithResponse call
func ParseQueryVehicleTripInfoResponse(rsp *http.Response) (*QueryVehicleTripInfoResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &QueryVehicleTripInfoResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest VehicleTripInfoResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && true:
		var dest ErrorResponse
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSONDefault = &dest

	}

	return response, nil
}
