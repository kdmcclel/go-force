package force

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

const (
	loginHttpUri     = "https://login.salesforce.com/"
	testLoginHttpUri = "https://test.salesforce.com/"
)

type forceHttpAuth struct {
	jar http.CookieJar

	userName    string
	password    string
	environment string
}

func (httpAuth *forceHttpAuth) Validate() error {
	if httpAuth == nil || httpAuth.jar == nil || len(httpAuth.jar.Cookies(nil)) == 0 {
		return fmt.Errorf("Invalid Force HttpAuth Object: %#v", httpAuth)
	}

	return nil
}

func (httpAuth *forceHttpAuth) Authenticate() error {
	payload := url.Values{
		"un":       {httpAuth.userName},
		"username": {httpAuth.userName},
		"pw":       {fmt.Sprintf("%v", httpAuth.password)},
	}

	//set up the client
	cookiejarOptions := cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	}
	httpAuth.jar, _ = cookiejar.New(&cookiejarOptions)
	client := &http.Client{Jar: httpAuth.jar}

	// Build Uri
	uri := loginHttpUri
	if httpAuth.environment == "sandbox" {
		uri = testLoginHttpUri
	}

	// Build Body
	body := strings.NewReader(payload.Encode())

	// Build Request
	req, err := http.NewRequest("POST", uri, body)
	if err != nil {
		return fmt.Errorf("Error creating authentication request: %v", err)
	}

	// Add Headers
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", responseType)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Error sending authentication request: %v", err)
	}
	defer resp.Body.Close()

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Error reading authentication response bytes: %v", err)
	}

	return nil
}

func (forceApi *ForceApi) ConnectHTTP() error {
	if err := forceApi.httpAuth.Validate(); err != nil {
		return forceApi.httpAuth.Authenticate()
	}
	return nil
}

func (forceApi *ForceApi) GetHTTP(path string) (*http.Response, error) {
	client := &http.Client{Jar: forceApi.httpAuth.jar}

	uri := forceApi.oauth.InstanceUrl + path

	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, fmt.Errorf("error sending get request: %v", err)
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", responseType)

	forceApi.traceRequest(req)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Error sending authentication request: %v", err)
	}
	forceApi.traceResponse(resp)

	return resp, err
}

func (forceApi *ForceApi) PostHTTP(path string, payload map[string][]string) (*http.Response, error) {
	client := &http.Client{Jar: forceApi.httpAuth.jar}

	uri := forceApi.oauth.InstanceUrl + path

	// Build Body
	body := strings.NewReader(url.Values(payload).Encode())

	req, err := http.NewRequest("POST", uri, body)
	if err != nil {
		return nil, fmt.Errorf("Error sending get request: %v", err)
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", responseType)

	forceApi.traceRequest(req)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Error sending authentication request: %v", err)
	}
	forceApi.traceResponse(resp)

	return resp, err
}
