// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package xsrf

import (
	"errors"
	"fmt"
	"github.com/google/go-safeweb/safehttp"
	// TODO(@empijei, @kele, @mattiasgrenfeldt, @mihalimara22): decide whether we want to depend on this package or reimplement thefunctionality
	"golang.org/x/net/xsrftoken"
)

const (
	// FMEnforceMode TODO
	FMEnforceMode = "enforce"
	// FMReportMode TODO
	FMReportMode = "report"
	// FMDisabledMode TODO
	FMDisabledMode = "disable"
	// TokenKey is the form key used when sending the token as part of POST
	// request
	TokenKey = "xsrf-token"
)

// StorageService is an interface the framework users need to implement. This
// will contain information about users of the web application, including their
// IDs, needed in generating the XSRF token.
type StorageService interface {
	// TODO(@mihalimara22): add the parameters that the storage service needs in
	// order to determine the user ID
	GetUserID() (string, error)
}

// Plugin implements XSRF protection.
type Plugin struct {
	// TODO(@mihalimara22): decide whether  we want to allow the user to set a
	// Fetch Metadata policy and how the report mode is going to be handled
	appKey       string
	s            StorageService
	fmPolicyMode string
	allowedCORS  map[string]bool
}

// NewPlugin creates a new XSRF plugin with safe defaults
func NewPlugin(appKey string, s StorageService, domains ...string) *Plugin {
	// TODO(@mihalimara22): make endpoints a variadic of string literals
	ad := map[string]bool{}
	for _, p := range domains {
		ad[p] = true
	}
	return &Plugin{
		appKey:       appKey,
		s:            s,
		fmPolicyMode: FMEnforceMode,
		allowedCORS:  ad,
	}
}

// SetFetchMetadataPolicyMode allows setting the Fetch Metadata policy, enforced
// by default to one of the other options. Setting it to report will allow
// requests that violate the policy to pass but will log violation. Setting it
// to disable
func (p *Plugin) SetFetchMetadataPolicyMode(mode string) error {
	switch mode {
	case FMEnforceMode, FMDisabledMode, FMReportMode:
		p.fmPolicyMode = mode
	default:
		return errors.New("invalid Fetch Metadata policy")
	}
	return nil
}

// GenerateToken generates a cryptographically safe XSRF token using the user ID
// and the path.
func (p *Plugin) GenerateToken(host string) (string, error) {
	userID, err := p.s.GetUserID()
	if err != nil {
		return "", fmt.Errorf("token generation failed: %v", err)
	}
	token := xsrftoken.Generate(p.appKey, userID, host)
	return token, nil
}

// validateToken validates the XSRF token. This should be present in all
// requests as the value of form parameter xsrf-token.
func (p *Plugin) validateToken(ir *safehttp.IncomingRequest) (safehttp.StatusCode, bool) {
	userID, err := p.s.GetUserID()
	if err != nil {
		return safehttp.Status401Unauthorized, false
	}
	// TODO(@mihalimara22): add multipart support as well
	f, err := ir.PostForm()
	if err != nil {
		return safehttp.Status400BadRequest, false
	}
	token := f.String(TokenKey, "")
	if f.Err() != nil || token == "" {
		return safehttp.Status403Forbidden, false
	}
	ok := xsrftoken.Valid(token, p.appKey, userID, ir.Header.Get("Host"))
	if !ok {
		return safehttp.Status403Forbidden, false
	}
	return 0, true
}

// applyPolicy validates the request using the default Fetch Metadata policy and
// only allows it to pass if it conforms to the policy. A cross-origin request
// will not be allowed unless targeted to a domain that is allowed to server
// cross-origin. The policy will not be applied if the browser doesn't have
// Fetch Metadata support implemented.
// TODO(@empijei, @kele, @mattiasgrenfeldt, @mihalimara22): decide whether the user should be allowed to provide
// their own policy
func (p *Plugin) applyPolicy(ir *safehttp.IncomingRequest) (safehttp.StatusCode, bool) {
	switch ir.Header.Get("Sec-Fetch-Site") {
	case "":
		// Fetch Metadata not supported by the browser
		return 0, true
	case "same-origin", "same-site", "none":
		return 0, true
	case "cross-origin":
		if p.allowedCORS[ir.Header.Get("Host")] {
			return 0, true
		}
		return safehttp.Status403Forbidden, false
	}

	switch ir.Header.Get("Sec-Fetch-Mode") {
	case "navigate":
		dest := ir.Header.Get("Sec-Fetch-Dest")
		if dest == "object" || dest == "embed" {
			return safehttp.Status403Forbidden, false
		}
		if ir.GetMethod() == "GET" || ir.GetMethod() == "HEAD" {
			return 0, true
		}
	}
	return safehttp.Status403Forbidden, false
}

// Before should be executed before directing the request to the handler. The
// function applies checks to the Incoming Request to ensure this is not part
// of a Cross-Site Request Forgery. These ensure the request complies to the
// Fetch Metadata policy provided and contain a XSRF token.
func (p *Plugin) Before(rw safehttp.ResponseWriter, ir *safehttp.IncomingRequest) safehttp.Result {
	// TODO(mihalimara22): handle the case when the Fetch Metadata policy is
	// in report mode
	if p.fmPolicyMode == FMEnforceMode {
		status, ok := p.applyPolicy(ir)
		if !ok {
			return rw.ServerError(status, "")
		}
	}

	status, ok := p.validateToken(ir)
	if !ok {
		return rw.ServerError(status, "")
	}
	return safehttp.Result{}
}
