// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package openid_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/canonical/secure-token-service/internal/auth/openid"
)

func TestBuildAuthURL(t *testing.T) {
	client := openid.NewClient("https://login.ubuntu.com/+openid", "https://auth.example.com/", nil)

	returnTo := "https://auth.example.com/auth/openid/callback"
	state := "random-state-12345"

	authURL, err := client.BuildAuthURL(returnTo, state)
	if err != nil {
		t.Fatalf("BuildAuthURL failed: %v", err)
	}

	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("failed to parse auth URL: %v", err)
	}

	if u.Scheme != "https" || u.Host != "login.ubuntu.com" || u.Path != "/+openid" {
		t.Errorf("unexpected base URL: %s://%s%s", u.Scheme, u.Host, u.Path)
	}

	q := u.Query()

	// Verify standard OpenID 2.0 parameters
	if got := q.Get("openid.ns"); got != openid.OpenIDNS {
		t.Errorf("openid.ns: got %q, want %q", got, openid.OpenIDNS)
	}
	if got := q.Get("openid.mode"); got != "checkid_setup" {
		t.Errorf("openid.mode: got %q, want %q", got, "checkid_setup")
	}
	if got := q.Get("openid.claimed_id"); got != openid.OpenIDIdentifierSelect {
		t.Errorf("openid.claimed_id: got %q, want %q", got, openid.OpenIDIdentifierSelect)
	}
	if got := q.Get("openid.identity"); got != openid.OpenIDIdentifierSelect {
		t.Errorf("openid.identity: got %q, want %q", got, openid.OpenIDIdentifierSelect)
	}
	if got := q.Get("openid.realm"); got != "https://auth.example.com/" {
		t.Errorf("openid.realm: got %q, want https://auth.example.com/", got)
	}

	// Verify effective return_to contains state parameter
	effectiveReturnTo := q.Get("openid.return_to")
	if effectiveReturnTo == "" {
		t.Fatal("openid.return_to is empty")
	}
	rtURL, err := url.Parse(effectiveReturnTo)
	if err != nil {
		t.Fatalf("failed to parse effective return_to: %v", err)
	}
	if rtURL.Query().Get("state") != state {
		t.Errorf("effective return_to state: got %q, want %q", rtURL.Query().Get("state"), state)
	}

	// Verify Simple Registration (SREG) parameters
	if got := q.Get("openid.ns.sreg"); got != openid.SREGNS {
		t.Errorf("openid.ns.sreg: got %q, want %q", got, openid.SREGNS)
	}
	if got := q.Get("openid.sreg.required"); got != "email,nickname" {
		t.Errorf("openid.sreg.required: got %q, want email,nickname", got)
	}
	if got := q.Get("openid.sreg.optional"); got != "fullname" {
		t.Errorf("openid.sreg.optional: got %q, want fullname", got)
	}

	// Verify Attribute Exchange parameters
	if got := q.Get("openid.ns.ax"); got != openid.AXNS {
		t.Errorf("openid.ns.ax: got %q, want %q", got, openid.AXNS)
	}
	if got := q.Get("openid.ax.mode"); got != "fetch_request" {
		t.Errorf("openid.ax.mode: got %q, want fetch_request", got)
	}
	if got := q.Get("openid.ax.type.email"); got != openid.AXSchemaEmail {
		t.Errorf("openid.ax.type.email: got %q, want %q", got, openid.AXSchemaEmail)
	}
	if got := q.Get("openid.ax.type.nickname"); got != openid.AXSchemaNickname {
		t.Errorf("openid.ax.type.nickname: got %q, want %q", got, openid.AXSchemaNickname)
	}
	if got := q.Get("openid.ax.type.fullname"); got != openid.AXSchemaFullname {
		t.Errorf("openid.ax.type.fullname: got %q, want %q", got, openid.AXSchemaFullname)
	}
	if got := q.Get("openid.ax.required"); got != "email,nickname,fullname" {
		t.Errorf("openid.ax.required: got %q, want email,nickname,fullname", got)
	}
}

func TestBuildAuthURL_DefaultRealm(t *testing.T) {
	// Empty realm in client should derive realm from returnTo URL
	client := openid.NewClient("", "", nil)

	returnTo := "http://localhost:8080/auth/openid/callback"
	authURL, err := client.BuildAuthURL(returnTo, "st")
	if err != nil {
		t.Fatalf("BuildAuthURL failed: %v", err)
	}

	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("failed to parse auth URL: %v", err)
	}
	if got := u.Query().Get("openid.realm"); got != "http://localhost:8080/" {
		t.Errorf("derived realm: got %q, want http://localhost:8080/", got)
	}
}

func TestBuildAuthURL_ValidationErrors(t *testing.T) {
	client := openid.NewClient("", "", nil)

	_, err := client.BuildAuthURL("", "state")
	if err == nil {
		t.Error("expected error for empty return_to, got nil")
	}

	_, err = client.BuildAuthURL(":%invalid-url", "state")
	if err == nil {
		t.Error("expected error for invalid return_to, got nil")
	}
}

func TestVerifyCallback_Success(t *testing.T) {
	// Mock OpenID provider server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		form, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		if form.Get("openid.mode") != "check_authentication" {
			t.Errorf("openid.mode: got %q, want check_authentication", form.Get("openid.mode"))
		}
		if form.Get("openid.sig") != "sig-xyz" {
			t.Errorf("openid.sig: got %q, want sig-xyz", form.Get("openid.sig"))
		}

		// Return OpenID 2.0 direct verification key-value response
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ns:http://specs.openid.net/auth/2.0\nis_valid:true\n"))
	}))
	defer server.Close()

	client := openid.NewClient(server.URL, "", server.Client())

	// Build callback request
	callbackQuery := url.Values{}
	callbackQuery.Set("openid.mode", "id_res")
	callbackQuery.Set("openid.ns", openid.OpenIDNS)
	callbackQuery.Set("openid.return_to", "https://example.com/auth/openid/callback?state=xyz")
	callbackQuery.Set("openid.sig", "sig-xyz")
	callbackQuery.Set("openid.signed", "mode,identity,claimed_id,return_to,response_nonce,sig")
	callbackQuery.Set("openid.response_nonce", time.Now().UTC().Format(time.RFC3339)+"extra-random")
	callbackQuery.Set("openid.claimed_id", "https://login.ubuntu.com/+id/user123")
	callbackQuery.Set("openid.identity", "https://login.ubuntu.com/+id/user123")
	callbackQuery.Set("openid.ns.ax", openid.AXNS)
	callbackQuery.Set("openid.ax.value.email", "alice@canonical.com")
	callbackQuery.Set("openid.ax.value.nickname", "alice")
	callbackQuery.Set("openid.ax.value.fullname", "Alice Smith")

	req := httptest.NewRequest("GET", "/auth/openid/callback?"+callbackQuery.Encode(), nil)

	claims, err := client.VerifyCallback(context.Background(), req)
	if err != nil {
		t.Fatalf("VerifyCallback failed: %v", err)
	}

	if claims.Email != "alice@canonical.com" {
		t.Errorf("email: got %q, want alice@canonical.com", claims.Email)
	}
	if claims.Nickname != "alice" {
		t.Errorf("nickname: got %q, want alice", claims.Nickname)
	}
	if claims.FullName != "Alice Smith" {
		t.Errorf("fullname: got %q, want Alice Smith", claims.FullName)
	}
	if claims.ClaimedID != "https://login.ubuntu.com/+id/user123" {
		t.Errorf("claimed_id: got %q, want https://login.ubuntu.com/+id/user123", claims.ClaimedID)
	}

	userID, err := claims.UserID()
	if err != nil {
		t.Fatalf("UserID() failed: %v", err)
	}
	if userID != "alice@canonical.com" {
		t.Errorf("resolved UserID: got %q, want alice@canonical.com", userID)
	}

	norm := claims.NormalizedClaims()
	if norm["email"] != "alice@canonical.com" {
		t.Errorf("norm[email]: got %v, want alice@canonical.com", norm["email"])
	}
	if norm["nickname"] != "alice" {
		t.Errorf("norm[nickname]: got %v, want alice", norm["nickname"])
	}
	if norm["name"] != "Alice Smith" {
		t.Errorf("norm[name]: got %v, want Alice Smith", norm["name"])
	}
	if norm["idp_provider"] != "openid" {
		t.Errorf("norm[idp_provider]: got %v, want openid", norm["idp_provider"])
	}
}

func TestVerifyCallback_Ext1NamespaceMapping(t *testing.T) {
	// Ubuntu One often uses ext1 for AX namespace
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("is_valid:true\n"))
	}))
	defer server.Close()

	client := openid.NewClient(server.URL, "", server.Client())

	callbackQuery := url.Values{}
	callbackQuery.Set("openid.mode", "id_res")
	callbackQuery.Set("openid.ns.ext1", openid.AXNS)
	callbackQuery.Set("openid.ext1.type.email", openid.AXSchemaEmail)
	callbackQuery.Set("openid.ext1.value.email", "bob@canonical.com")
	callbackQuery.Set("openid.ext1.type.nickname", openid.AXSchemaNickname)
	callbackQuery.Set("openid.ext1.value.nickname", "bob")
	callbackQuery.Set("openid.ext1.type.fullname", openid.AXSchemaFullname)
	callbackQuery.Set("openid.ext1.value.fullname", "Bob Jones")
	callbackQuery.Set("openid.response_nonce", time.Now().UTC().Format(time.RFC3339)+"extra")

	req := httptest.NewRequest("GET", "/auth/openid/callback?"+callbackQuery.Encode(), nil)

	claims, err := client.VerifyCallback(context.Background(), req)
	if err != nil {
		t.Fatalf("VerifyCallback failed: %v", err)
	}

	if claims.Email != "bob@canonical.com" {
		t.Errorf("email: got %q, want bob@canonical.com", claims.Email)
	}
	if claims.Nickname != "bob" {
		t.Errorf("nickname: got %q, want bob", claims.Nickname)
	}
	if claims.FullName != "Bob Jones" {
		t.Errorf("fullname: got %q, want Bob Jones", claims.FullName)
	}
}

func TestVerifyCallback_SREGResponse(t *testing.T) {
	// Canonical SSO / Launchpad returns attributes via SREG 1.1
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("is_valid:true\n"))
	}))
	defer server.Close()

	client := openid.NewClient(server.URL, "", server.Client())

	callbackQuery := url.Values{}
	callbackQuery.Set("openid.mode", "id_res")
	callbackQuery.Set("openid.ns", openid.OpenIDNS)
	callbackQuery.Set("openid.ns.sreg", openid.SREGNS)
	callbackQuery.Set("openid.sreg.email", "canonical-user@canonical.com")
	callbackQuery.Set("openid.sreg.nickname", "canonical-user")
	callbackQuery.Set("openid.sreg.fullname", "Canonical Test User")
	callbackQuery.Set("openid.claimed_id", "https://sso.iam.test.canonical.com/+id/Xb6LTdm")
	callbackQuery.Set("openid.identity", "https://sso.iam.test.canonical.com/+id/Xb6LTdm")
	callbackQuery.Set("openid.response_nonce", time.Now().UTC().Format(time.RFC3339)+"extra")

	req := httptest.NewRequest("GET", "/auth/openid/callback?"+callbackQuery.Encode(), nil)

	claims, err := client.VerifyCallback(context.Background(), req)
	if err != nil {
		t.Fatalf("VerifyCallback failed: %v", err)
	}

	if claims.Email != "canonical-user@canonical.com" {
		t.Errorf("email: got %q, want canonical-user@canonical.com", claims.Email)
	}
	if claims.Nickname != "canonical-user" {
		t.Errorf("nickname: got %q, want canonical-user", claims.Nickname)
	}
	if claims.FullName != "Canonical Test User" {
		t.Errorf("fullname: got %q, want Canonical Test User", claims.FullName)
	}
	if claims.ClaimedID != "https://sso.iam.test.canonical.com/+id/Xb6LTdm" {
		t.Errorf("claimed_id: got %q, want https://sso.iam.test.canonical.com/+id/Xb6LTdm", claims.ClaimedID)
	}

	userID, err := claims.UserID()
	if err != nil {
		t.Fatalf("UserID() failed: %v", err)
	}
	if userID != "canonical-user@canonical.com" {
		t.Errorf("UserID: got %q, want canonical-user@canonical.com", userID)
	}

	norm := claims.NormalizedClaims()
	if norm["email"] != "canonical-user@canonical.com" {
		t.Errorf("norm[email]: got %v, want canonical-user@canonical.com", norm["email"])
	}
	if norm["claimed_id"] != "https://sso.iam.test.canonical.com/+id/Xb6LTdm" {
		t.Errorf("norm[claimed_id]: got %v, want https://sso.iam.test.canonical.com/+id/Xb6LTdm", norm["claimed_id"])
	}
	if norm["idp_provider"] != "openid" {
		t.Errorf("norm[idp_provider]: got %v, want openid", norm["idp_provider"])
	}
}

func TestVerifyCallback_DynamicSREGNamespace(t *testing.T) {
	// Provider using dynamic namespace alias for SREG (e.g. ext2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("is_valid:true\n"))
	}))
	defer server.Close()

	client := openid.NewClient(server.URL, "", server.Client())

	callbackQuery := url.Values{}
	callbackQuery.Set("openid.mode", "id_res")
	callbackQuery.Set("openid.ns", openid.OpenIDNS)
	callbackQuery.Set("openid.ns.ext2", openid.SREGNS10)
	callbackQuery.Set("openid.ext2.email", "ext2-user@example.com")
	callbackQuery.Set("openid.ext2.nickname", "ext2-nick")
	callbackQuery.Set("openid.ext2.fullname", "Ext2 Name")
	callbackQuery.Set("openid.response_nonce", time.Now().UTC().Format(time.RFC3339)+"extra")

	req := httptest.NewRequest("GET", "/auth/openid/callback?"+callbackQuery.Encode(), nil)

	claims, err := client.VerifyCallback(context.Background(), req)
	if err != nil {
		t.Fatalf("VerifyCallback failed: %v", err)
	}

	if claims.Email != "ext2-user@example.com" {
		t.Errorf("email: got %q, want ext2-user@example.com", claims.Email)
	}
	if claims.Nickname != "ext2-nick" {
		t.Errorf("nickname: got %q, want ext2-nick", claims.Nickname)
	}
	if claims.FullName != "Ext2 Name" {
		t.Errorf("fullname: got %q, want Ext2 Name", claims.FullName)
	}
}

func TestVerifyCallback_UserCancelled(t *testing.T) {
	client := openid.NewClient("https://login.ubuntu.com/+openid", "", nil)

	q := url.Values{}
	q.Set("openid.mode", "cancel")

	req := httptest.NewRequest("GET", "/auth/openid/callback?"+q.Encode(), nil)
	_, err := client.VerifyCallback(context.Background(), req)
	if err == nil {
		t.Fatal("expected error on cancellation, got nil")
	}
	if !strings.Contains(err.Error(), "cancelled") {
		t.Errorf("expected cancellation error message, got: %v", err)
	}
}

func TestVerifyCallback_MissingModeOrNonce(t *testing.T) {
	client := openid.NewClient("https://login.ubuntu.com/+openid", "", nil)

	// Missing mode
	req1 := httptest.NewRequest("GET", "/auth/openid/callback", nil)
	_, err := client.VerifyCallback(context.Background(), req1)
	if err == nil {
		t.Error("expected error for missing mode")
	}

	// Unexpected mode
	q := url.Values{}
	q.Set("openid.mode", "unsupported")
	req2 := httptest.NewRequest("GET", "/auth/openid/callback?"+q.Encode(), nil)
	_, err = client.VerifyCallback(context.Background(), req2)
	if err == nil {
		t.Error("expected error for unsupported mode")
	}

	// Missing nonce
	q.Set("openid.mode", "id_res")
	req3 := httptest.NewRequest("GET", "/auth/openid/callback?"+q.Encode(), nil)
	_, err = client.VerifyCallback(context.Background(), req3)
	if err == nil {
		t.Error("expected error for missing nonce")
	}
}

func TestVerifyCallback_InvalidSignature(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ns:http://specs.openid.net/auth/2.0\nis_valid:false\n"))
	}))
	defer server.Close()

	client := openid.NewClient(server.URL, "", server.Client())

	q := url.Values{}
	q.Set("openid.mode", "id_res")
	q.Set("openid.response_nonce", time.Now().UTC().Format(time.RFC3339)+"extra")

	req := httptest.NewRequest("GET", "/auth/openid/callback?"+q.Encode(), nil)
	_, err := client.VerifyCallback(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for is_valid:false, got nil")
	}
	if !strings.Contains(err.Error(), "verification failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestVerifyCallback_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := openid.NewClient(server.URL, "", server.Client())

	q := url.Values{}
	q.Set("openid.mode", "id_res")
	q.Set("openid.response_nonce", time.Now().UTC().Format(time.RFC3339)+"extra")

	req := httptest.NewRequest("GET", "/auth/openid/callback?"+q.Encode(), nil)
	_, err := client.VerifyCallback(context.Background(), req)
	if err == nil {
		t.Fatal("expected error on 500 response, got nil")
	}
}

func TestClaims_UserIDHierarchy(t *testing.T) {
	tests := []struct {
		name       string
		claims     openid.Claims
		wantUserID string
		wantErr    bool
	}{
		{
			name: "email preferred when all present",
			claims: openid.Claims{
				Email:     "user@canonical.com",
				Nickname:  "user_nick",
				ClaimedID: "https://login.ubuntu.com/+id/user123",
			},
			wantUserID: "user@canonical.com",
			wantErr:    false,
		},
		{
			name: "fallback to nickname when email absent",
			claims: openid.Claims{
				Nickname:  "user_nick",
				ClaimedID: "https://login.ubuntu.com/+id/user123",
			},
			wantUserID: "user_nick",
			wantErr:    false,
		},
		{
			name: "fallback to claimed_id when email and nickname absent",
			claims: openid.Claims{
				ClaimedID: "https://login.ubuntu.com/+id/user123",
			},
			wantUserID: "https://login.ubuntu.com/+id/user123",
			wantErr:    false,
		},
		{
			name:       "error when all absent",
			claims:     openid.Claims{},
			wantUserID: "",
			wantErr:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			userID, err := tc.claims.UserID()
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if userID != tc.wantUserID {
				t.Errorf("UserID: got %q, want %q", userID, tc.wantUserID)
			}
		})
	}
}
