// Copyright 2025 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package openid_test

import (
	"context"
	"fmt"
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
	callbackQuery.Set("openid.signed", "mode,identity,claimed_id,return_to,response_nonce,sig,ns.ax,ax.type.email,ax.value.email,ax.type.nickname,ax.value.nickname,ax.type.fullname,ax.value.fullname")
	callbackQuery.Set("openid.response_nonce", time.Now().UTC().Format(time.RFC3339)+"extra-random")
	callbackQuery.Set("openid.claimed_id", "https://login.ubuntu.com/+id/user123")
	callbackQuery.Set("openid.identity", "https://login.ubuntu.com/+id/user123")
	callbackQuery.Set("openid.ns.ax", openid.AXNS)
	callbackQuery.Set("openid.ax.type.email", openid.AXSchemaEmail)
	callbackQuery.Set("openid.ax.value.email", "alice@canonical.com")
	callbackQuery.Set("openid.ax.type.nickname", openid.AXSchemaNickname)
	callbackQuery.Set("openid.ax.value.nickname", "alice")
	callbackQuery.Set("openid.ax.type.fullname", openid.AXSchemaFullname)
	callbackQuery.Set("openid.ax.value.fullname", "Alice Smith")

	req := httptest.NewRequest("GET", "/auth/openid/callback?"+callbackQuery.Encode(), nil)

	claims, err := client.VerifyCallback(context.Background(), req, "https://example.com/auth/openid/callback?state=xyz")
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
	if userID != "user123" {
		t.Errorf("resolved UserID: got %q, want user123", userID)
	}

	norm := claims.NormalizedClaims()
	if norm["email"] != "alice@canonical.com" {
		t.Errorf("norm[email]: got %v, want alice@canonical.com", norm["email"])
	}
	if norm["u1_sso_id"] != "user123" {
		t.Errorf("norm[u1_sso_id]: got %v, want user123", norm["u1_sso_id"])
	}
	if _, hasLegacy := norm["claimed_id"]; hasLegacy {
		t.Errorf("norm[claimed_id]: expected legacy claimed_id claim to be omitted, got %v", norm["claimed_id"])
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
	returnTo := "https://example.com/auth/openid/callback"

	callbackQuery := url.Values{}
	callbackQuery.Set("openid.mode", "id_res")
	callbackQuery.Set("openid.return_to", returnTo)
	callbackQuery.Set("openid.ns.ext1", openid.AXNS)
	callbackQuery.Set("openid.ext1.type.email", openid.AXSchemaEmail)
	callbackQuery.Set("openid.ext1.value.email", "bob@canonical.com")
	callbackQuery.Set("openid.ext1.type.nickname", openid.AXSchemaNickname)
	callbackQuery.Set("openid.ext1.value.nickname", "bob")
	callbackQuery.Set("openid.ext1.type.fullname", openid.AXSchemaFullname)
	callbackQuery.Set("openid.ext1.value.fullname", "Bob Jones")
	callbackQuery.Set("openid.signed", "mode,return_to,response_nonce,ns.ext1,ext1.type.email,ext1.value.email,ext1.type.nickname,ext1.value.nickname,ext1.type.fullname,ext1.value.fullname")
	callbackQuery.Set("openid.response_nonce", time.Now().UTC().Format(time.RFC3339)+"extra")

	req := httptest.NewRequest("GET", "/auth/openid/callback?"+callbackQuery.Encode(), nil)

	claims, err := client.VerifyCallback(context.Background(), req, returnTo)
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
	returnTo := "https://example.com/auth/openid/callback"

	callbackQuery := url.Values{}
	callbackQuery.Set("openid.mode", "id_res")
	callbackQuery.Set("openid.ns", openid.OpenIDNS)
	callbackQuery.Set("openid.return_to", returnTo)
	callbackQuery.Set("openid.ns.sreg", openid.SREGNS)
	callbackQuery.Set("openid.sreg.email", "canonical-user@canonical.com")
	callbackQuery.Set("openid.sreg.nickname", "canonical-user")
	callbackQuery.Set("openid.sreg.fullname", "Canonical Test User")
	callbackQuery.Set("openid.claimed_id", "https://sso.iam.test.canonical.com/+id/Xb6LTdm")
	callbackQuery.Set("openid.identity", "https://sso.iam.test.canonical.com/+id/Xb6LTdm")
	callbackQuery.Set("openid.signed", "mode,ns,return_to,response_nonce,claimed_id,identity,ns.sreg,sreg.email,sreg.nickname,sreg.fullname")
	callbackQuery.Set("openid.response_nonce", time.Now().UTC().Format(time.RFC3339)+"extra")

	req := httptest.NewRequest("GET", "/auth/openid/callback?"+callbackQuery.Encode(), nil)

	claims, err := client.VerifyCallback(context.Background(), req, returnTo)
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
	if userID != "Xb6LTdm" {
		t.Errorf("UserID: got %q, want Xb6LTdm", userID)
	}

	norm := claims.NormalizedClaims()
	if norm["email"] != "canonical-user@canonical.com" {
		t.Errorf("norm[email]: got %v, want canonical-user@canonical.com", norm["email"])
	}
	if norm["u1_sso_id"] != "Xb6LTdm" {
		t.Errorf("norm[u1_sso_id]: got %v, want Xb6LTdm", norm["u1_sso_id"])
	}
	if _, hasLegacy := norm["claimed_id"]; hasLegacy {
		t.Errorf("norm[claimed_id]: expected legacy claimed_id claim to be omitted, got %v", norm["claimed_id"])
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
	returnTo := "https://example.com/auth/openid/callback"

	callbackQuery := url.Values{}
	callbackQuery.Set("openid.mode", "id_res")
	callbackQuery.Set("openid.ns", openid.OpenIDNS)
	callbackQuery.Set("openid.return_to", returnTo)
	callbackQuery.Set("openid.ns.ext2", openid.SREGNS10)
	callbackQuery.Set("openid.ext2.email", "ext2-user@example.com")
	callbackQuery.Set("openid.ext2.nickname", "ext2-nick")
	callbackQuery.Set("openid.ext2.fullname", "Ext2 Name")
	callbackQuery.Set("openid.signed", "mode,ns,return_to,response_nonce,ns.ext2,ext2.email,ext2.nickname,ext2.fullname")
	callbackQuery.Set("openid.response_nonce", time.Now().UTC().Format(time.RFC3339)+"extra")

	req := httptest.NewRequest("GET", "/auth/openid/callback?"+callbackQuery.Encode(), nil)

	claims, err := client.VerifyCallback(context.Background(), req, returnTo)
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
	_, err := client.VerifyCallback(context.Background(), req, "https://example.com/auth/openid/callback")
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
	_, err := client.VerifyCallback(context.Background(), req1, "https://example.com/auth/openid/callback")
	if err == nil {
		t.Error("expected error for missing mode")
	}

	// Unexpected mode
	q := url.Values{}
	q.Set("openid.mode", "unsupported")
	req2 := httptest.NewRequest("GET", "/auth/openid/callback?"+q.Encode(), nil)
	_, err = client.VerifyCallback(context.Background(), req2, "https://example.com/auth/openid/callback")
	if err == nil {
		t.Error("expected error for unsupported mode")
	}

	// Missing nonce
	q.Set("openid.mode", "id_res")
	q.Set("openid.return_to", "https://example.com/auth/openid/callback")
	req3 := httptest.NewRequest("GET", "/auth/openid/callback?"+q.Encode(), nil)
	_, err = client.VerifyCallback(context.Background(), req3, "https://example.com/auth/openid/callback")
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
	returnTo := "https://example.com/auth/openid/callback"

	q := url.Values{}
	q.Set("openid.mode", "id_res")
	q.Set("openid.return_to", returnTo)
	q.Set("openid.response_nonce", time.Now().UTC().Format(time.RFC3339)+"extra")
	q.Set("openid.signed", "mode,return_to,response_nonce")

	req := httptest.NewRequest("GET", "/auth/openid/callback?"+q.Encode(), nil)
	_, err := client.VerifyCallback(context.Background(), req, returnTo)
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
	returnTo := "https://example.com/auth/openid/callback"

	q := url.Values{}
	q.Set("openid.mode", "id_res")
	q.Set("openid.return_to", returnTo)
	q.Set("openid.response_nonce", time.Now().UTC().Format(time.RFC3339)+"extra")
	q.Set("openid.signed", "mode,return_to,response_nonce")

	req := httptest.NewRequest("GET", "/auth/openid/callback?"+q.Encode(), nil)
	_, err := client.VerifyCallback(context.Background(), req, returnTo)
	if err == nil {
		t.Fatal("expected error on 500 response, got nil")
	}
}

func TestVerifyCallback_ReturnToMismatch(t *testing.T) {
	client := openid.NewClient("https://login.ubuntu.com/+openid", "", nil)

	q := url.Values{}
	q.Set("openid.mode", "id_res")
	q.Set("openid.return_to", "https://example.com/auth/openid/callback?state=expected-state")

	req := httptest.NewRequest("GET", "/auth/openid/callback?"+q.Encode(), nil)
	_, err := client.VerifyCallback(context.Background(), req, "https://example.com/auth/openid/callback?state=different-state")
	if err == nil {
		t.Fatal("expected error on return_to mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "return_to mismatch") {
		t.Errorf("expected return_to mismatch error, got: %v", err)
	}
}

func TestVerifyCallback_MissingReturnTo(t *testing.T) {
	client := openid.NewClient("https://login.ubuntu.com/+openid", "", nil)

	q := url.Values{}
	q.Set("openid.mode", "id_res")
	// No openid.return_to set

	req := httptest.NewRequest("GET", "/auth/openid/callback?"+q.Encode(), nil)
	_, err := client.VerifyCallback(context.Background(), req, "https://example.com/auth/openid/callback")
	if err == nil {
		t.Fatal("expected error on missing return_to, got nil")
	}
	if !strings.Contains(err.Error(), "missing openid.return_to") {
		t.Errorf("expected missing return_to error, got: %v", err)
	}
}

func TestVerifyCallback_NonceReplay(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("is_valid:true\n"))
	}))
	defer server.Close()

	client := openid.NewClient(server.URL, "", server.Client())
	returnTo := "https://example.com/auth/openid/callback"

	q := url.Values{}
	q.Set("openid.mode", "id_res")
	q.Set("openid.return_to", returnTo)
	nonce := time.Now().UTC().Format(time.RFC3339) + "unique-token"
	q.Set("openid.response_nonce", nonce)
	q.Set("openid.signed", "mode,return_to,response_nonce")

	req1 := httptest.NewRequest("GET", "/auth/openid/callback?"+q.Encode(), nil)
	_, err := client.VerifyCallback(context.Background(), req1, returnTo)
	if err != nil {
		t.Fatalf("first verification failed: %v", err)
	}

	req2 := httptest.NewRequest("GET", "/auth/openid/callback?"+q.Encode(), nil)
	_, err = client.VerifyCallback(context.Background(), req2, returnTo)
	if err == nil {
		t.Fatal("expected error on nonce replay, got nil")
	}
	if !strings.Contains(err.Error(), "replay detected") {
		t.Errorf("expected replay detected error, got: %v", err)
	}
}

func TestVerifyCallback_TimestampSkew(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("is_valid:true\n"))
	}))
	defer server.Close()

	client := openid.NewClient(server.URL, "", server.Client())
	returnTo := "https://example.com/auth/openid/callback"

	tests := []struct {
		name      string
		timestamp time.Time
		wantErr   bool
	}{
		{
			name:      "6 minutes in past",
			timestamp: time.Now().UTC().Add(-6 * time.Minute),
			wantErr:   true,
		},
		{
			name:      "6 minutes in future",
			timestamp: time.Now().UTC().Add(6 * time.Minute),
			wantErr:   true,
		},
		{
			name:      "2 minutes in past",
			timestamp: time.Now().UTC().Add(-2 * time.Minute),
			wantErr:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := url.Values{}
			q.Set("openid.mode", "id_res")
			q.Set("openid.return_to", returnTo)
			q.Set("openid.response_nonce", tc.timestamp.Format(time.RFC3339)+tc.name)
			q.Set("openid.signed", "mode,return_to,response_nonce")

			req := httptest.NewRequest("GET", "/auth/openid/callback?"+q.Encode(), nil)
			_, err := client.VerifyCallback(context.Background(), req, returnTo)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected timestamp skew error, got nil")
				}
				if !strings.Contains(err.Error(), "acceptable skew") {
					t.Errorf("expected acceptable skew error, got: %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error for valid skew: %v", err)
				}
			}
		})
	}
}

func TestVerifyCallback_ProviderNon200(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusNotFound, http.StatusBadGateway} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			}))
			defer server.Close()

			client := openid.NewClient(server.URL, "", server.Client())
			returnTo := "https://example.com/auth/openid/callback"

			q := url.Values{}
			q.Set("openid.mode", "id_res")
			q.Set("openid.return_to", returnTo)
			q.Set("openid.response_nonce", time.Now().UTC().Format(time.RFC3339)+"extra")
			q.Set("openid.signed", "mode,return_to,response_nonce")

			req := httptest.NewRequest("GET", "/auth/openid/callback?"+q.Encode(), nil)
			_, err := client.VerifyCallback(context.Background(), req, returnTo)
			if err == nil {
				t.Fatalf("expected error for status %d, got nil", status)
			}
			if !strings.Contains(err.Error(), fmt.Sprintf("status %d", status)) {
				t.Errorf("expected error mentioning status %d, got: %v", status, err)
			}
		})
	}
}

func TestVerifyCallback_SREGFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("is_valid:true\n"))
	}))
	defer server.Close()

	client := openid.NewClient(server.URL, "", server.Client())
	returnTo := "https://example.com/auth/openid/callback"

	t.Run("SREG attributes only without AX", func(t *testing.T) {
		q := url.Values{}
		q.Set("openid.mode", "id_res")
		q.Set("openid.return_to", returnTo)
		q.Set("openid.response_nonce", time.Now().UTC().Format(time.RFC3339)+"sregonly")
		q.Set("openid.claimed_id", "https://login.ubuntu.com/+id/sreg1")
		q.Set("openid.sreg.email", "sreg@canonical.com")
		q.Set("openid.sreg.nickname", "sreguser")
		q.Set("openid.sreg.fullname", "SREG User")
		q.Set("openid.signed", "mode,return_to,response_nonce,claimed_id,sreg.email,sreg.nickname,sreg.fullname")

		req := httptest.NewRequest("GET", "/auth/openid/callback?"+q.Encode(), nil)
		claims, err := client.VerifyCallback(context.Background(), req, returnTo)
		if err != nil {
			t.Fatalf("VerifyCallback failed: %v", err)
		}
		if claims.Email != "sreg@canonical.com" {
			t.Errorf("Email: got %q, want sreg@canonical.com", claims.Email)
		}
		if claims.Nickname != "sreguser" {
			t.Errorf("Nickname: got %q, want sreguser", claims.Nickname)
		}
		if claims.FullName != "SREG User" {
			t.Errorf("FullName: got %q, want SREG User", claims.FullName)
		}
	})

	t.Run("Mixed AX and SREG fallback", func(t *testing.T) {
		q := url.Values{}
		q.Set("openid.mode", "id_res")
		q.Set("openid.return_to", returnTo)
		q.Set("openid.response_nonce", time.Now().UTC().Format(time.RFC3339)+"mixed")
		q.Set("openid.claimed_id", "https://login.ubuntu.com/+id/mixed1")
		// Email in AX
		q.Set("openid.ns.ax", openid.AXNS)
		q.Set("openid.ax.type.email", openid.AXSchemaEmail)
		q.Set("openid.ax.value.email", "mixed-ax@canonical.com")
		// Nickname and FullName in SREG
		q.Set("openid.sreg.nickname", "mixednick")
		q.Set("openid.sreg.fullname", "Mixed Fullname")
		q.Set("openid.signed", "mode,return_to,response_nonce,claimed_id,ns.ax,ax.type.email,ax.value.email,sreg.nickname,sreg.fullname")

		req := httptest.NewRequest("GET", "/auth/openid/callback?"+q.Encode(), nil)
		claims, err := client.VerifyCallback(context.Background(), req, returnTo)
		if err != nil {
			t.Fatalf("VerifyCallback failed: %v", err)
		}
		if claims.Email != "mixed-ax@canonical.com" {
			t.Errorf("Email: got %q, want mixed-ax@canonical.com", claims.Email)
		}
		if claims.Nickname != "mixednick" {
			t.Errorf("Nickname: got %q, want mixednick", claims.Nickname)
		}
		if claims.FullName != "Mixed Fullname" {
			t.Errorf("FullName: got %q, want Mixed Fullname", claims.FullName)
		}
	})
}

func TestClaims_UserID(t *testing.T) {
	tests := []struct {
		name       string
		claims     openid.Claims
		wantUserID string
		wantErr    bool
	}{
		{
			name: "short u1_sso_id returned when claimed_id and email are present",
			claims: openid.Claims{
				Email:     "user@canonical.com",
				Nickname:  "user_nick",
				ClaimedID: "https://login.ubuntu.com/+id/user123",
			},
			wantUserID: "user123",
			wantErr:    false,
		},
		{
			name: "error when email absent despite nickname and claimed_id",
			claims: openid.Claims{
				Nickname:  "user_nick",
				ClaimedID: "https://login.ubuntu.com/+id/user123",
			},
			wantUserID: "",
			wantErr:    true,
		},
		{
			name: "error when email is whitespace only",
			claims: openid.Claims{
				Email:     "   \t\n ",
				Nickname:  "user_nick",
				ClaimedID: "https://login.ubuntu.com/+id/user123",
			},
			wantUserID: "",
			wantErr:    true,
		},
		{
			name: "error when claimed_id absent despite email and nickname",
			claims: openid.Claims{
				Email:    "user@canonical.com",
				Nickname: "user_nick",
			},
			wantUserID: "",
			wantErr:    true,
		},
		{
			name: "error when claimed_id is whitespace only",
			claims: openid.Claims{
				Email:     "user@canonical.com",
				ClaimedID: "   \t\n ",
			},
			wantUserID: "",
			wantErr:    true,
		},
		{
			name: "error when claimed_id is identifier_select sentinel",
			claims: openid.Claims{
				Email:     "user@canonical.com",
				ClaimedID: openid.OpenIDIdentifierSelect,
			},
			wantUserID: "",
			wantErr:    true,
		},
		{
			name: "error when claimed_id uses http instead of https",
			claims: openid.Claims{
				Email:     "user@canonical.com",
				ClaimedID: "http://login.ubuntu.com/+id/user123",
			},
			wantUserID: "",
			wantErr:    true,
		},
		{
			name: "error when claimed_id misses /+id/ prefix",
			claims: openid.Claims{
				Email:     "user@canonical.com",
				ClaimedID: "https://login.ubuntu.com/users/user123",
			},
			wantUserID: "",
			wantErr:    true,
		},
		{
			name: "error when claimed_id short id has extra path segment or colon",
			claims: openid.Claims{
				Email:     "user@canonical.com",
				ClaimedID: "https://login.ubuntu.com/+id/bad:id",
			},
			wantUserID: "",
			wantErr:    true,
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

func TestExtractClaims_NoIdentityFallbackAndRejectsIdentifierSelect(t *testing.T) {
	t.Run("signed identity without claimed_id does not populate ClaimedID", func(t *testing.T) {
		q := url.Values{
			"openid.identity":   {"https://login.ubuntu.com/+id/local-id"},
			"openid.ns.sreg":    {openid.SREGNS},
			"openid.sreg.email": {"alice@canonical.com"},
			"openid.signed":     {"identity,ns.sreg,sreg.email"},
		}
		claims := openid.ExtractClaims(q)
		if claims.ClaimedID != "" {
			t.Errorf("ClaimedID = %q, want empty (no openid.identity fallback)", claims.ClaimedID)
		}
		if _, err := claims.UserID(); err == nil {
			t.Error("expected UserID() to fail when claimed_id is absent")
		}
		if _, exists := claims.NormalizedClaims()["u1_sso_id"]; exists {
			t.Error("expected u1_sso_id to be omitted when claimed_id is absent")
		}
	})

	t.Run("identifier_select sentinel is ignored", func(t *testing.T) {
		q := url.Values{
			"openid.claimed_id": {openid.OpenIDIdentifierSelect},
			"openid.ns.sreg":    {openid.SREGNS},
			"openid.sreg.email": {"alice@canonical.com"},
			"openid.signed":     {"claimed_id,ns.sreg,sreg.email"},
		}
		claims := openid.ExtractClaims(q)
		if claims.ClaimedID != "" {
			t.Errorf("ClaimedID = %q, want empty for identifier_select", claims.ClaimedID)
		}
		if _, err := claims.UserID(); err == nil {
			t.Error("expected UserID() to fail for identifier_select")
		}
	})
}

func TestExtractClaims_SignedOnlyAndNoUnsignedFallback(t *testing.T) {
	q := url.Values{
		"openid.claimed_id":     {"https://login.ubuntu.com/+id/alice"},
		"openid.ns.ax":          {"http://openid.net/srv/ax/1.0"},
		"openid.ax.mode":        {"fetch_response"},
		"openid.ax.type.email":  {"http://axschema.org/contact/email"},
		"openid.ax.value.email": {"alice@canonical.com"},
		"openid.ax.type.first":  {"http://axschema.org/namePerson/first"},
		"openid.ax.value.first": {"Alice"},
		"openid.signed":         {"claimed_id,ns.ax,ax.type.email,ax.value.email,ax.type.first,ax.value.first"},
		// Unsigned injected parameters must be ignored.
		"openid.sreg.nickname": {"spoofed-nick"},
		"openid.sreg.tenant":   {"target-org"},
		"tenant":               {"target-org"},
		"email":                {"spoofed@evil.com"},
		"openid.fullname":      {"Spoofed Name"},
	}

	claims := openid.ExtractClaims(q)
	if claims.Email != "alice@canonical.com" {
		t.Errorf("Email = %q, want alice@canonical.com", claims.Email)
	}
	if claims.GivenName != "Alice" {
		t.Errorf("GivenName = %q, want Alice", claims.GivenName)
	}
	if claims.Nickname != "" {
		t.Errorf("unsigned Nickname leaked: got %q, want empty", claims.Nickname)
	}
	if claims.FullName != "Alice" {
		t.Errorf("FullName = %q, want Alice (unsigned openid.fullname must be ignored)", claims.FullName)
	}

	norm := claims.NormalizedClaims()
	if norm["given_name"] != "Alice" {
		t.Errorf("NormalizedClaims[given_name] = %v, want Alice", norm["given_name"])
	}
	if _, hasTenant := norm["tenant"]; hasTenant {
		t.Errorf("unexpected tenant in OpenID NormalizedClaims: %v", norm["tenant"])
	}
}

func TestVerifyCallback_RejectsDuplicateOpenIDParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("is_valid:true\n"))
	}))
	defer server.Close()

	client := openid.NewClient(server.URL, "", server.Client())
	returnTo := "https://example.com/auth/openid/callback"

	baseQuery := func() url.Values {
		q := url.Values{}
		q.Set("openid.mode", "id_res")
		q.Set("openid.return_to", returnTo)
		q.Set("openid.response_nonce", time.Now().UTC().Format(time.RFC3339)+"dup")
		q.Set("openid.claimed_id", "https://login.ubuntu.com/+id/attacker")
		q.Set("openid.sreg.email", "attacker@example.com")
		q.Set("openid.signed", "mode,return_to,response_nonce,claimed_id,sreg.email")
		return q
	}

	tests := []struct {
		name   string
		mutate func(q url.Values)
	}{
		{
			name: "duplicate openid.sreg.email",
			mutate: func(q url.Values) {
				q["openid.sreg.email"] = []string{"victim@canonical.com", "attacker@example.com"}
			},
		},
		{
			name: "duplicate openid.signed",
			mutate: func(q url.Values) {
				q["openid.signed"] = []string{"mode,return_to,response_nonce,sreg.email", "mode,return_to,response_nonce"}
			},
		},
		{
			name: "duplicate openid.return_to",
			mutate: func(q url.Values) {
				q["openid.return_to"] = []string{returnTo, "https://evil.example.com/cb"}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := baseQuery()
			tc.mutate(q)
			req := httptest.NewRequest("GET", "/auth/openid/callback?"+q.Encode(), nil)
			if _, err := client.VerifyCallback(context.Background(), req, returnTo); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestVerifyCallback_RequiresCoreSignedFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("is_valid:true\n"))
	}))
	defer server.Close()

	client := openid.NewClient(server.URL, "", server.Client())
	returnTo := "https://example.com/auth/openid/callback"

	tests := []struct {
		name   string
		signed string
	}{
		{name: "missing openid.signed", signed: ""},
		{name: "missing return_to", signed: "mode,response_nonce,claimed_id"},
		{name: "missing response_nonce", signed: "mode,return_to,claimed_id"},
		{name: "missing claimed_id when present", signed: "mode,return_to,response_nonce"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := url.Values{}
			q.Set("openid.mode", "id_res")
			q.Set("openid.return_to", returnTo)
			q.Set("openid.response_nonce", time.Now().UTC().Format(time.RFC3339)+"core-"+tc.name)
			q.Set("openid.claimed_id", "https://login.ubuntu.com/+id/alice")
			if tc.signed != "" {
				q.Set("openid.signed", tc.signed)
			}
			req := httptest.NewRequest("GET", "/auth/openid/callback?"+q.Encode(), nil)
			if _, err := client.VerifyCallback(context.Background(), req, returnTo); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestExtractClaims_RejectsDuplicateParamsAndEnforcesAXTypeBinding(t *testing.T) {
	t.Run("duplicate openid.sreg.email fails closed", func(t *testing.T) {
		q := url.Values{
			"openid.signed":     {"claimed_id,sreg.email"},
			"openid.claimed_id": {"https://login.ubuntu.com/+id/attacker"},
			"openid.sreg.email": {"victim@canonical.com", "attacker@example.com"},
		}
		claims := openid.ExtractClaims(q)
		if claims.Email != "" {
			t.Errorf("expected empty Email on duplicate openid.sreg.email, got %q", claims.Email)
		}
	})

	t.Run("duplicate openid.signed fails closed", func(t *testing.T) {
		q := url.Values{
			"openid.signed":     {"claimed_id,sreg.email", "claimed_id"},
			"openid.claimed_id": {"https://login.ubuntu.com/+id/attacker"},
			"openid.sreg.email": {"victim@canonical.com"},
		}
		claims := openid.ExtractClaims(q)
		if claims.Email != "" || claims.ClaimedID != "" {
			t.Errorf("expected empty claims on duplicate openid.signed, got %+v", claims)
		}
	})

	t.Run("AX alias confusion and missing type URI rejected", func(t *testing.T) {
		q := url.Values{
			"openid.claimed_id":          {"https://login.ubuntu.com/+id/attacker"},
			"openid.ns.ax":               {openid.AXNS},
			"openid.ax.type.email":       {openid.AXSchemaNickname},
			"openid.ax.value.email":      {"victim@canonical.com"},
			"openid.ax.value.given_name": {"SpoofedGiven"},
			"openid.signed":              {"claimed_id,ns.ax,ax.type.email,ax.value.email,ax.value.given_name"},
		}
		claims := openid.ExtractClaims(q)
		if claims.Email != "" {
			t.Errorf("AX alias bound to nickname schema must not populate Email: got %q", claims.Email)
		}
		if claims.Nickname != "victim@canonical.com" {
			t.Errorf("AX alias bound to nickname schema should populate Nickname: got %q", claims.Nickname)
		}
		if claims.GivenName != "" {
			t.Errorf("AX value without signed type URI must not populate GivenName: got %q", claims.GivenName)
		}
	})
}
