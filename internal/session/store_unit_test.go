// Copyright 2026 Canonical Ltd.
// SPDX-License-Identifier: AGPL-3.0-only

package session

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	valkeygo "github.com/valkey-io/valkey-go"
)

// fakeValkeyServer is a minimal in-memory RESP2 TCP server for unit testing ValkeyStore
// without requiring Docker/Podman containers.
type fakeValkeyServer struct {
	ln         net.Listener
	mu         sync.Mutex
	kv         map[string]string
	sets       map[string]map[string]struct{}
	ttls       map[string]int64 // remaining seconds; absent means no expiry (-1)
	failDelKey string
}

func (f *fakeValkeyServer) injectSetMember(setKey, member string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sets[setKey] == nil {
		f.sets[setKey] = make(map[string]struct{})
	}
	f.sets[setKey][member] = struct{}{}
}

func (f *fakeValkeyServer) getSetCopy(setKey string) map[string]struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	src := f.sets[setKey]
	out := make(map[string]struct{}, len(src))
	for k := range src {
		out[k] = struct{}{}
	}
	return out
}

func (f *fakeValkeyServer) hasSetKey(setKey string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.sets[setKey]
	return ok
}

func (f *fakeValkeyServer) getTTL(key string) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ttls[key]
}

func (f *fakeValkeyServer) setFailDelKey(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failDelKey = key
}

func startFakeValkeyServer(t *testing.T) (*fakeValkeyServer, *ValkeyStore) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	srv := &fakeValkeyServer{
		ln:   ln,
		kv:   make(map[string]string),
		sets: make(map[string]map[string]struct{}),
		ttls: make(map[string]int64),
	}

	go srv.acceptLoop()

	client, err := valkeygo.NewClient(valkeygo.ClientOption{
		InitAddress:       []string{ln.Addr().String()},
		AlwaysRESP2:       true,
		DisableCache:      true,
		ForceSingleClient: true,
	})
	if err != nil {
		_ = ln.Close()
		t.Fatalf("failed to create valkey client: %v", err)
	}

	store := &ValkeyStore{
		client: client,
		ttl:    1 * time.Hour,
	}

	t.Cleanup(func() {
		store.Close()
		_ = ln.Close()
	})

	return srv, store
}

func (f *fakeValkeyServer) acceptLoop() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handleConn(conn)
	}
}

func (f *fakeValkeyServer) handleConn(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	for {
		args, err := readRESPCommand(r)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}
		resp := f.exec(args)
		if _, err := w.WriteString(resp); err != nil {
			return
		}
		if err := w.Flush(); err != nil {
			return
		}
	}
}

func readRESPCommand(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	if len(line) == 0 || line[0] != '*' {
		return nil, fmt.Errorf("unexpected resp prefix: %q", line)
	}
	count, err := strconv.Atoi(line[1:])
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, count)
	for i := 0; i < count; i++ {
		lenLine, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		lenLine = strings.TrimSuffix(strings.TrimSuffix(lenLine, "\n"), "\r")
		if len(lenLine) == 0 || lenLine[0] != '$' {
			return nil, fmt.Errorf("unexpected bulk prefix: %q", lenLine)
		}
		n, err := strconv.Atoi(lenLine[1:])
		if err != nil {
			return nil, err
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:n]))
	}
	return args, nil
}

func respBulk(s string) string {
	return fmt.Sprintf("$%d\r\n%s\r\n", len(s), s)
}

func respArray(items []string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("*%d\r\n", len(items)))
	for _, item := range items {
		sb.WriteString(respBulk(item))
	}
	return sb.String()
}

func (f *fakeValkeyServer) keyExistsLocked(key string) bool {
	if _, ok := f.kv[key]; ok {
		return true
	}
	if _, ok := f.sets[key]; ok {
		return true
	}
	return false
}

func (f *fakeValkeyServer) exec(args []string) string {
	cmd := strings.ToUpper(args[0])

	f.mu.Lock()
	defer f.mu.Unlock()

	switch cmd {
	case "HELLO":
		return "*4\r\n$6\r\nserver\r\n$6\r\nvalkey\r\n$5\r\nproto\r\n:2\r\n"
	case "PING":
		return "+PONG\r\n"
	case "CLIENT":
		return "+OK\r\n"
	case "SETEX":
		if len(args) < 4 {
			return "-ERR wrong number of arguments\r\n"
		}
		key := args[1]
		secs, err := strconv.ParseInt(args[2], 10, 64)
		if err != nil {
			return "-ERR invalid ttl\r\n"
		}
		f.kv[key] = args[3]
		f.ttls[key] = secs
		return "+OK\r\n"
	case "GET":
		if len(args) < 2 {
			return "-ERR wrong number of arguments\r\n"
		}
		val, ok := f.kv[args[1]]
		if !ok {
			return "$-1\r\n"
		}
		return respBulk(val)
	case "TTL":
		if len(args) < 2 {
			return "-ERR wrong number of arguments\r\n"
		}
		key := args[1]
		if !f.keyExistsLocked(key) {
			return ":-2\r\n"
		}
		secs, ok := f.ttls[key]
		if !ok {
			return ":-1\r\n"
		}
		return fmt.Sprintf(":%d\r\n", secs)
	case "EXPIRE":
		if len(args) < 3 {
			return "-ERR wrong number of arguments\r\n"
		}
		key := args[1]
		secs, err := strconv.ParseInt(args[2], 10, 64)
		if err != nil {
			return "-ERR invalid ttl\r\n"
		}
		if !f.keyExistsLocked(key) {
			return ":0\r\n"
		}
		if len(args) >= 4 {
			cond := strings.ToUpper(args[3])
			cur, hasTTL := f.ttls[key]
			switch cond {
			case "NX":
				if hasTTL {
					return ":0\r\n"
				}
			case "GT":
				if !hasTTL || secs <= cur {
					return ":0\r\n"
				}
			}
		}
		f.ttls[key] = secs
		return ":1\r\n"
	case "DEL":
		var deleted int64
		for _, key := range args[1:] {
			if f.failDelKey != "" && key == f.failDelKey {
				return "-ERR simulated del failure\r\n"
			}
			existed := false
			if _, ok := f.kv[key]; ok {
				delete(f.kv, key)
				existed = true
			}
			if _, ok := f.sets[key]; ok {
				delete(f.sets, key)
				existed = true
			}
			delete(f.ttls, key)
			if existed {
				deleted++
			}
		}
		return fmt.Sprintf(":%d\r\n", deleted)
	case "SADD":
		if len(args) < 3 {
			return "-ERR wrong number of arguments\r\n"
		}
		key := args[1]
		set, ok := f.sets[key]
		if !ok {
			set = make(map[string]struct{})
			f.sets[key] = set
		}
		var added int64
		for _, m := range args[2:] {
			if _, exists := set[m]; !exists {
				set[m] = struct{}{}
				added++
			}
		}
		return fmt.Sprintf(":%d\r\n", added)
	case "SREM":
		if len(args) < 3 {
			return "-ERR wrong number of arguments\r\n"
		}
		set, ok := f.sets[args[1]]
		if !ok {
			return ":0\r\n"
		}
		var removed int64
		for _, m := range args[2:] {
			if _, exists := set[m]; exists {
				delete(set, m)
				removed++
			}
		}
		if len(set) == 0 {
			delete(f.sets, args[1])
			delete(f.ttls, args[1])
		}
		return fmt.Sprintf(":%d\r\n", removed)
	case "SMEMBERS":
		if len(args) < 2 {
			return "-ERR wrong number of arguments\r\n"
		}
		set, ok := f.sets[args[1]]
		if !ok {
			return "*0\r\n"
		}
		members := make([]string, 0, len(set))
		for m := range set {
			members = append(members, m)
		}
		return respArray(members)
	case "SISMEMBER":
		if len(args) < 3 {
			return "-ERR wrong number of arguments\r\n"
		}
		set, ok := f.sets[args[1]]
		if !ok {
			return ":0\r\n"
		}
		if _, exists := set[args[2]]; exists {
			return ":1\r\n"
		}
		return ":0\r\n"
	default:
		return fmt.Sprintf("-ERR unsupported command %s\r\n", cmd)
	}
}

func TestValkeyStoreUnit_ListUserSessions_TTLDerivedAndLazyPrune(t *testing.T) {
	srv, store := startFakeValkeyServer(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	older := &Session{
		SessionID: "sess-1",
		UserID:    "alice@canonical.com",
		Provider:  "oidc",
		CreatedAt: now.Add(-10 * time.Minute),
		// Deliberately stale stored ExpiresAt to prove ListUserSessions derives from Valkey TTL.
		ExpiresAt: now.Add(5 * time.Minute),
	}
	newer := &Session{
		SessionID: "sess-2",
		UserID:    "alice@canonical.com",
		Provider:  "openid",
		CreatedAt: now.Add(-2 * time.Minute),
		ExpiresAt: now.Add(5 * time.Minute),
	}

	if err := store.Set(ctx, older, WithTTL(1800*time.Second)); err != nil {
		t.Fatalf("Set(older) failed: %v", err)
	}
	if err := store.Set(ctx, newer, WithTTL(3600*time.Second)); err != nil {
		t.Fatalf("Set(newer) failed: %v", err)
	}

	// Inject a stale/expired session ID directly into user_sessions:<userID>.
	srv.injectSetMember("user_sessions:alice@canonical.com", "sess-expired")

	before := time.Now()
	sessions, err := store.ListUserSessions(ctx, "alice@canonical.com")
	if err != nil {
		t.Fatalf("ListUserSessions failed: %v", err)
	}

	if len(sessions) != 2 {
		t.Fatalf("expected 2 active sessions, got %d", len(sessions))
	}
	// Sorted newest CreatedAt first
	if sessions[0].SessionID != "sess-2" || sessions[1].SessionID != "sess-1" {
		t.Fatalf("unexpected session order: got [%s, %s], want [sess-2, sess-1]", sessions[0].SessionID, sessions[1].SessionID)
	}

	// ExpiresAt must be derived from active TTL (3600s and 1800s), not stale 5m stored value.
	if delta := sessions[0].ExpiresAt.Sub(before); delta < 3590*time.Second || delta > 3610*time.Second {
		t.Errorf("sess-2 ExpiresAt not derived from TTL: delta=%v", delta)
	}
	if delta := sessions[1].ExpiresAt.Sub(before); delta < 1790*time.Second || delta > 1810*time.Second {
		t.Errorf("sess-1 ExpiresAt not derived from TTL: delta=%v", delta)
	}

	// Verify expired session ID was lazily pruned from user_sessions:<userID>.
	setCopy := srv.getSetCopy("user_sessions:alice@canonical.com")
	if _, stillPresent := setCopy["sess-expired"]; stillPresent {
		t.Error("expected expired session ID to be lazily pruned via SREM")
	}
}

func TestValkeyStoreUnit_ListUserSessions_EmptyUser(t *testing.T) {
	_, store := startFakeValkeyServer(t)
	ctx := context.Background()

	sessions, err := store.ListUserSessions(ctx, "nobody@canonical.com")
	if err != nil {
		t.Fatalf("ListUserSessions failed: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("expected 0 sessions, got %d", len(sessions))
	}
}

func TestValkeyStoreUnit_RevokeUserSessionsExcept(t *testing.T) {
	srv, store := startFakeValkeyServer(t)
	ctx := context.Background()

	userID := "bob@canonical.com"
	for _, id := range []string{"sess-a", "sess-b", "sess-c"} {
		if err := store.Set(ctx, &Session{
			SessionID: id,
			UserID:    userID,
			Provider:  "oidc",
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("Set(%s) failed: %v", id, err)
		}
	}

	// Inject a stale ID that has no session:<id> key to ensure revoked_count only counts active deleted sessions.
	srv.injectSetMember("user_sessions:"+userID, "sess-stale")

	// 1. Revoke all except sess-a
	revoked, err := store.RevokeUserSessionsExcept(ctx, userID, "sess-a")
	if err != nil {
		t.Fatalf("RevokeUserSessionsExcept failed: %v", err)
	}
	if revoked != 2 {
		t.Fatalf("expected 2 revoked sessions, got %d", revoked)
	}

	// sess-a must still exist; sess-b and sess-c must be deleted.
	if _, err := store.Get(ctx, "sess-a"); err != nil {
		t.Errorf("expected kept session sess-a to remain active, got err: %v", err)
	}
	for _, id := range []string{"sess-b", "sess-c"} {
		if _, err := store.Get(ctx, id); !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("expected %s to be deleted (ErrSessionNotFound), got %v", id, err)
		}
	}

	// user_sessions:<userID> must contain only sess-a.
	setCopy := srv.getSetCopy("user_sessions:" + userID)
	if len(setCopy) != 1 {
		t.Fatalf("expected 1 remaining ID in user_sessions set, got %v", setCopy)
	}
	if _, ok := setCopy["sess-a"]; !ok {
		t.Fatalf("expected sess-a in user_sessions set, got %v", setCopy)
	}

	// 2. Revoke all (keepSessionID == "")
	revokedAll, err := store.RevokeUserSessionsExcept(ctx, userID, "")
	if err != nil {
		t.Fatalf("RevokeUserSessionsExcept(all) failed: %v", err)
	}
	if revokedAll != 1 {
		t.Fatalf("expected 1 revoked session, got %d", revokedAll)
	}
	if _, err := store.Get(ctx, "sess-a"); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("expected sess-a to be deleted, got %v", err)
	}

	if srv.hasSetKey("user_sessions:" + userID) {
		t.Error("expected user_sessions set key to be deleted when keepSessionID is empty")
	}
}

func TestValkeyStoreUnit_Set_DoesNotShrinkUserSessionsTTL(t *testing.T) {
	srv, store := startFakeValkeyServer(t)
	ctx := context.Background()

	userID := "carol@canonical.com"
	userKey := "user_sessions:" + userID

	// Create initial session with 7200s TTL.
	if err := store.Set(ctx, &Session{
		SessionID: "sess-long",
		UserID:    userID,
		Provider:  "oidc",
		CreatedAt: time.Now(),
	}, WithTTL(7200*time.Second)); err != nil {
		t.Fatalf("Set(long) failed: %v", err)
	}

	if ttlAfterLong := srv.getTTL(userKey); ttlAfterLong != 7200 {
		t.Fatalf("expected user_sessions TTL=7200, got %d", ttlAfterLong)
	}

	// Create second session with shorter 600s TTL; user_sessions TTL MUST NOT shrink.
	if err := store.Set(ctx, &Session{
		SessionID: "sess-short",
		UserID:    userID,
		Provider:  "oidc",
		CreatedAt: time.Now(),
	}, WithTTL(600*time.Second)); err != nil {
		t.Fatalf("Set(short) failed: %v", err)
	}

	if ttlAfterShort := srv.getTTL(userKey); ttlAfterShort != 7200 {
		t.Fatalf("user_sessions TTL shrank from 7200 to %d", ttlAfterShort)
	}

	// Create third session with longer 10800s TTL; user_sessions TTL MUST extend.
	if err := store.Set(ctx, &Session{
		SessionID: "sess-longer",
		UserID:    userID,
		Provider:  "oidc",
		CreatedAt: time.Now(),
	}, WithTTL(10800*time.Second)); err != nil {
		t.Fatalf("Set(longer) failed: %v", err)
	}

	if ttlAfterLonger := srv.getTTL(userKey); ttlAfterLonger != 10800 {
		t.Fatalf("expected user_sessions TTL to extend to 10800, got %d", ttlAfterLonger)
	}
}

func TestValkeyStoreUnit_RevokeUserSessions_PartialErrorPreservesSet(t *testing.T) {
	srv, store := startFakeValkeyServer(t)
	ctx := context.Background()

	userID := "dave@canonical.com"
	for _, id := range []string{"sess-1", "sess-2"} {
		if err := store.Set(ctx, &Session{
			SessionID: id,
			UserID:    userID,
			Provider:  "oidc",
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("Set(%s) failed: %v", id, err)
		}
	}

	srv.setFailDelKey("session:sess-2")
	err := store.RevokeUserSessions(ctx, userID)
	if err == nil {
		t.Fatal("expected error when deleting session:sess-2 fails")
	}

	// user_sessions:<userID> MUST NOT be deleted when a session DEL failed.
	if !srv.hasSetKey("user_sessions:" + userID) {
		t.Error("expected user_sessions set to remain when individual DEL fails")
	}

	// Clear failure and retry: now all sessions and the user set are removed.
	srv.setFailDelKey("")
	if err := store.RevokeUserSessions(ctx, userID); err != nil {
		t.Fatalf("retry RevokeUserSessions failed: %v", err)
	}
	if srv.hasSetKey("user_sessions:" + userID) {
		t.Error("expected user_sessions set to be deleted after retry succeeds")
	}
}

func TestValkeyStoreUnit_RevokeUserSessionsExcept_PartialErrorPreservesRemainingAndRemovesDeleted(t *testing.T) {
	srv, store := startFakeValkeyServer(t)
	ctx := context.Background()

	userID := "eve@canonical.com"
	for _, id := range []string{"sess-cur", "sess-1", "sess-2"} {
		if err := store.Set(ctx, &Session{
			SessionID: id,
			UserID:    userID,
			Provider:  "oidc",
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("Set(%s) failed: %v", id, err)
		}
	}

	srv.setFailDelKey("session:sess-2")
	revoked, err := store.RevokeUserSessionsExcept(ctx, userID, "sess-cur")
	if err == nil {
		t.Fatal("expected error when deleting session:sess-2 fails")
	}
	if revoked != 1 {
		t.Fatalf("revoked = %d, want 1 (sess-1 deleted before sess-2 failed)", revoked)
	}

	// sess-1 must be removed from user_sessions:<userID>, while sess-cur and failed sess-2 stay.
	setCopy := srv.getSetCopy("user_sessions:" + userID)
	if _, ok := setCopy["sess-1"]; ok {
		t.Error("expected successfully deleted sess-1 to be SREM'd from user_sessions")
	}
	if _, ok := setCopy["sess-2"]; !ok {
		t.Error("expected failed sess-2 to remain in user_sessions for retry")
	}
	if _, ok := setCopy["sess-cur"]; !ok {
		t.Error("expected kept sess-cur to remain in user_sessions")
	}
}

func TestValkeyStoreUnit_DeleteUserSession(t *testing.T) {
	srv, store := startFakeValkeyServer(t)
	ctx := context.Background()

	alice := "alice@canonical.com"
	bob := "bob@canonical.com"

	if err := store.Set(ctx, &Session{
		SessionID: "sess-alice",
		UserID:    alice,
		Provider:  "oidc",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("Set(alice) failed: %v", err)
	}
	if err := store.Set(ctx, &Session{
		SessionID: "sess-bob",
		UserID:    bob,
		Provider:  "oidc",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("Set(bob) failed: %v", err)
	}

	// Foreign session must return ErrSessionNotFound without deleting Bob's session.
	if err := store.DeleteUserSession(ctx, alice, "sess-bob"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("DeleteUserSession(foreign) err = %v, want ErrSessionNotFound", err)
	}
	if _, err := store.Get(ctx, "sess-bob"); err != nil {
		t.Fatalf("expected bob's session to remain intact, got err: %v", err)
	}

	// Stale/expired session ID in Alice's index must return ErrSessionNotFound and be pruned.
	srv.injectSetMember("user_sessions:"+alice, "sess-stale")
	if err := store.DeleteUserSession(ctx, alice, "sess-stale"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("DeleteUserSession(stale) err = %v, want ErrSessionNotFound", err)
	}
	if _, stillPresent := srv.getSetCopy("user_sessions:" + alice)["sess-stale"]; stillPresent {
		t.Error("expected stale session ID to be pruned from user_sessions")
	}

	// Owned active session is deleted and removed from user_sessions.
	if err := store.DeleteUserSession(ctx, alice, "sess-alice"); err != nil {
		t.Fatalf("DeleteUserSession(owned) failed: %v", err)
	}
	if _, err := store.Get(ctx, "sess-alice"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected sess-alice to be deleted, got err: %v", err)
	}
	if srv.hasSetKey("user_sessions:" + alice) {
		t.Error("expected empty user_sessions set for alice to be removed")
	}
}

func TestValkeyStoreUnit_ListUserSessions_SkipsMalformedPayload(t *testing.T) {
	srv, store := startFakeValkeyServer(t)
	ctx := context.Background()

	userID := "frank@canonical.com"
	if err := store.Set(ctx, &Session{
		SessionID: "sess-good",
		UserID:    userID,
		Provider:  "oidc",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Inject a malformed JSON session into Valkey alongside the valid session.
	srv.mu.Lock()
	srv.kv["session:sess-bad"] = "{not-valid-json"
	srv.ttls["session:sess-bad"] = 1800
	srv.sets["user_sessions:"+userID]["sess-bad"] = struct{}{}
	srv.mu.Unlock()

	sessions, err := store.ListUserSessions(ctx, userID)
	if err != nil {
		t.Fatalf("ListUserSessions failed on malformed entry: %v", err)
	}
	if len(sessions) != 1 || sessions[0].SessionID != "sess-good" {
		t.Fatalf("expected only [sess-good], got %+v", sessions)
	}
}
