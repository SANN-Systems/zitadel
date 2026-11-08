package eventstore

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/repository/user"
)

// TestSannP4GuardLatency measures the guard against a real, disposable Postgres with the upstream
// events2 schema. It never runs in ordinary test runs: set SANN_P4_MALING_DSN to a throwaway database.
func TestSannP4GuardLatency(t *testing.T) {
	db := sannP4MalingDB(t)
	ctx := context.Background()
	// Background: 2 000 other users with 100 events each, so the index is not trivially small.
	seed(t, db, "bakgrunn-", 2000, 100)
	sizes := []int{100, 1000, 10000, 50000, 100000}
	for _, n := range sizes {
		seed(t, db, fmt.Sprintf("konto-%d-", n), 1, n)
	}
	if _, err := db.ExecContext(ctx, "ANALYZE eventstore.events2"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	policy := `{"org":"sann","journal":"journal","finalizer":"finalizer","kart":"kart","live":"live","deletion":"deletion"}`
	if err := os.WriteFile(path, []byte(policy), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SANN_P4_POLICY", path)
	t.Logf("| hendelser | innlogging p50 | innlogging p95 | kontakt p50 | kontakt p95 |")
	t.Logf("|---:|---:|---:|---:|---:|")
	for _, n := range sizes {
		a := &eventstore.Aggregate{ID: fmt.Sprintf("konto-%d-0", n), Type: "user", InstanceID: "instance", ResourceOwner: "sann"}
		login := measure(t, db, user.NewHumanPasswordCheckSucceededEvent(ctx, a, nil))
		contact := measure(t, db, user.NewHumanEmailChangedEvent(ctx, a, "ny@example.invalid"))
		t.Logf("| %d | %s | %s | %s | %s |", n, login[0], login[1], contact[0], contact[1])
		assertSameAsFullReplay(t, db, a.ID)
	}
}

// assertSameAsFullReplay proves on real Postgres that the owner lookup and the filtered replay
// give the same state as replaying every event of the user.
func assertSameAsFullReplay(t *testing.T, db *sql.DB, uid string) {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT sequence, owner, event_type, payload, creator FROM eventstore.events2 WHERE instance_id='instance' AND aggregate_type='user' AND aggregate_id=$1 ORDER BY sequence`, uid)
	if err != nil {
		t.Fatal(err)
	}
	var full sannP4State
	for rows.Next() {
		var seq uint64
		var owner, typ, creator string
		var raw []byte
		if err := rows.Scan(&seq, &owner, &typ, &raw, &creator); err != nil {
			t.Fatal(err)
		}
		if err := full.reduce(seq, owner, typ, raw, creator, "journal"); err != nil {
			t.Fatal(err)
		}
	}
	rows.Close()
	filtered, err := sannP4Read(ctx, tx, "instance", uid, "journal")
	if err != nil {
		t.Fatal(err)
	}
	human, owner, err := sannP4Owner(ctx, tx, "instance", uid)
	if err != nil {
		t.Fatal(err)
	}
	if filtered != full || human != full.Human || owner != full.Owner {
		t.Fatalf("%s: filtered %+v (%v, %s) differs from full %+v", uid, filtered, human, owner, full)
	}
}

// sannP4MalingDB opens the throwaway database and recreates the upstream events2 schema.
func sannP4MalingDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("SANN_P4_MALING_DSN")
	if dsn == "" {
		t.Skip("SANN_P4_MALING_DSN er ikke satt")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()
	schema, err := os.ReadFile("../../../cmd/initialise/sql/08_events_table.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{"DROP SCHEMA IF EXISTS eventstore CASCADE", "CREATE SCHEMA eventstore", string(schema[:bytes.Index(schema, []byte("CREATE OR REPLACE"))]),
		`CREATE TABLE eventstore.unique_constraints (instance_id TEXT, unique_type TEXT, unique_field TEXT, PRIMARY KEY (instance_id, unique_type, unique_field))`} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// A write allowed under a broken policy must wait for the user lock held by a transaction that
// decided under the valid policy, so that decision cannot miss a concurrent state change.
func TestSannP4PolicyErrorWaitsForUserLock(t *testing.T) {
	db := sannP4MalingDB(t)
	ctx := context.Background()
	seed(t, db, "samtidig-", 1, 10)
	path := filepath.Join(t.TempDir(), "policy.json")
	t.Setenv("SANN_P4_POLICY", path)
	write := func(policy string) {
		if err := os.WriteFile(path, []byte(policy), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"org":"sann","journal":"journal","finalizer":"finalizer","kart":"kart","live":"live","deletion":"deletion"}`)
	a := &eventstore.Aggregate{ID: "samtidig-0", Type: "user", InstanceID: "instance", ResourceOwner: "sann"}
	first, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Rollback()
	if err := sannP4Guard(ctx, first, []eventstore.Command{user.NewHumanPasswordCheckSucceededEvent(ctx, a, nil)}); err != nil {
		t.Fatal(err)
	}
	write(`{"org":`)
	second, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Rollback()
	done := make(chan error, 1)
	go func() { done <- sannP4Guard(ctx, second, []eventstore.Command{user.NewUserDeactivatedEvent(ctx, a)}) }()
	select {
	case err := <-done:
		t.Fatalf("write under broken policy did not wait for the user lock (err %v)", err)
	case <-time.After(500 * time.Millisecond):
	}
	if err := first.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("deactivation must pass under a broken policy: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("write did not continue after the lock was released")
	}
}

// seed writes realistic user histories: creation, then login, token and sign-out events with
// upstream-sized payloads, a phone code now and then and a metadata write every 1 000 events.
func seed(t *testing.T, db *sql.DB, prefix string, users, events int) {
	t.Helper()
	_, err := db.Exec(`
INSERT INTO eventstore.events2 (instance_id, aggregate_type, aggregate_id, event_type, sequence, revision, created_at, payload, creator, owner, position, in_tx_order)
SELECT 'instance', 'user', $1 || u, k.typ, s, 1, now(), p.payload, 'creator', 'sann', s, 0
FROM generate_series(0, $2 - 1) u, generate_series(1, $3) s,
LATERAL (SELECT CASE
  WHEN s = 1 THEN 'user.human.added'
  WHEN s % 1000 = 0 THEN 'user.metadata.set'
  WHEN s % 500 = 0 THEN 'user.human.phone.code.added'
  WHEN s % 3 = 0 THEN 'user.token.added'
  WHEN s % 3 = 1 THEN 'user.human.password.check.succeeded'
  ELSE 'user.human.signed.out' END AS typ) k,
LATERAL (SELECT CASE k.typ
  WHEN 'user.human.added' THEN '{"userName":"person@example.invalid","email":"person@example.invalid","phone":"+12025550100"}'::jsonb
  WHEN 'user.metadata.set' THEN '{"key":"sann.annet","value":"dmVyZGk="}'::jsonb
  WHEN 'user.human.phone.code.added' THEN '{"code":{"cryptoType":0,"algorithm":"aes","keyId":"k","crypted":"AAAAAAAAAAAAAAAAAAAAAAAA"},"expiry":300000000000}'::jsonb
  WHEN 'user.token.added' THEN ('{"tokenId":"' || md5(s::text) || '","applicationId":"app","userAgentId":"agent","refreshTokenID":"","audience":["app","project"],"scopes":["openid","profile","email","urn:zitadel:iam:org:project:id:zitadel:aud"],"expiration":"2026-11-09T12:00:00Z","preferredLanguage":"nb","reason":"auth_request","actor":null,"authTime":"2026-11-08T12:00:00Z","authMethodsReferences":["password","pwd"]}')::jsonb
  ELSE '{"userAgentID":"agent","userAgent":{"fingerprintID":"agent","remoteIP":"192.0.2.10","userAgent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15","header":{"accept-language":["nb-NO,nb;q=0.9"]}},"authMethods":["password"]}'::jsonb
  END AS payload) p`, prefix, users, events)
	if err != nil {
		t.Fatal(err)
	}
}

// measure runs the guard 30 times in its own transaction, as the push path does, and returns p50 and p95.
func measure(t *testing.T, db *sql.DB, cmd eventstore.Command) [2]time.Duration {
	t.Helper()
	ctx := context.Background()
	var runs []time.Duration
	for i := 0; i < 31; i++ {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		_ = sannP4Guard(ctx, tx, []eventstore.Command{cmd})
		if i > 0 { // the first run warms the cache
			runs = append(runs, time.Since(start))
		}
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i] < runs[j] })
	return [2]time.Duration{runs[len(runs)/2].Round(10 * time.Microsecond), runs[len(runs)*95/100].Round(10 * time.Microsecond)}
}
