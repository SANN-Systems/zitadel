package eventstore

import (
	"context"
	"encoding/json"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/repository/user"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSannP4OrderRejectsStaleStateAndExtraWrites(t *testing.T) {
	r := json.RawMessage(`{"userId":"person","human":{"phone":{"phone":"+12025550101","isVerified":true}}}`)
	p := sannP4Policy{Finalizer: "finalizer"}
	s := sannP4State{State: "active", Phone: "+12025550100", Revision: 7, OrderRevision: 7, Journal: sannP4Journal{Order: &sannP4Order{
		ID: "order", Method: "/zitadel.user.v2.UserService/UpdateUser", Request: r, Field: "phone", Old: "+12025550100", Expires: time.Now().Add(time.Minute).Unix(),
	}}}
	if !sannP4OrderMatches(p, s, "finalizer", "person", s.Journal.Order.Method, r) {
		t.Fatal("fresh order must match")
	}
	s.Revision++
	if sannP4OrderMatches(p, s, "finalizer", "person", s.Journal.Order.Method, r) {
		t.Fatal("stale order must not match")
	}
	s.Revision--
	s.Journal.Order.Request = json.RawMessage(`{"userId":"person","human":{"password":{"password":"synthetic"}}}`)
	if sannP4OrderMatches(p, s, "finalizer", "person", s.Journal.Order.Method, s.Journal.Order.Request) {
		t.Fatal("an order cannot authorize password writes")
	}
}

func TestSannP4GuardReadsCurrentStateUnderLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"org":"sann","journal":"journal","finalizer":"finalizer","kart":"kart","live":"live","deletion":"deletion"}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SANN_P4_POLICY", path)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	tx, _ := db.Begin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs("instance:person").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT \(SELECT owner`).WithArgs("instance", "person").WillReturnRows(
		sqlmock.NewRows([]string{"owner", "human"}).AddRow("sann", true))
	mock.ExpectQuery("SELECT sequence.*event_type IN").WithArgs("instance", "person").WillReturnRows(
		sqlmock.NewRows([]string{"sequence", "owner", "event_type", "payload", "creator"}).
			AddRow(1, "sann", "user.human.added", []byte(`{"email":"old@example.invalid"}`), "admin"))
	a := &eventstore.Aggregate{ID: "person", Type: "user", InstanceID: "instance", ResourceOwner: "sann"}
	err = sannP4Guard(context.Background(), tx, []eventstore.Command{user.NewHumanEmailChangedEvent(context.Background(), a, "new@example.invalid")})
	if err == nil {
		t.Fatal("direct contact change must fail after reading current state")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSannP4PhoneRevisionIncludesCodeRotation(t *testing.T) {
	s := sannP4State{}
	if err := s.reduce(22, "sann", "user.human.phone.code.added", []byte(`{}`), "person", "journal"); err != nil {
		t.Fatal(err)
	}
	if s.PhoneRevision != 22 {
		t.Fatal("a stale verification must not survive code rotation")
	}
}

func TestSannP4JournalCannotHideOpenInvitation(t *testing.T) {
	s := sannP4State{}
	if err := s.reduce(1, "sann", "user.human.invite.code.added", []byte(`{}`), "admin", "journal"); err != nil {
		t.Fatal(err)
	}
	if err := s.reduce(2, "sann", "user.metadata.set", []byte(`{"key":"sann.p4.journal","value":"e30="}`), "journal", "journal"); err != nil {
		t.Fatal(err)
	}
	if !s.OpenInvitation {
		t.Fatal("current invitation state must survive journal replacement")
	}
}

func TestSannP4ReplacingJournalRevokesOldEvidence(t *testing.T) {
	s := sannP4State{Journal: sannP4Journal{SMS: "+12025550101", Original: "old@example.invalid"}}
	if err := s.reduce(2, "sann", "user.metadata.set", []byte(`{"key":"sann.p4.journal","value":"e30="}`), "journal", "journal"); err != nil {
		t.Fatal(err)
	}
	if s.Journal.SMS != "" || s.Journal.Original != "" {
		t.Fatal("replacement must revoke omitted evidence")
	}
}

func TestSannP4RemovingJournalRevokesEvidence(t *testing.T) {
	s := sannP4State{Journal: sannP4Journal{SMS: "+12025550101"}}
	if err := s.reduce(2, "sann", "user.metadata.removed", []byte(`{"key":"sann.p4.journal"}`), "journal", "journal"); err != nil {
		t.Fatal(err)
	}
	if s.Journal.SMS != "" {
		t.Fatal("removing journal must revoke evidence")
	}
}

func TestSannP4DeletionMarkerTracksCurrentMetadata(t *testing.T) {
	s := sannP4State{Deleted: true, Revision: 3}
	if err := s.reduce(4, "sann", "user.metadata.removed", []byte(`{"key":"sann.sletting"}`), "admin", "journal"); err != nil {
		t.Fatal(err)
	}
	if s.Deleted || s.Revision != 4 {
		t.Fatal("marker removal must update current state and invalidate older orders")
	}
}

func TestSannP4DirectEmailDenied(t *testing.T) {
	s := sannP4State{Human: true, State: "active", Email: "old@example.invalid"}
	r := json.RawMessage(`{"userId":"person","email":"new@example.invalid","isVerified":true}`)
	if sannP4Allowed(sannP4Policy{}, s, "person", "person", "/zitadel.user.v2.UserService/SetEmail", r) {
		t.Fatal("direct email change must be denied")
	}
}

func TestSannP4ImportBinding(t *testing.T) {
	p := sannP4Policy{Live: "live"}
	s := sannP4State{State: "inactive", Email: "a@example.invalid", Journal: sannP4Journal{Original: "a@example.invalid"}}
	r := json.RawMessage(`{"userId":"person","email":"a@example.invalid","returnCode":{}}`)
	m := "/zitadel.user.v2.UserService/SetEmail"
	if !sannP4Allowed(p, s, "live", "person", m, r) {
		t.Fatal("journaled import must be allowed")
	}
	s.Journal.Invitation = true
	if sannP4Allowed(p, s, "live", "person", m, r) {
		t.Fatal("open invitation must block import")
	}
	s.Journal.Invitation = false
	s.State = "active"
	if sannP4Allowed(p, s, "live", "person", m, r) {
		t.Fatal("active account must block import")
	}
}

func TestSannP4DeletionBoundToJournalStateAndActor(t *testing.T) {
	p := sannP4Policy{Deletion: "deletion"}
	s := sannP4State{Human: true, State: "inactive", Deleted: true, Journal: sannP4Journal{Delete: true}}
	r := json.RawMessage(`{"userId":"person","email":"gone@slettet.invalid","isVerified":true}`)
	m := "/zitadel.user.v2.UserService/SetEmail"
	if !sannP4Allowed(p, s, "deletion", "person", m, r) {
		t.Fatal("journaled deletion must be allowed")
	}
	s.State = "active"
	if sannP4Allowed(p, s, "deletion", "person", m, r) {
		t.Fatal("active deletion must be denied")
	}
	s.State = "inactive"
	if sannP4Allowed(p, s, "kart", "person", m, r) {
		t.Fatal("wrong actor must be denied")
	}
}

func TestSannP4FirstPhone(t *testing.T) {
	p := sannP4Policy{Kart: "kart", Live: "live"}
	s := sannP4State{Human: true, State: "active"}
	r := json.RawMessage(`{"userId":"person","phone":"+12025550101","returnCode":{}}`)
	method := "/zitadel.user.v2.UserService/SetPhone"
	if !sannP4Allowed(p, s, "kart", "person", method, r) {
		t.Fatal("first phone must be allowed")
	}
	s.PhoneVerified = true
	if sannP4Allowed(p, s, "kart", "person", method, r) {
		t.Fatal("verified phone must be protected")
	}
}

func sannP4PolicyFile(t *testing.T, content string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	if content != "" {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("SANN_P4_POLICY", path)
}

// A broken policy must not stop logins and other writes in the whole instance. It must still
// stop the protected contact and journal writes, without touching the database.
func TestSannP4InvalidPolicyOnlyDeniesProtectedWrites(t *testing.T) {
	a := &eventstore.Aggregate{ID: "person", Type: "user", InstanceID: "instance", ResourceOwner: "sann"}
	ctx := context.Background()
	for name, policy := range map[string]string{"missing": "", "invalid": `{"org":`, "incomplete": `{"org":"sann","journal":"journal"}`} {
		t.Run(name, func(t *testing.T) {
			sannP4PolicyFile(t, policy)
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectBegin()
			tx, _ := db.Begin()
			if err := sannP4Guard(ctx, tx, []eventstore.Command{user.NewHumanPasswordCheckSucceededEvent(ctx, a, nil)}); err != nil {
				t.Fatalf("login write must pass: %v", err)
			}
			for _, c := range []eventstore.Command{
				user.NewHumanEmailChangedEvent(ctx, a, "new@example.invalid"),
				user.NewMetadataSetEvent(ctx, a, "sann.p4.journal", []byte("e30=")),
				user.NewMetadataRemovedAllEvent(ctx, a),
			} {
				if err := sannP4Guard(ctx, tx, []eventstore.Command{c}); err == nil {
					t.Fatalf("%s must be denied", c.Type())
				}
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Logins and other non-contact writes in the P4 org must not replay the whole history under the lock.
func TestSannP4NonContactWriteSkipsReplay(t *testing.T) {
	sannP4PolicyFile(t, `{"org":"sann","journal":"journal","finalizer":"finalizer","kart":"kart","live":"live","deletion":"deletion"}`)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	tx, _ := db.Begin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs("instance:person").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT \(SELECT owner`).WithArgs("instance", "person").WillReturnRows(
		sqlmock.NewRows([]string{"owner", "human"}).AddRow("sann", true))
	a := &eventstore.Aggregate{ID: "person", Type: "user", InstanceID: "instance", ResourceOwner: "sann"}
	ctx := context.Background()
	if err := sannP4Guard(ctx, tx, []eventstore.Command{user.NewHumanPasswordCheckSucceededEvent(ctx, a, nil)}); err != nil {
		t.Fatalf("login write must pass without replay: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// The contact replay only reads event types the reducer uses. Every other upstream user event type
// must leave the replayed state unchanged, so the filter cannot hide state.
func TestSannP4ReplayFilterCoversReducer(t *testing.T) {
	payload := []byte(`{"email":"x@example.invalid","phone":"+12025550199","key":"sann.p4.journal","value":"e30="}`)
	for _, typ := range append(sannP4UpstreamUserTypes, "user.email.changed", "user.email.verified", "user.phone.changed", "user.phone.code.added") {
		if sannP4Relevant(typ) {
			continue
		}
		before := sannP4State{Human: true, State: "active", Email: "a@example.invalid", Phone: "+12025550100", Owner: "sann", Revision: 3, PhoneRevision: 2}
		after := before
		if err := after.reduce(99, "sann", typ, payload, "journal", "journal"); err != nil {
			continue // an undecodable irrelevant payload would only fail the old full replay
		}
		if after != before {
			t.Errorf("%s changes replay state but is filtered out", typ)
		}
	}
}

// The generated type list must follow upstream, so a new user event type cannot slip past the filter test.
// On a Zitadel upgrade this fails until sann_p4_typer_test.go is regenerated (see the patch's drift routine).
func TestSannP4UpstreamTypeListIsCurrent(t *testing.T) {
	fset := token.NewFileSet()
	want := map[string]bool{}
	files, _ := filepath.Glob("../../repository/user/*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range file.Decls {
			if g, ok := d.(*ast.GenDecl); ok && g.Tok == token.CONST {
				for _, spec := range g.Specs {
					for _, n := range spec.(*ast.ValueSpec).Names {
						if n.IsExported() && strings.HasSuffix(n.Name, "Type") && n.Name != "AggregateType" {
							want[n.Name] = true
						}
					}
				}
			}
		}
	}
	file, err := parser.ParseFile(fset, "sann_p4_typer_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			got[sel.Sel.Name] = true
		}
		return true
	})
	if len(want) == 0 || !maps.Equal(want, got) {
		t.Fatalf("sann_p4_typer_test.go is stale: upstream has %d types, list has %d", len(want), len(got))
	}
}
