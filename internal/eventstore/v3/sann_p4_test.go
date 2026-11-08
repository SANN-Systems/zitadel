package eventstore

import (
	"context"
	"encoding/json"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/repository/user"
	"os"
	"path/filepath"
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
	if err := os.WriteFile(path, []byte(`{"org":"sann","journal":"journal"}`), 0600); err != nil {
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
	mock.ExpectQuery("SELECT.*event_type").WithArgs("instance", "person").WillReturnRows(
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
