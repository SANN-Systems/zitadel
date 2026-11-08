package eventstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/database"
	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/sannp4"
	"github.com/zitadel/zitadel/internal/zerrors"
)

type sannP4Policy = sannp4.Policy

type sannP4State struct {
	Human          bool
	State          string
	Email          string
	Phone          string
	PhoneVerified  bool
	Deleted        bool
	Journal        sannP4Journal
	Owner          string
	Revision       uint64
	OrderRevision  uint64
	PhoneRevision  uint64
	OpenInvitation bool
}

type sannP4Journal struct {
	Original   string       `json:"original"`
	SMS        string       `json:"sms"`
	Delete     bool         `json:"delete"`
	Invitation bool         `json:"invitation"`
	Order      *sannP4Order `json:"order"`
}

type sannP4Order struct {
	ID      string          `json:"id"`
	Method  string          `json:"method"`
	Request json.RawMessage `json:"request"`
	Field   string          `json:"field"`
	Old     string          `json:"old"`
	Expires int64           `json:"expires"`
}

func sannP4Denied() error {
	return zerrors.ThrowPermissionDenied(nil, "SANN-P4", "Errors.PermissionDenied")
}

// The hook is inside BOTH push transactions. Every user write takes the same lock, including
// deletion, metadata and creation. Lock ordering also covers multi-user domain-policy pushes.
func sannP4Guard(ctx context.Context, tx database.Tx, commands []eventstore.Command) error {
	p, configured, err := sannp4.LoadPolicy()
	if !configured {
		return nil
	}
	if err != nil {
		// Startup checks the policy. A policy broken later fails closed only for protected writes,
		// so logins and other writes in the instance keep working.
		for _, c := range commands {
			if c.Aggregate().Type != "user" {
				continue
			}
			if contact, journal, err := sannP4Classify(c); err != nil || contact || journal {
				return sannP4Denied()
			}
		}
		return nil
	}
	// An empty policy is only used during isolated bootstrap, before the person org exists.
	if p.Org == "" {
		return nil
	}
	groups := make(map[string][]eventstore.Command)
	for _, c := range commands {
		if c.Aggregate().Type == "user" {
			if c.Aggregate().InstanceID == "" {
				c.Aggregate().InstanceID = authz.GetInstance(ctx).InstanceID()
			}
			key := c.Aggregate().InstanceID + ":" + c.Aggregate().ID
			groups[key] = append(groups[key], c)
		}
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	actor := authz.GetCtxData(ctx).UserID
	for _, key := range keys {
		if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 741018))", key); err != nil {
			return sannP4Denied()
		}
		cmds := groups[key]
		a := cmds[0].Aggregate()
		human, owner, err := sannP4Owner(ctx, tx, a.InstanceID, a.ID)
		if err != nil {
			return sannP4Denied()
		}
		if !human || owner != p.Org {
			continue
		} // Existing humans only; never trust command owner for scoping.
		contact, phoneContact := false, false
		for _, c := range cmds {
			isContact, journal, err := sannP4Classify(c)
			if err != nil || journal && (actor == "" || actor != p.Journal) {
				return sannP4Denied()
			}
			contact = contact || isContact
			phoneContact = phoneContact || strings.HasPrefix(string(c.Type()), "user.human.phone.")
		}
		if !contact {
			continue
		}
		// Only contact writes need the replayed state.
		s, err := sannP4Read(ctx, tx, a.InstanceID, a.ID, p.Journal)
		if err != nil {
			return sannP4Denied()
		}
		r := sannp4.FromContext(ctx)
		if sannP4OrderMatches(p, s, actor, a.ID, r.Method, r.Body) {
			// A fixed namespace, no owner tags: ordinary user cleanup must never release a consumed order.
			_, err := tx.ExecContext(ctx, `INSERT INTO eventstore.unique_constraints (instance_id, unique_type, unique_field) VALUES ($1, 'sann_p4_order', $2)`, a.InstanceID, s.Journal.Order.ID)
			if err != nil {
				return sannP4Denied()
			}
			continue
		}
		if phoneContact && s.PhoneRevision > a.SannP4ReadSequence || !sannP4Allowed(p, s, actor, a.ID, r.Method, r.Body) {
			return sannP4Denied()
		}
	}
	return nil
}

// sannP4Classify reports whether a user command changes contact data, or writes the P4 journal
// namespace (sann.p4.* metadata or removing all metadata).
func sannP4Classify(c eventstore.Command) (contact, journal bool, err error) {
	data, err := eventstore.EventData(c)
	if err != nil {
		return false, false, err
	}
	var meta struct {
		Key string `json:"key"`
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &meta); err != nil {
			return false, false, err
		}
	}
	typ := string(c.Type())
	return sannP4Contact(typ), strings.HasPrefix(meta.Key, "sann.p4.") || typ == "user.metadata.removed.all", nil
}

func sannP4Contact(typ string) bool {
	switch typ {
	case "user.human.email.changed", "user.human.email.verified", "user.human.phone.changed", "user.human.phone.verified", "user.human.phone.removed", "user.username.changed", "user.domain.claimed":
		return true
	}
	return false
}

var sannP4HumanTypes = []string{"user.human.added", "user.human.selfregistered", "user.added", "user.selfregistered"}

// sannP4ReplayTypes are the exact event types reduce reacts to. Every phone event moves PhoneRevision.
// An explicit list (no LIKE or ranges) keeps the filter an index condition under any collation.
var sannP4ReplayTypes = append([]string{
	"user.human.phone.changed", "user.human.phone.removed", "user.human.phone.verified",
	"user.human.phone.verification.failed", "user.human.phone.code.added", "user.human.phone.code.sent",
	"user.phone.changed", "user.phone.removed", "user.phone.verified",
	"user.phone.verification.failed", "user.phone.code.added", "user.phone.code.sent",
	"user.human.initialization.code.added", "user.initialization.code.added",
	"user.human.initialization.check.succeeded", "user.initialization.check.succeeded",
	"user.human.email.changed", "user.email.changed", "user.human.email.verified", "user.email.verified",
	"user.username.changed", "user.domain.claimed",
	"user.deactivated", "user.locked", "user.reactivated", "user.unlocked", "user.removed",
	"user.metadata.set", "user.metadata.removed", "user.metadata.removed.all", "user.human.invite.code.added",
}, sannP4HumanTypes...)

func sannP4Relevant(typ string) bool {
	return slices.Contains(sannP4ReplayTypes, typ)
}

func sannP4SQLList(types []string) string {
	return "'" + strings.Join(types, "','") + "'"
}

// The lists are constants from this file; es_wm (aggregate_id, instance_id, aggregate_type, event_type) serves both.
var (
	sannP4OwnerQuery = `SELECT (SELECT owner FROM eventstore.events2 WHERE instance_id=$1 AND aggregate_type='user' AND aggregate_id=$2 ORDER BY sequence DESC LIMIT 1), ` +
		`EXISTS (SELECT 1 FROM eventstore.events2 WHERE instance_id=$1 AND aggregate_type='user' AND aggregate_id=$2 AND event_type IN (` + sannP4SQLList(sannP4HumanTypes) + `))`
	sannP4ReplayQuery = `SELECT sequence, owner, event_type, payload, creator FROM eventstore.events2 WHERE instance_id=$1 AND aggregate_type='user' AND aggregate_id=$2 ` +
		`AND event_type IN (` + sannP4SQLList(sannP4ReplayTypes) + `) ORDER BY sequence`
)

// sannP4Owner gives the same Human and Owner as a full replay: any human creation, and the latest owner.
func sannP4Owner(ctx context.Context, tx database.Tx, instance, uid string) (human bool, owner string, err error) {
	rows, err := tx.QueryContext(ctx, sannP4OwnerQuery, instance, uid)
	if err != nil {
		return false, "", err
	}
	defer rows.Close()
	if !rows.Next() {
		return false, "", errors.Join(sql.ErrNoRows, rows.Err())
	}
	var o sql.NullString
	if err := rows.Scan(&o, &human); err != nil {
		return false, "", err
	}
	return human, o.String, rows.Close()
}

func sannP4Read(ctx context.Context, tx database.Tx, instance, uid, journal string) (s sannP4State, err error) {
	rows, err := tx.QueryContext(ctx, sannP4ReplayQuery, instance, uid)
	if err != nil {
		return s, err
	}
	defer rows.Close()
	for rows.Next() {
		var seq uint64
		var owner, typ, creator string
		var raw []byte
		if err := rows.Scan(&seq, &owner, &typ, &raw, &creator); err != nil {
			return s, err
		}
		if err := s.reduce(seq, owner, typ, raw, creator, journal); err != nil {
			return s, err
		}
	}
	return s, rows.Err()
}

func (s *sannP4State) reduce(seq uint64, owner, typ string, raw []byte, creator, journal string) error {
	var data struct {
		Email string `json:"email"`
		Phone string `json:"phone"`
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &data); err != nil {
			return err
		}
	}
	s.Owner = owner
	// Normalize historical v1 events when replaying existing users.
	if strings.HasPrefix(typ, "user.email.") || strings.HasPrefix(typ, "user.phone.") {
		typ = strings.Replace(typ, "user.", "user.human.", 1)
	}
	if strings.HasPrefix(typ, "user.human.phone.") {
		s.PhoneRevision = seq
	}
	switch typ {
	case "user.human.added", "user.human.selfregistered", "user.added", "user.selfregistered":
		s.Human, s.State, s.Email, s.Phone = true, "active", data.Email, data.Phone
	case "user.human.initialization.code.added", "user.initialization.code.added":
		s.State = "initial"
	case "user.human.initialization.check.succeeded", "user.initialization.check.succeeded":
		s.State = "active"
	case "user.human.email.changed":
		s.Email = data.Email
	case "user.human.phone.changed":
		s.Phone, s.PhoneVerified = data.Phone, false
	case "user.human.phone.verified":
		s.PhoneVerified = true
	case "user.human.phone.removed":
		s.Phone, s.PhoneVerified = "", false
	case "user.deactivated":
		s.State = "inactive"
	case "user.locked":
		s.State = "locked"
	case "user.reactivated", "user.unlocked":
		s.State = "active"
	case "user.removed":
		s.State = "removed"
	case "user.metadata.set":
		if data.Key == "sann.sletting" {
			s.Deleted = true
			s.Revision = seq
		}
		if data.Key == "sann.p4.journal" && journal != "" && creator == journal {
			decoded, err := base64.StdEncoding.DecodeString(data.Value)
			if err != nil {
				return err
			}
			var next sannP4Journal
			if err := json.Unmarshal(decoded, &next); err != nil {
				return err
			}
			s.Journal = next
			s.OrderRevision = s.Revision
		}
	case "user.human.invite.code.added":
		s.OpenInvitation = true
	case "user.metadata.removed", "user.metadata.removed.all":
		if data.Key == "sann.sletting" || typ == "user.metadata.removed.all" {
			s.Deleted, s.Revision = false, seq
		}
		if creator == journal && journal != "" && (data.Key == "sann.p4.journal" || typ == "user.metadata.removed.all") {
			s.Journal, s.OrderRevision = sannP4Journal{}, 0
		}
	}
	if sannP4Contact(typ) || typ == "user.deactivated" || typ == "user.locked" || typ == "user.reactivated" || typ == "user.unlocked" || typ == "user.removed" {
		s.Revision = seq
	}
	return nil
}

func sannP4OrderMatches(p sannP4Policy, s sannP4State, actor, uid, method string, raw json.RawMessage) bool {
	b := s.Journal.Order
	if actor == "" || actor != p.Finalizer || s.State != "active" || s.Deleted || b == nil || b.ID == "" || b.Expires <= time.Now().Unix() || s.Revision != s.OrderRevision {
		return false
	}
	if method != "/zitadel.user.v2.UserService/UpdateUser" || b.Method != method {
		return false
	}
	var actual, expected map[string]any
	if json.Unmarshal(raw, &actual) != nil || json.Unmarshal(b.Request, &expected) != nil {
		return false
	}
	a, _ := json.Marshal(actual)
	e, _ := json.Marshal(expected)
	if string(a) != string(e) || actual["userId"] != uid {
		return false
	}
	for key := range actual {
		if key != "userId" && key != "human" && key != "username" {
			return false
		}
	}
	human, ok := actual["human"].(map[string]any)
	if !ok || len(human) != 1 {
		return false
	}
	contact, ok := human[b.Field].(map[string]any)
	if !ok || len(contact) != 2 || contact["isVerified"] != true {
		return false
	}
	value, ok := contact[b.Field].(string)
	if !ok || value == "" {
		return false
	}
	if username, exists := actual["username"]; exists && (b.Field != "email" || username != value) {
		return false
	}
	return b.Field == "email" && b.Old == s.Email || b.Field == "phone" && b.Old == s.Phone
}

func sannP4Allowed(p sannP4Policy, s sannP4State, actor, uid, method string, raw json.RawMessage) bool {
	if actor == "" {
		return false
	}
	var r struct {
		Phone      string          `json:"phone"`
		Verified   bool            `json:"isVerified"`
		Email      string          `json:"email"`
		ReturnCode json.RawMessage `json:"returnCode"`
	}
	if json.Unmarshal(raw, &r) != nil {
		return false
	}
	v2 := strings.HasPrefix(method, "/zitadel.user.v2.UserService/")
	op := method[strings.LastIndex(method, "/")+1:]
	if actor == p.Deletion && v2 && s.Deleted && s.Journal.Delete && (s.State == "inactive" || s.State == "locked") {
		return op == "RemovePhone" || op == "SetEmail" && r.Verified && strings.HasSuffix(r.Email, "@slettet.invalid")
	}
	if s.Deleted {
		return false
	}
	if actor == p.Live && v2 && s.State == "inactive" && s.Journal.Original != "" && !s.Journal.Invitation && !s.OpenInvitation {
		original := s.Journal.Original
		migration := fmt.Sprintf("%x@migrering.invalid", sha256.Sum256([]byte(original)))
		if op == "SetEmail" {
			return r.ReturnCode != nil && !r.Verified && (s.Email == original || s.Email == migration) && (r.Email == original || r.Email == migration)
		}
		if op == "VerifyEmail" {
			return s.Email == original
		}
	}
	if !s.PhoneVerified && (actor == p.Kart || actor == p.Live) && v2 {
		if op == "SetPhone" {
			if r.Verified {
				return actor == p.Live && s.State == "inactive" && r.Phone == s.Journal.SMS && r.Phone != ""
			}
			return true
		}
		return op == "VerifyPhone"
	}
	if !s.PhoneVerified && actor == uid {
		return method == "/zitadel.auth.v1.AuthService/SetMyPhone" || method == "/zitadel.auth.v1.AuthService/VerifyMyPhone" ||
			method == "/zitadel.user.v2.UserService/VerifyPhone" || method == "/sann.login.v1/FirstPhone"
	}
	return false
}
