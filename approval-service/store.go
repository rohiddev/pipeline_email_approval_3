// store.go — all database operations using MongoDB.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Approval represents one access request and its current state.
type Approval struct {
	Token               string
	Status              string // pending | approved | rejected | expired
	Requester           string
	RequesterEmail      string
	ManagerEmail        string
	ADGroup             string
	Reason              string
	PipelineExecutionID string
	CreatedAt           time.Time
	ExpiresAt           time.Time
	DecidedAt           *time.Time
	DecidedBy           *string
	DecidedFromIP       *string
}

// EmailReference is what goes in the email URL — never the real token.
type EmailReference struct {
	Reference string
	Token     string
	ExpiresAt time.Time
}

// SSOState links an SSO state param back to an email reference.
type SSOState struct {
	State     string
	Reference string
}

type store struct {
	client     *mongo.Client
	approvals  *mongo.Collection
	references *mongo.Collection
	ssoStates  *mongo.Collection
	csrfTokens *mongo.Collection
	auditLog   *mongo.Collection
}

func newStore(uri, dbName string) (*store, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, fmt.Errorf("connect to MongoDB: %w", err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("ping MongoDB: %w", err)
	}

	db := client.Database(dbName)
	s := &store{
		client:     client,
		approvals:  db.Collection("approvals"),
		references: db.Collection("email_references"),
		ssoStates:  db.Collection("sso_states"),
		csrfTokens: db.Collection("csrf_tokens"),
		auditLog:   db.Collection("audit_log"),
	}
	return s, s.ensureIndexes()
}

func (s *store) close() {
	s.client.Disconnect(context.Background())
}

// ensureIndexes creates TTL indexes so MongoDB auto-deletes expired documents.
// Short-lived records (references, SSO states, CSRF tokens) clean themselves up.
func (s *store) ensureIndexes() error {
	ctx := context.Background()

	// Email references expire on their expires_at field
	s.references.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "expires_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(0),
	})

	// SSO states auto-delete after 1 hour regardless of created_at value
	s.ssoStates.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "created_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(3600),
	})

	// CSRF tokens expire on their expires_at field
	s.csrfTokens.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "expires_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(0),
	})

	return nil
}

// ─────────────────────────────────────────────────────────────
// Approval operations
// ─────────────────────────────────────────────────────────────

func (s *store) Create(
	requester, requesterEmail, managerEmail, adGroup, reason, pipelineID string,
	ttlHours int,
) (*Approval, error) {
	token := newUUID()
	now := time.Now().UTC()
	expires := now.Add(time.Duration(ttlHours) * time.Hour)

	_, err := s.approvals.InsertOne(context.Background(), bson.M{
		"_id":                   token,
		"status":                "pending",
		"requester":             requester,
		"requester_email":       requesterEmail,
		"manager_email":         managerEmail,
		"ad_group":              adGroup,
		"reason":                reason,
		"pipeline_execution_id": pipelineID,
		"created_at":            now,
		"expires_at":            expires,
	})
	if err != nil {
		return nil, fmt.Errorf("insert approval: %w", err)
	}
	return &Approval{
		Token: token, Status: "pending",
		Requester: requester, RequesterEmail: requesterEmail,
		ManagerEmail: managerEmail, ADGroup: adGroup,
		Reason: reason, PipelineExecutionID: pipelineID,
		CreatedAt: now, ExpiresAt: expires,
	}, nil
}

func (s *store) Get(token string) (*Approval, error) {
	var doc bson.M
	err := s.approvals.FindOne(context.Background(), bson.M{"_id": token}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("not found")
	}
	if err != nil {
		return nil, err
	}

	a := &Approval{
		Token:               token,
		Status:              str(doc, "status"),
		Requester:           str(doc, "requester"),
		RequesterEmail:      str(doc, "requester_email"),
		ManagerEmail:        str(doc, "manager_email"),
		ADGroup:             str(doc, "ad_group"),
		Reason:              str(doc, "reason"),
		PipelineExecutionID: str(doc, "pipeline_execution_id"),
		CreatedAt:           timeVal(doc, "created_at"),
		ExpiresAt:           timeVal(doc, "expires_at"),
		DecidedAt:           timePtr(doc, "decided_at"),
		DecidedBy:           strPtr(doc, "decided_by"),
		DecidedFromIP:       strPtr(doc, "decided_from_ip"),
	}

	// Lazily mark expired
	if a.Status == "pending" && time.Now().UTC().After(a.ExpiresAt) {
		a.Status = "expired"
		s.approvals.UpdateOne(context.Background(),
			bson.M{"_id": token},
			bson.M{"$set": bson.M{"status": "expired"}},
		)
	}
	return a, nil
}

// Decide records the decision atomically.
// The filter on status="pending" means a second click does nothing.
func (s *store) Decide(token, decision, decidedBy, ip string) error {
	res, err := s.approvals.UpdateOne(
		context.Background(),
		bson.M{"_id": token, "status": "pending"},
		bson.M{"$set": bson.M{
			"status":          decision,
			"decided_at":      time.Now().UTC(),
			"decided_by":      decidedBy,
			"decided_from_ip": ip,
		}},
	)
	if err != nil {
		return err
	}
	if res.MatchedCount == 0 {
		return fmt.Errorf("already decided or not found")
	}
	return nil
}

// ─────────────────────────────────────────────────────────────
// Email reference operations
// Fix 1: real token never appears in a URL
// ─────────────────────────────────────────────────────────────

func (s *store) CreateReference(token string, ttlHours int) (*EmailReference, error) {
	ref := newUUID()
	expires := time.Now().UTC().Add(time.Duration(ttlHours) * time.Hour)
	_, err := s.references.InsertOne(context.Background(), bson.M{
		"_id":       ref,
		"token":     token,
		"expires_at": expires,
		"used":      false,
	})
	if err != nil {
		return nil, err
	}
	return &EmailReference{Reference: ref, Token: token, ExpiresAt: expires}, nil
}

// PeekReference checks validity without consuming the reference.
func (s *store) PeekReference(reference string) (*EmailReference, error) {
	var doc bson.M
	err := s.references.FindOne(context.Background(), bson.M{
		"_id":        reference,
		"used":       false,
		"expires_at": bson.M{"$gt": time.Now().UTC()},
	}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("not found, already used, or expired")
	}
	if err != nil {
		return nil, err
	}
	return &EmailReference{
		Reference: reference,
		Token:     str(doc, "token"),
		ExpiresAt: timeVal(doc, "expires_at"),
	}, nil
}

// UseReference atomically retrieves and marks the reference used (single use).
func (s *store) UseReference(reference string) (*EmailReference, error) {
	var doc bson.M
	err := s.references.FindOneAndUpdate(
		context.Background(),
		bson.M{
			"_id":        reference,
			"used":       false,
			"expires_at": bson.M{"$gt": time.Now().UTC()},
		},
		bson.M{"$set": bson.M{"used": true}},
		options.FindOneAndUpdate().SetReturnDocument(options.Before),
	).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("reference not found, already used, or expired")
	}
	if err != nil {
		return nil, err
	}
	return &EmailReference{
		Reference: reference,
		Token:     str(doc, "token"),
		ExpiresAt: timeVal(doc, "expires_at"),
	}, nil
}

// ─────────────────────────────────────────────────────────────
// SSO state operations
// ─────────────────────────────────────────────────────────────

func (s *store) SaveState(state, reference string) error {
	_, err := s.ssoStates.InsertOne(context.Background(), bson.M{
		"_id":        state,
		"reference":  reference,
		"created_at": time.Now().UTC(),
	})
	return err
}

func (s *store) PopState(state string) (*SSOState, error) {
	var doc bson.M
	err := s.ssoStates.FindOneAndDelete(
		context.Background(),
		bson.M{"_id": state},
	).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, fmt.Errorf("state not found or expired")
	}
	if err != nil {
		return nil, err
	}
	return &SSOState{State: state, Reference: str(doc, "reference")}, nil
}

// ─────────────────────────────────────────────────────────────
// CSRF operations
// ─────────────────────────────────────────────────────────────

func (s *store) CreateCSRF(approvalToken, managerEmail string) string {
	csrf := newUUID()
	key := approvalToken + ":" + csrf
	s.csrfTokens.InsertOne(context.Background(), bson.M{
		"_id":        key,
		"manager":    managerEmail,
		"expires_at": time.Now().UTC().Add(30 * time.Minute),
		"used":       false,
	})
	return csrf
}

func (s *store) ValidateCSRF(approvalToken, csrf string) (string, error) {
	key := approvalToken + ":" + csrf
	var doc bson.M
	err := s.csrfTokens.FindOneAndUpdate(
		context.Background(),
		bson.M{
			"_id":        key,
			"used":       false,
			"expires_at": bson.M{"$gt": time.Now().UTC()},
		},
		bson.M{"$set": bson.M{"used": true}},
	).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return "", fmt.Errorf("invalid or expired csrf")
	}
	if err != nil {
		return "", err
	}
	return str(doc, "manager"), nil
}

// ─────────────────────────────────────────────────────────────
// Audit log — hash-chained, append-only
// Fix 3: tamper-evident audit trail
// ─────────────────────────────────────────────────────────────

func (s *store) WriteAudit(event string, fields map[string]string) error {
	data, _ := json.Marshal(fields)
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	prevHash := s.lastAuditHash()

	content := event + string(data) + timestamp + prevHash
	hash := sha256hex(content)

	_, err := s.auditLog.InsertOne(context.Background(), bson.M{
		"event":         event,
		"data":          string(data),
		"timestamp":     timestamp,
		"previous_hash": prevHash,
		"hash":          hash,
	})
	return err
}

// VerifyChain walks every audit record in insertion order and checks every hash.
// Returns records verified, or an error identifying the first broken link.
func (s *store) VerifyChain() (int, error) {
	cursor, err := s.auditLog.Find(
		context.Background(),
		bson.M{},
		options.Find().SetSort(bson.D{{Key: "_id", Value: 1}}),
	)
	if err != nil {
		return 0, err
	}
	defer cursor.Close(context.Background())

	prevHash := ""
	count := 0

	for cursor.Next(context.Background()) {
		var doc bson.M
		if err := cursor.Decode(&doc); err != nil {
			return count, err
		}

		storedPrevHash := str(doc, "previous_hash")
		storedHash := str(doc, "hash")
		event := str(doc, "event")
		data := str(doc, "data")
		timestamp := str(doc, "timestamp")

		if storedPrevHash != prevHash {
			return count, fmt.Errorf("chain broken at record %v: previous_hash mismatch", doc["_id"])
		}

		expected := sha256hex(event + data + timestamp + storedPrevHash)
		if storedHash != expected {
			return count, fmt.Errorf("hash mismatch at record %v: record was tampered with", doc["_id"])
		}

		prevHash = storedHash
		count++
	}
	return count, cursor.Err()
}

func (s *store) lastAuditHash() string {
	var doc bson.M
	s.auditLog.FindOne(
		context.Background(),
		bson.M{},
		options.FindOne().SetSort(bson.D{{Key: "_id", Value: -1}}),
	).Decode(&doc)
	if doc == nil {
		return ""
	}
	return str(doc, "hash")
}

// ─────────────────────────────────────────────────────────────
// bson helpers — keep handler code clean
// ─────────────────────────────────────────────────────────────

func str(doc bson.M, key string) string {
	if v, ok := doc[key].(string); ok {
		return v
	}
	return ""
}

func strPtr(doc bson.M, key string) *string {
	if v, ok := doc[key].(string); ok && v != "" {
		return &v
	}
	return nil
}

func timeVal(doc bson.M, key string) time.Time {
	if v, ok := doc[key].(time.Time); ok {
		return v
	}
	return time.Time{}
}

func timePtr(doc bson.M, key string) *time.Time {
	if v, ok := doc[key].(time.Time); ok {
		return &v
	}
	return nil
}

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
