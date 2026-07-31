package issuedelivery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const operationSchema = "packy.active-operation/v1"

type OperationState string
type OperationKind string
type OperationPhase string

const (
	OperationActive                 OperationState = "active"
	OperationCompleted              OperationState = "completed"
	OperationFailed                 OperationState = "failed"
	OperationCancelled              OperationState = "cancelled"
	OperationKindAdvance            OperationKind  = "advance"
	OperationPhaseAdvance           OperationPhase = "advance"
	OperationPhaseValidationSession OperationPhase = "validation-session"
)

type Operation struct {
	Schema              string         `json:"schema"`
	ID                  string         `json:"id"`
	Kind                OperationKind  `json:"kind"`
	Phase               OperationPhase `json:"phase"`
	State               OperationState `json:"state"`
	StartedAt           string         `json:"started_at"`
	ValidationSessionID string         `json:"validation_session_id,omitempty"`
}

func newAdvanceOperation(started time.Time) (Operation, error) {
	var identity [16]byte
	if _, err := rand.Read(identity[:]); err != nil {
		return Operation{}, fmt.Errorf("create Advance operation identity: %w", err)
	}
	return Operation{
		Schema: operationSchema, ID: hex.EncodeToString(identity[:]), Kind: OperationKindAdvance,
		Phase: OperationPhaseAdvance, State: OperationActive,
		StartedAt: started.UTC().Format(time.RFC3339Nano),
	}, nil
}

type operationContextKey struct{}

type operationTracker struct {
	store     lockedIssueStore
	operation *Operation
}

func contextWithOperation(ctx context.Context, store lockedIssueStore, operation *Operation) context.Context {
	return context.WithValue(ctx, operationContextKey{}, &operationTracker{store: store, operation: operation})
}

func advanceOperationProgress(ctx context.Context, phase OperationPhase, validationSessionID string) error {
	tracker, _ := ctx.Value(operationContextKey{}).(*operationTracker)
	if tracker == nil {
		return nil
	}
	if operationPhaseRank(phase) < operationPhaseRank(tracker.operation.Phase) {
		return errors.New("Advance operation progress cannot move backwards")
	}
	tracker.operation.Phase = phase
	if validationSessionID != "" {
		tracker.operation.ValidationSessionID = validationSessionID
	}
	return tracker.store.storeOperation(*tracker.operation)
}

func operationPhaseRank(phase OperationPhase) int {
	switch phase {
	case OperationPhaseAdvance:
		return 1
	case OperationPhaseValidationSession:
		return 2
	default:
		return 0
	}
}
