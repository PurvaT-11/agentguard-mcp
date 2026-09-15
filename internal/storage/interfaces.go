package storage

import (
	"context"

	"github.com/PurvaT-11/agentguard-mcp/internal/access"
	"github.com/PurvaT-11/agentguard-mcp/internal/audit"
)

type AgentRepository interface {
	Save(ctx context.Context, profile access.AgentProfile) error
	AgentProfile(ctx context.Context, agentID string) (access.AgentProfile, bool, error)
}

type ResourceRepository interface {
	Save(ctx context.Context, resource access.Resource) error
	Get(ctx context.Context, resourceID string) (access.Resource, bool, error)
}

type AuditRepository interface {
	Append(ctx context.Context, event audit.Event) error
	Get(ctx context.Context, eventID string) (audit.Event, bool, error)
	List(ctx context.Context) ([]audit.Event, error)
	ListByAgent(ctx context.Context, agentID string) ([]audit.Event, error)
}
