package mcpserver

import (
	"context"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PurvaT-11/agentguard-mcp/internal/access"
	"github.com/PurvaT-11/agentguard-mcp/internal/audit"
	"github.com/PurvaT-11/agentguard-mcp/internal/storage"
)

func TestNormalizeAuditLimit(t *testing.T) {
	tests := []struct {
		name    string
		limit   int
		want    int
		wantErr bool
	}{
		{name: "default", limit: 0, want: 20},
		{name: "one", limit: 1, want: 1},
		{name: "negative", limit: -1, wantErr: true},
		{name: "too large", limit: 101, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeAuditLimit(tt.limit)
			if tt.wantErr {
				if err == nil {
					t.Fatal("normalizeAuditLimit() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeAuditLimit() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("limit = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestListMyAuditEventsReturnsMostRecentEvents(t *testing.T) {
	ctx := context.Background()
	agents := storage.NewMemoryAgentRepository()
	resources := storage.NewMemoryResourceRepository()
	audits := storage.NewMemoryAuditRepository()
	for _, event := range []audit.Event{
		{ID: "audit-1", AgentID: "support-agent-001", Decision: access.DecisionDeny},
		{ID: "audit-2", AgentID: "support-agent-001", Decision: access.DecisionDeny},
		{ID: "audit-3", AgentID: "support-agent-001", Decision: access.DecisionAllow},
	} {
		if err := audits.Append(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	service := access.NewService("support-agent-001", agents, resources, audits, time.Now, func() (string, error) { return "unused", nil })
	server := Server{access: service}

	_, output, err := server.listMyAuditEvents(ctx, &mcp.CallToolRequest{}, ListMyAuditEventsInput{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(output.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(output.Events))
	}
	if output.Events[0].ID != "audit-3" {
		t.Fatalf("event ID = %q, want audit-3", output.Events[0].ID)
	}
}

func TestListMyAuditEventsRejectsInvalidLimits(t *testing.T) {
	server := Server{}
	for _, limit := range []int{-1, 101} {
		_, _, err := server.listMyAuditEvents(context.Background(), &mcp.CallToolRequest{}, ListMyAuditEventsInput{Limit: limit})
		if err == nil {
			t.Fatalf("limit %d error = nil, want validation error", limit)
		}
	}
}
