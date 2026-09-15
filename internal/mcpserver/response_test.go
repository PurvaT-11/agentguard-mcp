package mcpserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PurvaT-11/agentguard-mcp/internal/access"
	"github.com/PurvaT-11/agentguard-mcp/internal/storage"
)

func TestRequestResourceAccessDeniedOutputOmitsResource(t *testing.T) {
	server := Server{access: testAccessService(t, "support-agent-001")}
	_, output, err := server.requestResourceAccess(context.Background(), &mcp.CallToolRequest{}, RequestResourceAccessInput{
		ResourceID:      "invoice-2001",
		Purpose:         "payment_operations",
		RequestedScopes: []string{"invoice.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if output.Allowed {
		t.Fatal("output was allowed, want denied")
	}
	if output.Resource != nil {
		t.Fatalf("denied output resource = %#v, want nil", output.Resource)
	}
	assertMCPResourceKey(t, output, false)
}

func TestRequestResourceAccessAllowedOutputIncludesResource(t *testing.T) {
	server := Server{access: testAccessService(t, "support-agent-001")}
	_, output, err := server.requestResourceAccess(context.Background(), &mcp.CallToolRequest{}, RequestResourceAccessInput{
		ResourceID:      "ticket-1001",
		Purpose:         "customer_support",
		RequestedScopes: []string{"ticket.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !output.Allowed {
		t.Fatalf("output denied: %s", output.Reason)
	}
	if output.Resource == nil {
		t.Fatal("allowed output resource = nil, want projected view")
	}
	assertMCPResourceKey(t, output, true)
}

func testAccessService(t *testing.T, agentID string) access.Service {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.September, 15, 12, 0, 0, 0, time.UTC)
	agents := storage.NewMemoryAgentRepository()
	resources := storage.NewMemoryResourceRepository()
	audits := storage.NewMemoryAuditRepository()
	if err := agents.Save(ctx, access.AgentProfile{
		ID: "support-agent-001",
		PolicyRule: access.PolicyRule{
			ResourceType: access.ResourceTypeSupportTicket,
			Purpose:      "customer_support",
			Scope:        "ticket.read",
		},
	}); err != nil {
		t.Fatal(err)
	}
	for _, resource := range []access.Resource{
		{
			ID:   "ticket-1001",
			Type: access.ResourceTypeSupportTicket,
			SupportTicket: &access.SupportTicket{
				ID:              "ticket-1001",
				Subject:         "Workspace export question",
				Status:          "open",
				Priority:        "normal",
				Category:        "account",
				PublicSummary:   "A demo customer asked how to export workspace data.",
				RequesterHandle: "demo-customer-17",
				UpdatedAt:       now,
			},
		},
		{
			ID:   "invoice-2001",
			Type: access.ResourceTypeInvoice,
			Invoice: &access.Invoice{
				ID:            "invoice-2001",
				AccountCode:   "acct-demo-42",
				Status:        "pending",
				AmountCents:   129900,
				Currency:      "USD",
				DueDate:       "2026-10-15",
				LineItemCount: 3,
				UpdatedAt:     now,
			},
		},
	} {
		if err := resources.Save(ctx, resource); err != nil {
			t.Fatal(err)
		}
	}
	return access.NewService(agentID, agents, resources, audits, func() time.Time { return now }, func() (string, error) { return "audit-test", nil })
}

func assertMCPResourceKey(t *testing.T, output RequestResourceAccessOutput, want bool) {
	t.Helper()
	encoded, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &body); err != nil {
		t.Fatal(err)
	}
	_, ok := body["resource"]
	if ok != want {
		t.Fatalf("resource key present = %v, want %v; json=%s", ok, want, encoded)
	}
}
