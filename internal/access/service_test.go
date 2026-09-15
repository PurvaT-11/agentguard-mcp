package access_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PurvaT-11/agentguard-mcp/internal/access"
	"github.com/PurvaT-11/agentguard-mcp/internal/audit"
	"github.com/PurvaT-11/agentguard-mcp/internal/storage"
)

const (
	sensitiveTicketNote  = "synthetic internal ticket note"
	sensitiveFinanceMemo = "synthetic internal finance memo"
	sensitiveCompBand    = "synthetic compensation band"
	sensitiveHRNote      = "synthetic HR note"
)

func TestServiceRequestResourceAccess(t *testing.T) {
	tests := []struct {
		name             string
		agentID          string
		req              access.Request
		wantAllowed      bool
		wantDecision     string
		wantTicket       bool
		wantInvoice      bool
		wantEmployee     bool
		wantReason       string
		wantAuditCount   int
		wantNoSecretData bool
	}{
		{
			name:    "support agent may read support tickets",
			agentID: "support-agent-001",
			req: access.Request{
				ResourceID:      "ticket-1001",
				Purpose:         "customer_support",
				RequestedScopes: []string{"ticket.read"},
			},
			wantAllowed:      true,
			wantDecision:     access.DecisionAllow,
			wantTicket:       true,
			wantAuditCount:   1,
			wantNoSecretData: true,
		},
		{
			name:    "finance agent may read invoices",
			agentID: "finance-agent-001",
			req: access.Request{
				ResourceID:      "invoice-2001",
				Purpose:         "payment_operations",
				RequestedScopes: []string{"invoice.read"},
			},
			wantAllowed:      true,
			wantDecision:     access.DecisionAllow,
			wantInvoice:      true,
			wantAuditCount:   1,
			wantNoSecretData: true,
		},
		{
			name:    "hr agent may read employee profiles",
			agentID: "hr-agent-001",
			req: access.Request{
				ResourceID:      "employee-3001",
				Purpose:         "workforce_administration",
				RequestedScopes: []string{"employee.read"},
			},
			wantAllowed:      true,
			wantDecision:     access.DecisionAllow,
			wantEmployee:     true,
			wantAuditCount:   1,
			wantNoSecretData: true,
		},
		{
			name:    "support agent cannot read invoices",
			agentID: "support-agent-001",
			req: access.Request{
				ResourceID:      "invoice-2001",
				Purpose:         "payment_operations",
				RequestedScopes: []string{"invoice.read"},
			},
			wantAllowed:    false,
			wantDecision:   access.DecisionDeny,
			wantReason:     "no matching policy rule",
			wantAuditCount: 1,
		},
		{
			name:    "finance agent cannot read employee profiles",
			agentID: "finance-agent-001",
			req: access.Request{
				ResourceID:      "employee-3001",
				Purpose:         "workforce_administration",
				RequestedScopes: []string{"employee.read"},
			},
			wantAllowed:    false,
			wantDecision:   access.DecisionDeny,
			wantReason:     "no matching policy rule",
			wantAuditCount: 1,
		},
		{
			name:    "marketing purpose cannot access sensitive resources",
			agentID: "support-agent-001",
			req: access.Request{
				ResourceID:      "ticket-1001",
				Purpose:         "marketing",
				RequestedScopes: []string{"ticket.read"},
			},
			wantAllowed:    false,
			wantDecision:   access.DecisionDeny,
			wantReason:     "marketing purpose may not access sensitive resources",
			wantAuditCount: 1,
		},
		{
			name:    "unknown agents are denied",
			agentID: "unknown-agent",
			req: access.Request{
				ResourceID:      "ticket-1001",
				Purpose:         "customer_support",
				RequestedScopes: []string{"ticket.read"},
			},
			wantAllowed:    false,
			wantDecision:   access.DecisionDeny,
			wantReason:     "unknown agent",
			wantAuditCount: 1,
		},
		{
			name:    "unsupported purposes are denied",
			agentID: "support-agent-001",
			req: access.Request{
				ResourceID:      "ticket-1001",
				Purpose:         "research",
				RequestedScopes: []string{"ticket.read"},
			},
			wantAllowed:    false,
			wantDecision:   access.DecisionDeny,
			wantReason:     "unsupported purpose",
			wantAuditCount: 1,
		},
		{
			name:    "unsupported scopes are denied",
			agentID: "support-agent-001",
			req: access.Request{
				ResourceID:      "ticket-1001",
				Purpose:         "customer_support",
				RequestedScopes: []string{"ticket.write"},
			},
			wantAllowed:    false,
			wantDecision:   access.DecisionDeny,
			wantReason:     "unsupported scope",
			wantAuditCount: 1,
		},
		{
			name:    "multiple scopes are denied",
			agentID: "support-agent-001",
			req: access.Request{
				ResourceID:      "ticket-1001",
				Purpose:         "customer_support",
				RequestedScopes: []string{"ticket.read", "invoice.read"},
			},
			wantAllowed:    false,
			wantDecision:   access.DecisionDeny,
			wantReason:     "exactly one scope is supported by this demo",
			wantAuditCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			service, audits, _ := testService(t, tt.agentID)

			result, err := service.RequestResourceAccess(ctx, tt.req)
			if err != nil {
				t.Fatalf("RequestResourceAccess() error = %v", err)
			}
			if result.Allowed != tt.wantAllowed {
				t.Fatalf("allowed = %v, want %v; reason=%s", result.Allowed, tt.wantAllowed, result.Reason)
			}
			if tt.wantReason != "" && result.Reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", result.Reason, tt.wantReason)
			}
			wantResource := tt.wantTicket || tt.wantInvoice || tt.wantEmployee
			if (result.Resource != nil) != wantResource {
				t.Fatalf("resource returned = %v, want %v", result.Resource != nil, wantResource)
			}
			if result.Resource != nil {
				if (result.Resource.SupportTicket != nil) != tt.wantTicket {
					t.Fatalf("ticket returned = %v, want %v", result.Resource.SupportTicket != nil, tt.wantTicket)
				}
				if (result.Resource.Invoice != nil) != tt.wantInvoice {
					t.Fatalf("invoice returned = %v, want %v", result.Resource.Invoice != nil, tt.wantInvoice)
				}
				if (result.Resource.EmployeeProfile != nil) != tt.wantEmployee {
					t.Fatalf("employee returned = %v, want %v", result.Resource.EmployeeProfile != nil, tt.wantEmployee)
				}
			}
			if tt.wantNoSecretData {
				assertNoUnapprovedFields(t, result)
			}

			events, err := audits.List(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(events) != tt.wantAuditCount {
				t.Fatalf("audit count = %d, want %d", len(events), tt.wantAuditCount)
			}
			if events[0].Decision != tt.wantDecision {
				t.Fatalf("audit decision = %q, want %q", events[0].Decision, tt.wantDecision)
			}
			if events[0].AgentID != tt.agentID {
				t.Fatalf("audit agent ID = %q, want %q", events[0].AgentID, tt.agentID)
			}
		})
	}
}

func TestDeniedResultOmitsResourceFromJSON(t *testing.T) {
	ctx := context.Background()
	service, _, _ := testService(t, "support-agent-001")
	result, err := service.RequestResourceAccess(ctx, access.Request{
		ResourceID:      "invoice-2001",
		Purpose:         "payment_operations",
		RequestedScopes: []string{"invoice.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Allowed {
		t.Fatal("result was allowed, want denied")
	}
	if result.Resource != nil {
		t.Fatalf("denied result resource = %#v, want nil", result.Resource)
	}
	assertJSONResourcePresence(t, result, false)
}

func TestAllowedResultIncludesResourceInJSON(t *testing.T) {
	ctx := context.Background()
	service, _, _ := testService(t, "support-agent-001")
	result, err := service.RequestResourceAccess(ctx, access.Request{
		ResourceID:      "ticket-1001",
		Purpose:         "customer_support",
		RequestedScopes: []string{"ticket.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Allowed {
		t.Fatalf("result denied: %s", result.Reason)
	}
	if result.Resource == nil {
		t.Fatal("allowed result resource = nil, want projected view")
	}
	assertJSONResourcePresence(t, result, true)
}

func TestUnknownAgentCannotEnumerateResources(t *testing.T) {
	ctx := context.Background()
	service, _, resources := testService(t, "unknown-agent")
	existing, err := service.RequestResourceAccess(ctx, access.Request{ResourceID: "ticket-1001", Purpose: "customer_support", RequestedScopes: []string{"ticket.read"}})
	if err != nil {
		t.Fatal(err)
	}
	missing, err := service.RequestResourceAccess(ctx, access.Request{ResourceID: "missing-resource", Purpose: "customer_support", RequestedScopes: []string{"ticket.read"}})
	if err != nil {
		t.Fatal(err)
	}
	if existing.Allowed || missing.Allowed {
		t.Fatalf("unknown agent was allowed: existing=%v missing=%v", existing.Allowed, missing.Allowed)
	}
	if existing.Reason != missing.Reason || existing.Reason != "unknown agent" {
		t.Fatalf("unknown agent reasons differ: existing=%q missing=%q", existing.Reason, missing.Reason)
	}
	if resources.Count() != 0 {
		t.Fatalf("resource lookups = %d, want 0", resources.Count())
	}
}

func TestKnownAgentFetchesResourceOnce(t *testing.T) {
	ctx := context.Background()
	service, _, resources := testService(t, "support-agent-001")
	_, err := service.RequestResourceAccess(ctx, access.Request{ResourceID: "ticket-1001", Purpose: "customer_support", RequestedScopes: []string{"ticket.read"}})
	if err != nil {
		t.Fatal(err)
	}
	if resources.Count() != 1 {
		t.Fatalf("resource Get calls = %d, want 1", resources.Count())
	}
}

func TestAuditIDGenerationFailureFailsClosed(t *testing.T) {
	ctx := context.Background()
	service, audits, _ := testServiceWithIDGenerator(t, "support-agent-001", func() (string, error) {
		return "", errors.New("rng unavailable")
	})
	result, err := service.RequestResourceAccess(ctx, access.Request{ResourceID: "ticket-1001", Purpose: "customer_support", RequestedScopes: []string{"ticket.read"}})
	if err == nil {
		t.Fatal("RequestResourceAccess() error = nil, want error")
	}
	if result.Allowed {
		t.Fatal("access response was allowed despite audit ID generation failure")
	}
	events, listErr := audits.List(ctx)
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(events) != 0 {
		t.Fatalf("audit events = %d, want 0", len(events))
	}
}

func TestListMyAuditEventsFiltersConfiguredAgent(t *testing.T) {
	ctx := context.Background()
	service, audits, _ := testService(t, "support-agent-001")
	if err := audits.Append(ctx, audit.Event{ID: "other", AgentID: "finance-agent-001", Decision: access.DecisionDeny}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RequestResourceAccess(ctx, access.Request{
		ResourceID:      "ticket-1001",
		Purpose:         "customer_support",
		RequestedScopes: []string{"ticket.read"},
	}); err != nil {
		t.Fatal(err)
	}

	events, err := service.ListMyAuditEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("filtered audit count = %d, want 1", len(events))
	}
	if events[0].AgentID != "support-agent-001" {
		t.Fatalf("agent ID = %q, want support-agent-001", events[0].AgentID)
	}
}

func TestExplainAccessDecisionIsSafe(t *testing.T) {
	ctx := context.Background()
	service, _, _ := testService(t, "support-agent-001")
	result, err := service.RequestResourceAccess(ctx, access.Request{
		ResourceID:      "invoice-2001",
		Purpose:         "payment_operations",
		RequestedScopes: []string{"invoice.read"},
	})
	if err != nil {
		t.Fatal(err)
	}

	explanation, found, err := service.ExplainAccessDecision(ctx, result.AuditEventID)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("explanation not found")
	}
	if explanation.Decision != access.DecisionDeny {
		t.Fatalf("decision = %q, want deny", explanation.Decision)
	}
	for _, forbidden := range []string{"support-agent-001", "finance-agent-001", "internal", "secret"} {
		if strings.Contains(explanation.Summary, forbidden) {
			t.Fatalf("summary %q contains forbidden detail %q", explanation.Summary, forbidden)
		}
	}
}

func TestExplainAccessDecisionHidesCrossAgentEvents(t *testing.T) {
	ctx := context.Background()
	service, audits, _ := testService(t, "support-agent-001")
	if err := audits.Append(ctx, audit.Event{ID: "finance-event", AgentID: "finance-agent-001", Decision: access.DecisionAllow}); err != nil {
		t.Fatal(err)
	}

	missingExplanation, missingFound, missingErr := service.ExplainAccessDecision(ctx, "missing-event")
	crossExplanation, crossFound, crossErr := service.ExplainAccessDecision(ctx, "finance-event")
	if missingErr != nil || crossErr != nil {
		t.Fatalf("unexpected errors: missing=%v cross=%v", missingErr, crossErr)
	}
	if missingFound != crossFound || missingExplanation != crossExplanation {
		t.Fatalf("cross-agent response differs from not-found: missing=(%+v,%v), cross=(%+v,%v)", missingExplanation, missingFound, crossExplanation, crossFound)
	}
}

func testService(t *testing.T, agentID string) (access.Service, *storage.MemoryAuditRepository, *countingResourceRepository) {
	t.Helper()
	return testServiceWithIDGenerator(t, agentID, deterministicIDGenerator())
}

func testServiceWithIDGenerator(t *testing.T, agentID string, newID access.AuditIDGenerator) (access.Service, *storage.MemoryAuditRepository, *countingResourceRepository) {
	t.Helper()

	ctx := context.Background()
	now := time.Date(2026, time.September, 14, 12, 0, 0, 0, time.UTC)
	agents := storage.NewMemoryAgentRepository()
	baseResources := storage.NewMemoryResourceRepository()
	resources := &countingResourceRepository{base: baseResources}
	audits := storage.NewMemoryAuditRepository()

	for _, profile := range []access.AgentProfile{
		{ID: "support-agent-001", PolicyRule: access.PolicyRule{ResourceType: access.ResourceTypeSupportTicket, Purpose: "customer_support", Scope: "ticket.read"}},
		{ID: "finance-agent-001", PolicyRule: access.PolicyRule{ResourceType: access.ResourceTypeInvoice, Purpose: "payment_operations", Scope: "invoice.read"}},
		{ID: "hr-agent-001", PolicyRule: access.PolicyRule{ResourceType: access.ResourceTypeEmployeeProfile, Purpose: "workforce_administration", Scope: "employee.read"}},
	} {
		if err := agents.Save(ctx, profile); err != nil {
			t.Fatal(err)
		}
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
				InternalNotes:   []string{sensitiveTicketNote},
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
				InternalMemo:  sensitiveFinanceMemo,
				UpdatedAt:     now,
			},
		},
		{
			ID:   "employee-3001",
			Type: access.ResourceTypeEmployeeProfile,
			EmployeeProfile: &access.EmployeeProfile{
				ID:             "employee-3001",
				EmployeeCode:   "emp-demo-88",
				Department:     "Operations",
				Location:       "Remote",
				EmploymentType: "full_time",
				ManagerCode:    "mgr-demo-12",
				CompBand:       sensitiveCompBand,
				Notes:          []string{sensitiveHRNote},
				UpdatedAt:      now,
			},
		},
	} {
		if err := baseResources.Save(ctx, resource); err != nil {
			t.Fatal(err)
		}
	}

	return access.NewService(agentID, agents, resources, audits, func() time.Time { return now }, newID), audits, resources
}

func deterministicIDGenerator() access.AuditIDGenerator {
	var n int
	return func() (string, error) {
		n++
		return "audit-test-" + string(rune('0'+n)), nil
	}
}

type countingResourceRepository struct {
	base  *storage.MemoryResourceRepository
	count int
}

func (r *countingResourceRepository) Get(ctx context.Context, resourceID string) (access.Resource, bool, error) {
	r.count++
	return r.base.Get(ctx, resourceID)
}

func (r *countingResourceRepository) Count() int {
	return r.count
}

func assertNoUnapprovedFields(t *testing.T, result access.Result) {
	t.Helper()
	if result.Resource == nil {
		t.Fatal("resource view is nil")
	}
	if result.Resource.SupportTicket != nil && len(result.Resource.SupportTicket.PublicSummary) == 0 {
		t.Fatal("ticket view omitted approved public summary")
	}
	if result.Resource.Invoice != nil && result.Resource.Invoice.LineItemCount == 0 {
		t.Fatal("invoice view omitted approved line item count")
	}
	if result.Resource.EmployeeProfile != nil && result.Resource.EmployeeProfile.ManagerCode == "" {
		t.Fatal("employee view omitted approved manager code")
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	body := string(encoded)
	for _, forbidden := range []string{sensitiveTicketNote, sensitiveFinanceMemo, sensitiveCompBand, sensitiveHRNote} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("serialized output leaked %q: %s", forbidden, body)
		}
	}
}

func assertJSONResourcePresence(t *testing.T, result access.Result, want bool) {
	t.Helper()
	encoded, err := json.Marshal(result)
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
