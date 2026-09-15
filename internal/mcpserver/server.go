package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PurvaT-11/agentguard-mcp/internal/access"
	"github.com/PurvaT-11/agentguard-mcp/internal/audit"
)

type Server struct {
	access access.Service
}

func New(accessService access.Service) *mcp.Server {
	adapter := Server{access: accessService}
	server := mcp.NewServer(&mcp.Implementation{Name: "agentguard-mcp", Version: "v0.1.0"}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "request_resource_access",
		Description: "Request least-privilege access to a synthetic business resource. Agent identity is loaded from trusted server configuration.",
	}, adapter.requestResourceAccess)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "explain_access_decision",
		Description: "Return a safe explanation for one of the configured agent's audit decisions.",
	}, adapter.explainAccessDecision)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_my_audit_events",
		Description: "List audit events for the configured agent only.",
	}, adapter.listMyAuditEvents)

	return server
}

type RequestResourceAccessInput struct {
	ResourceID      string   `json:"resource_id" jsonschema:"Synthetic resource ID, such as ticket-1001, invoice-2001, or employee-3001"`
	Purpose         string   `json:"purpose" jsonschema:"Purpose of use, such as customer_support, payment_operations, or workforce_administration"`
	RequestedScopes []string `json:"requested_scopes" jsonschema:"Requested scopes, such as ticket.read, invoice.read, or employee.read"`
}

type RequestResourceAccessOutput struct {
	AuditEventID string               `json:"audit_event_id" jsonschema:"Audit event ID for this authorization decision"`
	Allowed      bool                 `json:"allowed" jsonschema:"Whether access was allowed by deterministic server-side policy"`
	Reason       string               `json:"reason" jsonschema:"Safe policy decision reason"`
	Resource     *access.ResourceView `json:"resource,omitempty" jsonschema:"Projected synthetic resource fields covered by the approved scope only"`
}

func (s Server) requestResourceAccess(ctx context.Context, _ *mcp.CallToolRequest, input RequestResourceAccessInput) (*mcp.CallToolResult, RequestResourceAccessOutput, error) {
	result, err := s.access.RequestResourceAccess(ctx, access.Request{
		ResourceID:      input.ResourceID,
		Purpose:         input.Purpose,
		RequestedScopes: input.RequestedScopes,
	})
	if err != nil {
		return nil, RequestResourceAccessOutput{}, err
	}

	return nil, RequestResourceAccessOutput{
		AuditEventID: result.AuditEventID,
		Allowed:      result.Allowed,
		Reason:       result.Reason,
		Resource:     result.Resource,
	}, nil
}

type ExplainAccessDecisionInput struct {
	AuditEventID string `json:"audit_event_id" jsonschema:"Audit event ID returned by request_resource_access or list_my_audit_events"`
}

type ExplainAccessDecisionOutput struct {
	AuditEventID string `json:"audit_event_id" jsonschema:"Audit event ID"`
	Decision     string `json:"decision" jsonschema:"Allowed or denied decision"`
	Reason       string `json:"reason" jsonschema:"Safe reason for the policy decision"`
	Summary      string `json:"summary" jsonschema:"Safe explanation that avoids sensitive policy internals"`
	Found        bool   `json:"found" jsonschema:"Whether the audit event was found"`
}

func (s Server) explainAccessDecision(ctx context.Context, _ *mcp.CallToolRequest, input ExplainAccessDecisionInput) (*mcp.CallToolResult, ExplainAccessDecisionOutput, error) {
	explanation, found, err := s.access.ExplainAccessDecision(ctx, input.AuditEventID)
	if err != nil {
		return nil, ExplainAccessDecisionOutput{}, err
	}
	if !found {
		return nil, ExplainAccessDecisionOutput{AuditEventID: input.AuditEventID, Found: false}, nil
	}
	return nil, ExplainAccessDecisionOutput{
		AuditEventID: explanation.AuditEventID,
		Decision:     explanation.Decision,
		Reason:       explanation.Reason,
		Summary:      explanation.Summary,
		Found:        true,
	}, nil
}

type ListMyAuditEventsInput struct {
	Limit int `json:"limit,omitempty" jsonschema:"Optional maximum number of most recent audit events to return for the configured agent"`
}

type ListMyAuditEventsOutput struct {
	Events []audit.Event `json:"events" jsonschema:"Audit events belonging to the configured agent only"`
}

func (s Server) listMyAuditEvents(ctx context.Context, _ *mcp.CallToolRequest, input ListMyAuditEventsInput) (*mcp.CallToolResult, ListMyAuditEventsOutput, error) {
	limit, err := normalizeAuditLimit(input.Limit)
	if err != nil {
		return nil, ListMyAuditEventsOutput{}, err
	}

	events, err := s.access.ListMyAuditEvents(ctx)
	if err != nil {
		return nil, ListMyAuditEventsOutput{}, err
	}
	if len(events) > limit {
		events = events[len(events)-limit:]
	}
	return nil, ListMyAuditEventsOutput{Events: events}, nil
}

func normalizeAuditLimit(limit int) (int, error) {
	if limit == 0 {
		return 20, nil
	}
	if limit < 0 || limit > 100 {
		return 0, fmt.Errorf("limit must be 0 or between 1 and 100")
	}
	return limit, nil
}
