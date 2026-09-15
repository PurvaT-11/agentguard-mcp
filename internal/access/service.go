package access

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	"github.com/PurvaT-11/agentguard-mcp/internal/audit"
)

const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
)

type AgentRepository interface {
	AgentProfile(ctx context.Context, agentID string) (AgentProfile, bool, error)
}

type ResourceRepository interface {
	Get(ctx context.Context, resourceID string) (Resource, bool, error)
}

type AuditRepository interface {
	Append(ctx context.Context, event audit.Event) error
	Get(ctx context.Context, eventID string) (audit.Event, bool, error)
	ListByAgent(ctx context.Context, agentID string) ([]audit.Event, error)
}

type Clock func() time.Time

type AuditIDGenerator func() (string, error)

type Request struct {
	ResourceID      string
	Purpose         string
	RequestedScopes []string
}

type Result struct {
	AuditEventID string        `json:"audit_event_id"`
	Allowed      bool          `json:"allowed"`
	Reason       string        `json:"reason"`
	Resource     *ResourceView `json:"resource,omitempty"`
}

type Explanation struct {
	AuditEventID string `json:"audit_event_id"`
	Decision     string `json:"decision"`
	Reason       string `json:"reason"`
	Summary      string `json:"summary"`
}

type Service struct {
	agentID   string
	agents    AgentRepository
	resources ResourceRepository
	audit     AuditRepository
	now       Clock
	newID     AuditIDGenerator
}

func NewService(agentID string, agents AgentRepository, resources ResourceRepository, auditRepo AuditRepository, now Clock, newID AuditIDGenerator) Service {
	if now == nil {
		now = time.Now
	}
	if newID == nil {
		newID = GenerateAuditID
	}
	return Service{
		agentID:   agentID,
		agents:    agents,
		resources: resources,
		audit:     auditRepo,
		now:       now,
		newID:     newID,
	}
}

func (s Service) RequestResourceAccess(ctx context.Context, req Request) (Result, error) {
	decision, resource := s.evaluate(ctx, req)
	result := Result{Allowed: decision.Allowed, Reason: decision.Reason}

	if decision.Allowed {
		view := projectResource(resource, req.RequestedScopes)
		result.Resource = &view
	}

	eventID, err := s.newID()
	if err != nil {
		return Result{}, fmt.Errorf("generate audit id: %w", err)
	}
	if err := s.audit.Append(ctx, audit.Event{
		ID:              eventID,
		AgentID:         s.agentID,
		ResourceID:      req.ResourceID,
		ResourceType:    decision.ResourceType,
		RequestedScopes: append([]string(nil), req.RequestedScopes...),
		Purpose:         req.Purpose,
		Decision:        decisionString(result.Allowed),
		Reason:          result.Reason,
		Timestamp:       s.now().UTC(),
	}); err != nil {
		return Result{}, err
	}
	result.AuditEventID = eventID

	return result, nil
}

func (s Service) ExplainAccessDecision(ctx context.Context, auditEventID string) (Explanation, bool, error) {
	event, ok, err := s.audit.Get(ctx, auditEventID)
	if err != nil {
		return Explanation{}, false, err
	}
	if !ok || event.AgentID != s.agentID {
		return Explanation{}, false, nil
	}

	return Explanation{
		AuditEventID: auditEventID,
		Decision:     event.Decision,
		Reason:       event.Reason,
		Summary:      safeSummary(event),
	}, true, nil
}

func (s Service) ListMyAuditEvents(ctx context.Context) ([]audit.Event, error) {
	return s.audit.ListByAgent(ctx, s.agentID)
}

type policyDecision struct {
	Allowed      bool
	Reason       string
	ResourceType string
}

func (s Service) evaluate(ctx context.Context, req Request) (policyDecision, Resource) {
	profile, ok, err := s.agents.AgentProfile(ctx, s.agentID)
	if err != nil {
		return policyDecision{Reason: "agent lookup failed"}, Resource{}
	}
	if !ok {
		return policyDecision{Reason: "unknown agent"}, Resource{}
	}

	if req.Purpose == "marketing" {
		return policyDecision{Reason: "marketing purpose may not access sensitive resources"}, Resource{}
	}
	if req.Purpose == "" {
		return policyDecision{Reason: "purpose is required"}, Resource{}
	}
	if len(req.RequestedScopes) == 0 {
		return policyDecision{Reason: "at least one scope is required"}, Resource{}
	}
	if len(req.RequestedScopes) != 1 {
		return policyDecision{Reason: "exactly one scope is supported by this demo"}, Resource{}
	}

	scope := req.RequestedScopes[0]
	if !supportedPurpose(req.Purpose) {
		return policyDecision{Reason: "unsupported purpose"}, Resource{}
	}
	if !supportedScope(scope) {
		return policyDecision{Reason: "unsupported scope"}, Resource{}
	}

	resource, ok, err := s.resources.Get(ctx, req.ResourceID)
	if err != nil {
		return policyDecision{Reason: "resource lookup failed"}, Resource{}
	}
	if !ok {
		return policyDecision{Reason: "resource not found"}, Resource{}
	}

	rule := profile.PolicyRule
	if rule.ResourceType == resource.Type && rule.Purpose == req.Purpose && rule.Scope == scope {
		return policyDecision{Allowed: true, ResourceType: resource.Type, Reason: "request matches configured least-privilege policy"}, resource
	}

	return policyDecision{ResourceType: resource.Type, Reason: "no matching policy rule"}, resource
}

func projectResource(resource Resource, scopes []string) ResourceView {
	view := ResourceView{
		ResourceID:    resource.ID,
		ResourceType:  resource.Type,
		GrantedScopes: append([]string(nil), scopes...),
	}
	if len(scopes) != 1 {
		return view
	}

	switch scopes[0] {
	case "ticket.read":
		if resource.SupportTicket != nil {
			ticket := resource.SupportTicket
			view.SupportTicket = &SupportTicketView{
				ID:              ticket.ID,
				Subject:         ticket.Subject,
				Status:          ticket.Status,
				Priority:        ticket.Priority,
				Category:        ticket.Category,
				PublicSummary:   ticket.PublicSummary,
				RequesterHandle: ticket.RequesterHandle,
				UpdatedAt:       ticket.UpdatedAt,
			}
		}
	case "invoice.read":
		if resource.Invoice != nil {
			invoice := resource.Invoice
			view.Invoice = &InvoiceView{
				ID:            invoice.ID,
				AccountCode:   invoice.AccountCode,
				Status:        invoice.Status,
				AmountCents:   invoice.AmountCents,
				Currency:      invoice.Currency,
				DueDate:       invoice.DueDate,
				LineItemCount: invoice.LineItemCount,
				UpdatedAt:     invoice.UpdatedAt,
			}
		}
	case "employee.read":
		if resource.EmployeeProfile != nil {
			employee := resource.EmployeeProfile
			view.EmployeeProfile = &EmployeeProfileView{
				ID:             employee.ID,
				EmployeeCode:   employee.EmployeeCode,
				Department:     employee.Department,
				Location:       employee.Location,
				EmploymentType: employee.EmploymentType,
				ManagerCode:    employee.ManagerCode,
				UpdatedAt:      employee.UpdatedAt,
			}
		}
	}

	return view
}

func decisionString(allowed bool) string {
	if allowed {
		return DecisionAllow
	}
	return DecisionDeny
}

func supportedPurpose(purpose string) bool {
	return slices.Contains([]string{"customer_support", "payment_operations", "workforce_administration"}, purpose)
}

func supportedScope(scope string) bool {
	return slices.Contains([]string{"ticket.read", "invoice.read", "employee.read"}, scope)
}

func safeSummary(event audit.Event) string {
	if event.Decision == DecisionAllow {
		return fmt.Sprintf("Access was allowed because the configured agent, purpose, scope, and resource type matched an explicit policy for %s.", event.ResourceType)
	}
	return "Access was denied by default because the request did not satisfy an explicit least-privilege policy."
}

func GenerateAuditID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "audit-" + hex.EncodeToString(b[:]), nil
}
