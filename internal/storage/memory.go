package storage

import (
	"context"
	"sync"

	"github.com/PurvaT-11/agentguard-mcp/internal/access"
	"github.com/PurvaT-11/agentguard-mcp/internal/audit"
)

type MemoryAgentRepository struct {
	mu       sync.RWMutex
	profiles map[string]access.AgentProfile
}

func NewMemoryAgentRepository() *MemoryAgentRepository {
	return &MemoryAgentRepository{profiles: make(map[string]access.AgentProfile)}
}

func (r *MemoryAgentRepository) Save(_ context.Context, profile access.AgentProfile) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.profiles[profile.ID] = profile
	return nil
}

func (r *MemoryAgentRepository) AgentProfile(_ context.Context, agentID string) (access.AgentProfile, bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	profile, ok := r.profiles[agentID]
	return profile, ok, nil
}

type MemoryResourceRepository struct {
	mu        sync.RWMutex
	resources map[string]access.Resource
}

func NewMemoryResourceRepository() *MemoryResourceRepository {
	return &MemoryResourceRepository{resources: make(map[string]access.Resource)}
}

func (r *MemoryResourceRepository) Save(_ context.Context, resource access.Resource) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resources[resource.ID] = cloneResource(resource)
	return nil
}

func (r *MemoryResourceRepository) Get(_ context.Context, resourceID string) (access.Resource, bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	resource, ok := r.resources[resourceID]
	if !ok {
		return access.Resource{}, false, nil
	}
	return cloneResource(resource), true, nil
}

type MemoryAuditRepository struct {
	mu     sync.RWMutex
	events []audit.Event
}

func NewMemoryAuditRepository() *MemoryAuditRepository {
	return &MemoryAuditRepository{}
}

func (r *MemoryAuditRepository) Append(_ context.Context, event audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, cloneAuditEvent(event))
	return nil
}

func (r *MemoryAuditRepository) Get(_ context.Context, eventID string) (audit.Event, bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, event := range r.events {
		if event.ID == eventID {
			return cloneAuditEvent(event), true, nil
		}
	}
	return audit.Event{}, false, nil
}

func (r *MemoryAuditRepository) List(_ context.Context) ([]audit.Event, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	events := make([]audit.Event, 0, len(r.events))
	for _, event := range r.events {
		events = append(events, cloneAuditEvent(event))
	}
	return events, nil
}

func (r *MemoryAuditRepository) ListByAgent(_ context.Context, agentID string) ([]audit.Event, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	events := make([]audit.Event, 0)
	for _, event := range r.events {
		if event.AgentID == agentID {
			events = append(events, cloneAuditEvent(event))
		}
	}
	return events, nil
}

func cloneResource(resource access.Resource) access.Resource {
	if resource.SupportTicket != nil {
		ticket := *resource.SupportTicket
		ticket.InternalNotes = append([]string(nil), resource.SupportTicket.InternalNotes...)
		resource.SupportTicket = &ticket
	}
	if resource.Invoice != nil {
		invoice := *resource.Invoice
		resource.Invoice = &invoice
	}
	if resource.EmployeeProfile != nil {
		employee := *resource.EmployeeProfile
		employee.Notes = append([]string(nil), resource.EmployeeProfile.Notes...)
		resource.EmployeeProfile = &employee
	}
	return resource
}

func cloneAuditEvent(event audit.Event) audit.Event {
	event.RequestedScopes = append([]string(nil), event.RequestedScopes...)
	return event
}
