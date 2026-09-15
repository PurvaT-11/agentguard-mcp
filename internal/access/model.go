package access

import "time"

const (
	ResourceTypeSupportTicket   = "support_ticket"
	ResourceTypeInvoice         = "invoice"
	ResourceTypeEmployeeProfile = "employee_profile"
)

type Resource struct {
	ID              string
	Type            string
	SupportTicket   *SupportTicket
	Invoice         *Invoice
	EmployeeProfile *EmployeeProfile
}

type SupportTicket struct {
	ID              string    `json:"id"`
	Subject         string    `json:"subject"`
	Status          string    `json:"status"`
	Priority        string    `json:"priority"`
	Category        string    `json:"category"`
	PublicSummary   string    `json:"public_summary"`
	InternalNotes   []string  `json:"internal_notes,omitempty"`
	RequesterHandle string    `json:"requester_handle"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type Invoice struct {
	ID            string    `json:"id"`
	AccountCode   string    `json:"account_code"`
	Status        string    `json:"status"`
	AmountCents   int       `json:"amount_cents"`
	Currency      string    `json:"currency"`
	DueDate       string    `json:"due_date"`
	LineItemCount int       `json:"line_item_count"`
	InternalMemo  string    `json:"internal_memo,omitempty"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type EmployeeProfile struct {
	ID             string    `json:"id"`
	EmployeeCode   string    `json:"employee_code"`
	Department     string    `json:"department"`
	Location       string    `json:"location"`
	EmploymentType string    `json:"employment_type"`
	ManagerCode    string    `json:"manager_code"`
	CompBand       string    `json:"comp_band,omitempty"`
	Notes          []string  `json:"notes,omitempty"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type ResourceView struct {
	ResourceID      string               `json:"resource_id"`
	ResourceType    string               `json:"resource_type"`
	SupportTicket   *SupportTicketView   `json:"support_ticket,omitempty"`
	Invoice         *InvoiceView         `json:"invoice,omitempty"`
	EmployeeProfile *EmployeeProfileView `json:"employee_profile,omitempty"`
	GrantedScopes   []string             `json:"granted_scopes"`
}

type SupportTicketView struct {
	ID              string    `json:"id"`
	Subject         string    `json:"subject"`
	Status          string    `json:"status"`
	Priority        string    `json:"priority"`
	Category        string    `json:"category"`
	PublicSummary   string    `json:"public_summary"`
	RequesterHandle string    `json:"requester_handle"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type InvoiceView struct {
	ID            string    `json:"id"`
	AccountCode   string    `json:"account_code"`
	Status        string    `json:"status"`
	AmountCents   int       `json:"amount_cents"`
	Currency      string    `json:"currency"`
	DueDate       string    `json:"due_date"`
	LineItemCount int       `json:"line_item_count"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type EmployeeProfileView struct {
	ID             string    `json:"id"`
	EmployeeCode   string    `json:"employee_code"`
	Department     string    `json:"department"`
	Location       string    `json:"location"`
	EmploymentType string    `json:"employment_type"`
	ManagerCode    string    `json:"manager_code"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type AgentProfile struct {
	ID         string
	PolicyRule PolicyRule
}

type PolicyRule struct {
	ResourceType string
	Purpose      string
	Scope        string
}
