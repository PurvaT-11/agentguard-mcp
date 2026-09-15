package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PurvaT-11/agentguard-mcp/internal/access"
	"github.com/PurvaT-11/agentguard-mcp/internal/mcpserver"
	"github.com/PurvaT-11/agentguard-mcp/internal/storage"
)

func main() {
	logger := log.New(os.Stderr, "agentguard-mcp: ", log.LstdFlags)
	ctx := context.Background()

	agentID := os.Getenv("AGENT_ID")
	if agentID == "" {
		logger.Fatal("AGENT_ID is required; set it to a configured local demo identity such as support-agent-001")
	}

	agents := storage.NewMemoryAgentRepository()
	resources := storage.NewMemoryResourceRepository()
	audits := storage.NewMemoryAuditRepository()

	if err := seed(ctx, agents, resources); err != nil {
		logger.Fatal(err)
	}

	accessService := access.NewService(agentID, agents, resources, audits, time.Now, nil)
	server := mcpserver.New(accessService)

	logger.Println("starting AgentGuard MCP server on stdio")
	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		logger.Fatal(err)
	}
}

func seed(ctx context.Context, agents *storage.MemoryAgentRepository, resources *storage.MemoryResourceRepository) error {
	for _, profile := range []access.AgentProfile{
		{
			ID: "support-agent-001",
			PolicyRule: access.PolicyRule{
				ResourceType: access.ResourceTypeSupportTicket,
				Purpose:      "customer_support",
				Scope:        "ticket.read",
			},
		},
		{
			ID: "finance-agent-001",
			PolicyRule: access.PolicyRule{
				ResourceType: access.ResourceTypeInvoice,
				Purpose:      "payment_operations",
				Scope:        "invoice.read",
			},
		},
		{
			ID: "hr-agent-001",
			PolicyRule: access.PolicyRule{
				ResourceType: access.ResourceTypeEmployeeProfile,
				Purpose:      "workforce_administration",
				Scope:        "employee.read",
			},
		},
	} {
		if err := agents.Save(ctx, profile); err != nil {
			return err
		}
	}

	now := time.Now().UTC()
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
				InternalNotes:   []string{"synthetic internal ticket note"},
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
				InternalMemo:  "synthetic internal finance memo",
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
				CompBand:       "synthetic compensation band",
				Notes:          []string{"synthetic HR note"},
				UpdatedAt:      now,
			},
		},
	} {
		if err := resources.Save(ctx, resource); err != nil {
			return err
		}
	}

	return nil
}
