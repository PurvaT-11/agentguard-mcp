package mcpserver_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PurvaT-11/agentguard-mcp/internal/access"
	"github.com/PurvaT-11/agentguard-mcp/internal/mcpserver"
)

func TestToolInputSchemasDoNotAcceptAgentControlledIdentity(t *testing.T) {
	ctx := context.Background()
	server := mcpserver.New(access.Service{})
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v0.0.1"}, nil)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := clientSession.Close(); err != nil {
			t.Errorf("client close: %v", err)
		}
		if err := serverSession.Wait(); err != nil {
			t.Errorf("server wait: %v", err)
		}
	}()

	seen := map[string]bool{}
	for tool, err := range clientSession.Tools(ctx, nil) {
		if err != nil {
			t.Fatal(err)
		}
		seen[tool.Name] = true
		schemaJSON, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatal(err)
		}
		schema := strings.ToLower(string(schemaJSON))
		for _, forbidden := range []string{"agent_id", "role", "permissions"} {
			if strings.Contains(schema, forbidden) {
				t.Fatalf("tool %q input schema contains %q: %s", tool.Name, forbidden, schema)
			}
		}
	}

	for _, expected := range []string{"request_resource_access", "explain_access_decision", "list_my_audit_events"} {
		if !seen[expected] {
			t.Fatalf("expected tool %q was not registered; saw %#v", expected, seen)
		}
	}
	if len(seen) != 3 {
		t.Fatalf("registered tool count = %d, want 3: %#v", len(seen), seen)
	}
}
