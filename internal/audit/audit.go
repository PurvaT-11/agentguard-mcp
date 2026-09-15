package audit

import "time"

type Event struct {
	ID              string    `json:"id"`
	AgentID         string    `json:"agent_id"`
	ResourceID      string    `json:"resource_id"`
	ResourceType    string    `json:"resource_type"`
	RequestedScopes []string  `json:"requested_scopes"`
	Purpose         string    `json:"purpose"`
	Decision        string    `json:"decision"`
	Reason          string    `json:"reason"`
	Timestamp       time.Time `json:"timestamp"`
}
