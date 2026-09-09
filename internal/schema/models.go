package schema

// ToolDefinition and ToolCall are the agent-facing contracts, extracted from
// Reeve's pkg/models without the conversation/LLM types (those stay out).
type ToolDefinition struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Parameters is the canonical recursive JSON Schema for this tool's
	// arguments. ArgsSchema remains as a compatibility input for older callers
	// and dynamic tool definitions; CanonicalSchema always prefers Parameters.
	Parameters *JSONSchema `json:"parameters,omitempty"`
	ArgsSchema string      `json:"args_schema"` // Deprecated: use Parameters.
}

type ToolCall struct {
	Name string                 `json:"name"`
	Args map[string]interface{} `json:"args"`
}
