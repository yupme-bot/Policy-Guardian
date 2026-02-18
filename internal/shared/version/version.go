package version

// Version is the semantic version for this repository release.
// It is used to populate deterministic tool_version fields in snapshots and CLI output.
const Version = "v1.0.0"

// ToolName is the stable tool identifier used in tool_version fields.
const ToolName = "policyguardian"

// ToolVersion is the fully-qualified tool identifier and version string.
// Example: "policyguardian/v0.1.0"
const ToolVersion = ToolName + "/" + Version
