package wire

// requestField is the complete path exclusion table documented in CONTRACT.md.
// The worker receives a resolved policy/context snapshot, not raw RPC params.
// A field not listed here, or any field inside embedded JSON, joins by default.
// schema excludes only the key; metadata excludes only a string leaf value.
func requestField(at screenPath, name string) (next screenPath, schema, metadata bool) {
	switch at {
	case requestPath:
		switch name {
		case "model":
			return dataPath, true, true
		case "questions":
			return questionsPath, true, false
		case "state":
			return statePath, true, false
		}
	case statePath:
		switch name {
		case "commands":
			return commandsPath, true, false
		case "rules":
			return rulesPath, true, false
		case "context":
			return contextPath, true, false
		case "decisions":
			return decisionsPath, true, false
		case "task":
			return dataPath, true, false
		}
	case commandPath:
		switch name {
		case "command", "cwd", "argv", "declared_paths", "tool":
			return dataPath, true, false
		case "raw_sha256":
			return dataPath, true, true
		}
	case contextPath:
		switch name {
		case "cwd":
			return dataPath, true, false
		case "config", "grant_set_id", "grants_sha256", "logical_turn_id", "policy_generation":
			return dataPath, true, true
		case "target":
			return targetPath, true, false
		case "role":
			return rolePath, true, false
		}
	case targetPath:
		switch name {
		case "life_id", "run":
			return dataPath, true, true
		}
	case rolePath:
		switch name {
		case "level", "role", "instance_id":
			return dataPath, true, true
		}
	case rulePath:
		switch name {
		case "id", "text", "source_sha256", "criteria_version":
			return dataPath, true, true
		}
	case decisionPath:
		// IDs are store-generated; org-authored paths/applicability and
		// provenance must equal the complete authoritative store candidate.
		// Decision text deliberately retains the caller-data join.
		switch name {
		case "id", "effective_at":
			return dataPath, true, true
		case "text", "binding":
			return dataPath, true, false
		case "source":
			return decisionSourcePath, true, false
		case "authority":
			return decisionAuthorityPath, true, false
		case "applies_to":
			return decisionAppliesToPath, true, false
		}
	case decisionSourcePath:
		switch name {
		case "id", "path", "sha256", "generation":
			return dataPath, true, true
		}
	case decisionAuthorityPath:
		switch name {
		case "kind", "receipt_id", "org_generation", "source_seq":
			return dataPath, true, true
		}
	case decisionAppliesToPath:
		switch name {
		case "roles", "project_ids", "life_ids":
			return metadataListPath, true, false
		case "levels":
			// Approved levels are numbers, with no text to exclude.
			return dataPath, true, false
		}
	case questionsPath:
		// Question-map keys are approved rule/decision IDs emitted by Payload.
		return questionPath, true, false
	case questionPath:
		switch name {
		case "instructions", "type":
			return dataPath, true, true
		case "criteria":
			return criteriaPath, true, false
		}
	case criteriaPath:
		switch name {
		case "true", "false":
			return dataPath, true, true
		}
	}
	return dataPath, false, false
}
