package eventstore

// RecordedLevel accepts only explicit numeric levels; names, roles and the
// starter's level never establish a lane's level.
func RecordedLevel(value any) any {
	if f, ok := value.(float64); ok {
		if f >= 3 && f <= 6 && f == float64(int(f)) {
			return int(f)
		}
		return nil
	}
	n, ok := integerValue(value)
	if !ok || n < 3 || n > 6 {
		return nil
	}
	return int(n)
}

// RecordedLaneInfo is the reading side for future start/adopt level/starter
// fields. It changes no event writer or lane-start contract.
func RecordedLaneInfo(events []Object) map[string]Object {
	result := map[string]Object{}
	for _, event := range events {
		if ExternallyAppended(event) {
			continue
		}
		if event["kind"] != "lane.started" && event["kind"] != "lane.adopted" {
			continue
		}
		name := text(event["lane"])
		if name == "" {
			continue
		}
		// Each start/adopt record owns its metadata. An older run must not
		// supply a missing field on the latest record.
		result[name] = Object{"level": nil, "level_source": nil, "starter": nil}
		payload := object(event["payload"])
		if value, exists := payload["level"]; exists {
			result[name]["level"] = RecordedLevel(value)
		}
		if source, ok := payload["level_source"].(string); ok && source != "" {
			result[name]["level_source"] = source
		}
		if value, exists := payload["starter"]; exists {
			result[name]["starter"] = nil
			if starter, ok := value.(string); ok && starter != "" {
				result[name]["starter"] = starter
			}
		}
	}
	return result
}
