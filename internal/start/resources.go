package start

import (
	"encoding/json"
	"math/big"
	"strconv"
	"strings"
	"time"
)

func resourcePayload(kind, lane string, p map[string]any) error {
	id := textCheck(`rs-[0-9a-f]{24}`, 27)
	identifier := textCheck(`[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`, 128)
	money := exactObject(map[string]validator{"amount_micros": integerCheck(0, 9007199254740991), "currency": textCheck(`[A-Z]{3}`, 3)})
	price := nullable(exactObject(map[string]validator{"per_hour": money, "source": choices("adapter", "configured")}))
	fields := map[string]validator{}
	switch kind {
	case "resource.intent":
		fields = map[string]validator{"resource": id, "run": integerCheck(1, 1000000), "kind": textCheck(`[a-z][a-z0-9-]{0,31}`, 32), "provider": textCheck(nameRule, 32), "purpose": textCheck(`[A-Za-z0-9][A-Za-z0-9._:/+-]{0,63}`, 64), "size": nullable(textCheck(`[A-Za-z0-9][A-Za-z0-9._:/+-]{0,63}`, 64)), "region": nullable(textCheck(nameRule, 32)), "price": price, "hard_cap_minutes": integerCheck(1, 10080)}
	case "resource.acquired":
		fields = map[string]validator{"resource": id, "provider_id": textCheck(`[A-Za-z0-9][A-Za-z0-9._:/+-]{0,191}`, 192), "found_by": choices("acquire", "describe"), "started_at": nullable(timestampCheck), "request": nullable(identifier)}
	case "resource.failed":
		fields = map[string]validator{"resource": id, "how": choices("adapter", "release"), "reason": textCheck(`[a-z][a-z-]{0,39}`, 40), "request": nullable(identifier)}
	case "resource.released":
		fields = map[string]validator{"resource": id, "how": choices("release", "by-itself", "observed"), "read_back": exactObject(map[string]validator{"at": timestampCheck, "state": choices("terminated"), "provider_state": identifier, "ended_at": nullable(timestampCheck), "request": nullable(identifier)})}
	case "resource.cost":
		fields = map[string]validator{"resource": id, "started_at": timestampCheck, "ended_at": timestampCheck, "price": price, "cost": nullable(money)}
	default:
		return integrity("kind: unknown resource event")
	}
	if !laneRE.MatchString(lane) {
		return integrity("lane: is required for resource events")
	}
	if err := exactObject(fields)(kind, p, "payload"); err != nil {
		return integrity(err.Error())
	}
	if kind == "resource.cost" {
		if (p["price"] == nil) != (p["cost"] == nil) {
			return integrity("resource.cost: cost is null exactly when price is null")
		}
		if p["price"] != nil && object(p["cost"])["currency"] != object(object(p["price"])["per_hour"])["currency"] {
			return integrity("resource.cost: cost currency must be the price currency")
		}
	}
	return nil
}
func atLeastVersion(version, threshold string) bool {
	a, b := strings.Split(version, "."), strings.Split(threshold, ".")
	if len(a) != 3 || len(b) != 3 {
		return false
	}
	for i := 0; i < 3; i++ {
		first, _ := strconv.Atoi(a[i])
		second, _ := strconv.Atoi(b[i])
		if first != second {
			return first > second
		}
	}
	return true
}
func resourceStart(record map[string]any) string {
	if record["started_at"] != nil {
		return str(record["started_at"])
	}
	return str(record["intent_at"])
}
func instant(text string) time.Time { t, _ := time.Parse(time.RFC3339Nano, text); return t }
func resourceEnd(record map[string]any) string {
	start := resourceStart(record)
	read := object(record["read_back"])
	for _, key := range []string{"ended_at", "at"} {
		value := read[key]
		if value != nil && !instant(str(value)).Before(instant(start)) {
			return str(value)
		}
	}
	return start
}
func resourceCost(record map[string]any) any {
	if record["price"] == nil {
		return nil
	}
	start, end := instant(resourceStart(record)), instant(resourceEnd(record))
	seconds := new(big.Int).Sub(big.NewInt(end.Unix()), big.NewInt(start.Unix()))
	micros := new(big.Int).Mul(seconds, big.NewInt(1000000))
	micros.Add(micros, big.NewInt(int64(end.Nanosecond()/1000-start.Nanosecond()/1000)))
	hour := object(object(record["price"])["per_hour"])
	amount := new(big.Int).Mul(big.NewInt(integer(hour["amount_micros"])), micros)
	amount.Add(amount, big.NewInt(3600000000-1))
	amount.Div(amount, big.NewInt(3600000000))
	return map[string]any{"amount_micros": json.Number(amount.String()), "currency": hour["currency"]}
}
func heldResources(records map[string]any, lane string) []any {
	held := []any{}
	for _, id := range sortedKeys(records) {
		record := object(records[id])
		if record["lane"] == lane && (record["state"] == "intent" || record["state"] == "acquired") {
			held = append(held, map[string]any{"resource": id, "state": record["state"]})
		}
	}
	return held
}
func checkHeld(records, event map[string]any) error {
	p := object(event["payload"])
	value := p["held"]
	if value == nil {
		value = []any{}
	}
	if !same(value, heldResources(records, str(event["lane"]))) {
		return integrity("lane.state: held must list exactly the resources its lane holds now, each with its state")
	}
	return nil
}
func resourceTransition(row, records, event map[string]any) error {
	kind, lane, p := str(event["kind"]), str(event["lane"]), object(event["payload"])
	if row == nil {
		return integrity(kind + ": the lane is not known")
	}
	id := str(p["resource"])
	record := object(records[id])
	if kind == "resource.intent" {
		if len(record) > 0 {
			return integrity("resource.intent: an id has one intent")
		}
		if integer(p["run"]) > integer(row["run"]) {
			return integrity("resource.intent: the lane has no such run")
		}
		if row["state"] == "merged" || row["state"] == "abandoned" {
			return integrity("resource.intent: a closed lane takes no new resource")
		}
		if len(heldResources(records, lane)) >= 256 {
			return integrity("resource.intent: the lane holds the maximum number of resources")
		}
		return nil
	}
	if len(record) == 0 || record["lane"] != lane {
		return integrity(kind + ": the resource has no intent of this lane")
	}
	needs := map[string]string{"resource.acquired": "intent", "resource.failed": "intent", "resource.released": "acquired", "resource.cost": "released"}
	if record["state"] != needs[kind] {
		return integrity(kind + ": the resource is not in the state this kind requires")
	}
	if kind == "resource.cost" {
		if record["cost_seq"] != nil {
			return integrity("resource.cost: the resource already has its cost")
		}
		if !same(p["price"], record["price"]) || p["started_at"] != resourceStart(record) || p["ended_at"] != resourceEnd(record) || !same(p["cost"], resourceCost(record)) {
			return integrity("resource.cost: the cost is not the recorded price times the held time, rounded up")
		}
	}
	return nil
}
func applyResource(records, event map[string]any) {
	p := object(event["payload"])
	id := str(p["resource"])
	at := event["occurred_at"]
	if at == nil {
		at = event["recorded_at"]
	}
	kind := str(event["kind"])
	if kind == "resource.intent" {
		record := map[string]any{"lane": event["lane"], "run": p["run"], "state": "intent", "intent_at": at, "started_at": nil, "price": p["price"], "read_back": nil, "cost_seq": nil}
		records[id] = record
		return
	}
	record := object(records[id])
	switch kind {
	case "resource.acquired":
		record["state"] = "acquired"
		record["started_at"] = p["started_at"]
	case "resource.failed":
		record["state"] = "failed"
	case "resource.released":
		record["state"] = "released"
		record["read_back"] = p["read_back"]
	case "resource.cost":
		record["cost_seq"] = event["seq"]
	}
}
