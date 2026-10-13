package eventstore

import (
	"encoding/json"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"
)

var moneyCheck = fields(map[string]validator{"amount_micros": whole(0, 9007199254740991), "currency": grammar(`[A-Z]{3}`)})
var priceCheck = nullable(fields(map[string]validator{"per_hour": moneyCheck, "source": oneOf("adapter", "configured")}))

func checkResource(e Object) error {
	kind := text(e["kind"])
	var checks map[string]validator
	resource := grammar(`rs-[0-9a-f]{24}`)
	identifier := grammar(`[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`)
	switch kind {
	case "resource.intent":
		checks = map[string]validator{"resource": resource, "run": runCheck, "kind": grammar(`[a-z][a-z0-9-]{0,31}`), "provider": grammar(`[a-z0-9][a-z0-9-]{0,31}`), "purpose": grammar(`[A-Za-z0-9][A-Za-z0-9._:/+-]{0,63}`), "size": nullable(grammar(`[A-Za-z0-9][A-Za-z0-9._:/+-]{0,63}`)), "region": nullable(grammar(`[a-z0-9][a-z0-9-]{0,31}`)), "price": priceCheck, "hard_cap_minutes": whole(1, 10080)}
	case "resource.acquired":
		checks = map[string]validator{"resource": resource, "provider_id": grammar(`[A-Za-z0-9][A-Za-z0-9._:/+-]{0,191}`), "found_by": oneOf("acquire", "describe"), "started_at": nullable(checkTimestamp), "request": nullable(identifier)}
	case "resource.failed":
		checks = map[string]validator{"resource": resource, "how": oneOf("adapter", "release"), "reason": grammar(`[a-z][a-z-]{0,39}`), "request": nullable(identifier)}
	case "resource.released":
		checks = map[string]validator{"resource": resource, "how": oneOf("release", "by-itself", "observed"), "read_back": fields(map[string]validator{"at": checkTimestamp, "state": oneOf("terminated"), "provider_state": identifier, "ended_at": nullable(checkTimestamp), "request": nullable(identifier)})}
	case "resource.cost":
		checks = map[string]validator{"resource": resource, "started_at": checkTimestamp, "ended_at": checkTimestamp, "price": priceCheck, "cost": nullable(moneyCheck)}
	default:
		return Refuse("kind: resource events are resource.intent, resource.acquired, resource.failed, resource.released, resource.cost")
	}
	if e["lane"] == nil {
		return Refuse("lane: is required for resource events")
	}
	p := object(e["payload"])
	if err := fields(checks)(p, "payload"); err != nil {
		return Refuse("%s %s", kind, err.Error())
	}
	if kind == "resource.cost" {
		if (p["price"] == nil) != (p["cost"] == nil) {
			return Refuse("resource.cost payload.cost: is null exactly when payload.price is null")
		}
		if p["price"] != nil && object(p["cost"])["currency"] != object(object(p["price"])["per_hour"])["currency"] {
			return Refuse("resource.cost payload.cost.currency: is the currency of payload.price")
		}
	}
	return nil
}
func holding(records map[string]Object, lane string) []any {
	names := []string{}
	for name, r := range records {
		if r["lane"] == lane && (r["state"] == "intent" || r["state"] == "acquired") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	result := []any{}
	for _, n := range names {
		result = append(result, Object{"resource": n, "state": records[n]["state"]})
	}
	return result
}
func checkResourceOrder(records map[string]Object, e Object) error {
	kind := text(e["kind"])
	p := object(e["payload"])
	r := records[text(p["resource"])]
	if kind == "resource.intent" {
		if r != nil {
			return Refuse("resource.intent: this resource is stored already; an id has one intent")
		}
		return nil
	}
	if r == nil {
		return Refuse("%s: no intent of this resource is stored", kind)
	}
	if !equal(r["lane"], e["lane"]) {
		return Refuse("%s: this resource belongs to another lane", kind)
	}
	needed := map[string]string{"resource.acquired": "intent", "resource.failed": "intent", "resource.released": "acquired", "resource.cost": "released"}[kind]
	if r["state"] != needed {
		return Refuse("%s: the resource is not in the state this kind needs", kind)
	}
	if kind == "resource.cost" && r["cost_seq"] != nil {
		return Refuse("resource.cost: this resource has its cost already")
	}
	return nil
}
func startOf(r Object) any {
	if r["started_at"] != nil {
		return r["started_at"]
	}
	return r["intent_at"]
}
func instant(v any) time.Time { t, _ := time.Parse(time.RFC3339Nano, text(v)); return t }
func endOf(r Object) any {
	start := startOf(r)
	back := object(r["read_back"])
	for _, v := range []any{back["ended_at"], back["at"]} {
		if v != nil && !instant(v).Before(instant(start)) {
			return v
		}
	}
	return start
}
func costOf(r Object) any {
	if r["price"] == nil {
		return nil
	}
	start, end := instant(startOf(r)), instant(endOf(r))
	micros := (end.Unix()-start.Unix())*1000000 + int64(end.Nanosecond()-start.Nanosecond())/1000
	price := object(object(r["price"])["per_hour"])
	amount := new(big.Int).Mul(big.NewInt(num(price["amount_micros"])), big.NewInt(micros))
	amount.Add(amount, big.NewInt(3599999999))
	amount.Quo(amount, big.NewInt(3600000000))
	return Object{"amount_micros": json.Number(amount.String()), "currency": price["currency"]}
}
func checkResourceTransition(row Object, records map[string]Object, e Object) error {
	kind := text(e["kind"])
	p := object(e["payload"])
	if row == nil {
		return Refuse("%s: lane %s is not known; the store has no lane event of it", kind, text(e["lane"]))
	}
	if err := checkResourceOrder(records, e); err != nil {
		return err
	}
	if kind == "resource.intent" {
		if num(p["run"]) > num(row["run"]) {
			return Refuse("resource.intent: the lane has no such run")
		}
		if row["state"] == "merged" || row["state"] == "abandoned" {
			return Refuse("resource.intent: the lane is closed, so it takes no new resource")
		}
		if len(holding(records, text(e["lane"]))) >= 256 {
			return Refuse("resource.intent: the lane holds 256 resources already")
		}
	}
	if kind == "resource.cost" {
		r := records[text(p["resource"])]
		if !equal(p["price"], r["price"]) {
			return Refuse("resource.cost: payload.price is not the price of the intent")
		}
		if !equal(p["started_at"], startOf(r)) {
			return Refuse("resource.cost: payload.started_at is not the start of the held time")
		}
		if !equal(p["ended_at"], endOf(r)) {
			return Refuse("resource.cost: payload.ended_at is not the end of the held time")
		}
		if !equal(p["cost"], costOf(r)) {
			return Refuse("resource.cost: payload.cost is not the price times the held time, rounded up")
		}
	}
	return nil
}
func checkResourceState(records map[string]Object, e Object) error {
	held := object(e["payload"])["held"]
	if held == nil {
		held = []any{}
	}
	if !equal(held, holding(records, text(e["lane"]))) {
		return Refuse("lane.state: payload.held must list exactly the resources this lane holds now, each with its state, and be left out when it holds none")
	}
	return nil
}
func applyResource(records map[string]Object, e Object) {
	p := object(e["payload"])
	name := text(p["resource"])
	at := e["occurred_at"]
	if at == nil {
		at = e["recorded_at"]
	}
	if e["kind"] == "resource.intent" {
		r := Object{}
		for k, v := range p {
			r[k] = v
		}
		r["lane"] = e["lane"]
		r["state"] = "intent"
		r["seq"] = e["seq"]
		r["intent_at"] = at
		r["started_at"], r["read_back"], r["cost_seq"] = nil, nil, nil
		records[name] = r
		return
	}
	r := records[name]
	switch e["kind"] {
	case "resource.acquired":
		r["state"], r["started_at"] = "acquired", p["started_at"]
	case "resource.failed":
		r["state"] = "failed"
	case "resource.released":
		r["state"], r["read_back"] = "released", p["read_back"]
	case "resource.cost":
		r["cost_seq"] = e["seq"]
	}
}
func foldResources(events []Object) (map[string]Object, error) {
	r := map[string]Object{}
	for _, e := range events {
		if strings.HasPrefix(text(e["kind"]), "resource.") {
			if err := checkResource(e); err != nil {
				return nil, storedFailure(e, err)
			}
			if err := checkResourceOrder(r, e); err != nil {
				return nil, storedFailure(e, err)
			}
			applyResource(r, e)
		}
	}
	return r, nil
}
func checkResourceAppend(events []Object, current, e Object) error {
	records, err := foldResources(events)
	if err != nil {
		return err
	}
	if e["kind"] == "lane.state" {
		return checkResourceState(records, e)
	}
	return checkResourceTransition(current, records, e)
}
func gateVersion(version string) bool {
	parts := strings.Split(version, ".")
	want := []int{1, 3, 0}
	if len(parts) != 3 {
		return false
	}
	for i, s := range parts {
		n, _ := strconv.Atoi(s)
		if n != want[i] {
			return n > want[i]
		}
	}
	return true
}
func replayResources(events []Object) error {
	projections := map[string]Object{}
	records := map[string]Object{}
	for _, e := range events {
		kind, lane := text(e["kind"]), text(e["lane"])
		if strings.HasPrefix(kind, "resource.") {
			if err := checkResourceTransition(projections[lane], records, e); err != nil {
				return storedFailure(e, err)
			}
			applyResource(records, e)
		} else if strings.HasPrefix(kind, "lane.") {
			if kind == "lane.state" && (object(e["payload"])["state"] == "accepted" || object(e["payload"])["state"] == "merged") && gateVersion(text(e["protocol_version"])) {
				if err := checkResourceState(records, e); err != nil {
					return storedFailure(e, err)
				}
			}
			p := projections[lane]
			if p == nil {
				p = empty(lane)
				projections[lane] = p
			}
			apply(p, e)
		}
	}
	return nil
}
