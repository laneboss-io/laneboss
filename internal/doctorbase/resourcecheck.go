package doctorbase

import (
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"
)

func resourcePayloads() map[string]map[string]validator {
	id := grammar("rs-[0-9a-f]{24}")
	identifier := grammar("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
	name := grammar(nameRule)
	money := exact(map[string]validator{"amount_micros": integer(0, 9007199254740991), "currency": grammar("[A-Z]{3}")})
	price := null(exact(map[string]validator{"per_hour": money, "source": choice("adapter", "configured")}))
	readBack := exact(map[string]validator{"at": eventTimestamp, "state": choice("terminated"), "provider_state": identifier, "ended_at": null(eventTimestamp), "request": null(identifier)})
	return map[string]map[string]validator{
		"resource.intent":   {"resource": id, "run": integer(1, 1000000), "kind": grammar("[a-z][a-z0-9-]{0,31}"), "provider": name, "purpose": grammar("[A-Za-z0-9][A-Za-z0-9._:/+-]{0,63}"), "size": null(grammar("[A-Za-z0-9][A-Za-z0-9._:/+-]{0,63}")), "region": null(name), "price": price, "hard_cap_minutes": integer(1, 10080)},
		"resource.acquired": {"resource": id, "provider_id": grammar("[A-Za-z0-9][A-Za-z0-9._:/+-]{0,191}"), "found_by": choice("acquire", "describe"), "started_at": null(eventTimestamp), "request": null(identifier)},
		"resource.failed":   {"resource": id, "how": choice("adapter", "release"), "reason": grammar("[a-z][a-z-]{0,39}"), "request": null(identifier)},
		"resource.released": {"resource": id, "how": choice("release", "by-itself", "observed"), "read_back": readBack},
		"resource.cost":     {"resource": id, "started_at": eventTimestamp, "ended_at": eventTimestamp, "price": price, "cost": null(money)},
	}
}
func validateResource(event map[string]any) error {
	kind := String(event["kind"])
	fields, ok := resourcePayloads()[kind]
	if !ok {
		return fmt.Errorf("kind: an unknown resource event was stored")
	}
	if event["lane"] == nil {
		return fmt.Errorf("lane: is required for resource events")
	}
	p := Object(checkNumbers(event["payload"]))
	if err := exact(fields)(p, "payload"); err != nil {
		return fmt.Errorf("%s %s", kind, err.Error())
	}
	if kind == "resource.cost" {
		if (p["price"] == nil) != (p["cost"] == nil) {
			return fmt.Errorf("resource.cost payload.cost: is null exactly when payload.price is null")
		}
		if p["price"] != nil && Object(p["cost"])["currency"] != Object(Object(p["price"])["per_hour"])["currency"] {
			return fmt.Errorf("resource.cost payload.cost.currency: is the currency of payload.price")
		}
	}
	return nil
}

type resourceRecord struct {
	Lane, State, IntentAt, StartedAt string
	Price                            any
	ReadBack                         map[string]any
	Costed                           bool
}

func holding(records map[string]*resourceRecord, lane string) []any {
	keys := []string{}
	for name, r := range records {
		if r.Lane == lane && (r.State == "intent" || r.State == "acquired") {
			keys = append(keys, name)
		}
	}
	sort.Strings(keys)
	a := []any{}
	for _, name := range keys {
		a = append(a, map[string]any{"resource": name, "state": records[name].State})
	}
	return a
}
func resourceStart(r *resourceRecord) string {
	if r.StartedAt != "" {
		return r.StartedAt
	}
	return r.IntentAt
}
func resourceEnd(r *resourceRecord) string {
	start := resourceStart(r)
	at, _ := time.Parse(time.RFC3339Nano, start)
	for _, s := range []string{String(r.ReadBack["ended_at"]), String(r.ReadBack["at"])} {
		if s != "" {
			moment, err := time.Parse(time.RFC3339Nano, s)
			if err == nil && !moment.Before(at) {
				return s
			}
		}
	}
	return start
}
func resourceCost(r *resourceRecord) any {
	if r.Price == nil {
		return nil
	}
	start, _ := time.Parse(time.RFC3339Nano, resourceStart(r))
	end, _ := time.Parse(time.RFC3339Nano, resourceEnd(r))
	microseconds := (end.Unix()-start.Unix())*1000000 + int64(end.Nanosecond()-start.Nanosecond())/1000
	price := Object(Object(r.Price)["per_hour"])
	amount := new(big.Int).Mul(big.NewInt(integral(price["amount_micros"])), big.NewInt(microseconds))
	amount.Add(amount, big.NewInt(3600000000-1))
	amount.Div(amount, big.NewInt(3600000000))
	return map[string]any{"amount_micros": jsonNumber(amount.String()), "currency": price["currency"]}
}
func replayResource(row map[string]any, records map[string]*resourceRecord, event map[string]any) error {
	kind := String(event["kind"])
	p := Object(event["payload"])
	id := String(p["resource"])
	lane := String(event["lane"])
	r := records[id]
	fail := func(s string) error { return fmt.Errorf("%s: %s", kind, s) }
	if len(row) == 0 {
		return fail("the lane is not known; the store has no lane event of it")
	}
	if kind == "resource.intent" {
		if r != nil {
			return fail("the resource is stored already; an id has one intent")
		}
		if integral(p["run"]) > integral(row["run"]) {
			return fail("the lane has no such run")
		}
		if finished(row["state"]) {
			return fail("a closed lane takes no new resource")
		}
		if len(holding(records, lane)) >= 256 {
			return fail("the lane holds the maximum number of resources")
		}
		at := event["occurred_at"]
		if at == nil {
			at = event["recorded_at"]
		}
		records[id] = &resourceRecord{Lane: lane, State: "intent", IntentAt: String(at), Price: p["price"]}
		return nil
	}
	if r == nil {
		return fail("no intent of the resource is stored")
	}
	if r.Lane != lane {
		return fail("the resource belongs to another lane")
	}
	needs := map[string]string{"resource.acquired": "intent", "resource.failed": "intent", "resource.released": "acquired", "resource.cost": "released"}
	if r.State != needs[kind] {
		return fail("the resource is not in the state this kind needs")
	}
	switch kind {
	case "resource.acquired":
		r.State = "acquired"
		r.StartedAt = String(p["started_at"])
	case "resource.failed":
		r.State = "failed"
	case "resource.released":
		r.State = "released"
		r.ReadBack = Object(p["read_back"])
	case "resource.cost":
		if r.Costed {
			return fail("the resource has its cost already")
		}
		if !equalValue(p["price"], r.Price) {
			return fail("payload.price is not the price of the intent")
		}
		if p["started_at"] != resourceStart(r) {
			return fail("payload.started_at is not the start of the held time")
		}
		if p["ended_at"] != resourceEnd(r) {
			return fail("payload.ended_at is not the end of the held time")
		}
		if !equalValue(p["cost"], resourceCost(r)) {
			return fail("payload.cost is not the price times the held time, rounded up")
		}
		r.Costed = true
	}
	return nil
}
func versionAtLeast(s string, major, minor, patch int) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	want := []int{major, minor, patch}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return false
		}
		if n != want[i] {
			return n > want[i]
		}
	}
	return true
}
