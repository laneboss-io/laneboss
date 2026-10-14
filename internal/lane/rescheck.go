package lane

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"math/big"
	"strings"
	"time"
)

func moneyValue(v any) bool {
	m := obj(v)
	return exactKeys(m, []string{"amount_micros", "currency"}) && whole(m["amount_micros"], 0, 9007199254740991) && match(`[A-Z]{3}`, str(m["currency"]))
}
func priceValue(v any) bool {
	if v == nil {
		return true
	}
	m := obj(v)
	return exactKeys(m, []string{"per_hour", "source"}) && moneyValue(m["per_hour"]) && contains([]string{"adapter", "configured"}, str(m["source"]))
}
func validateResource(kind, lane string, p object) error {
	fields, ok := map[string]string{"resource.intent": "resource run kind provider purpose size region price hard_cap_minutes", "resource.acquired": "resource provider_id found_by started_at request", "resource.failed": "resource how reason request", "resource.released": "resource how read_back", "resource.cost": "resource started_at ended_at price cost"}[kind]
	if !ok || lane == "" || !exactKeys(p, strings.Fields(fields)) || !match(`rs-[0-9a-f]{24}`, str(p["resource"])) {
		return refuse("resource event is not in this version's form")
	}
	switch kind {
	case "resource.intent":
		if !whole(p["run"], 1, 1000000) || !match(`[a-z][a-z0-9-]{0,31}`, str(p["kind"])) || !match(`[a-z0-9][a-z0-9-]{0,31}`, str(p["provider"])) || !match(`[A-Za-z0-9][A-Za-z0-9._:/+-]{0,63}`, str(p["purpose"])) || !nullableGrammar(p["size"], `[A-Za-z0-9][A-Za-z0-9._:/+-]{0,63}`) || !nullableGrammar(p["region"], `[a-z0-9][a-z0-9-]{0,31}`) || !priceValue(p["price"]) || !whole(p["hard_cap_minutes"], 1, 10080) {
			return refuse("resource.intent payload is invalid")
		}
	case "resource.acquired":
		if !match(`[A-Za-z0-9][A-Za-z0-9._:/+-]{0,191}`, str(p["provider_id"])) || !contains([]string{"acquire", "describe"}, str(p["found_by"])) || (p["started_at"] != nil && !validTimestamp(p["started_at"])) || !nullableGrammar(p["request"], `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`) {
			return refuse("resource.acquired payload is invalid")
		}
	case "resource.failed":
		if !contains([]string{"adapter", "release"}, str(p["how"])) || !match(`[a-z][a-z-]{0,39}`, str(p["reason"])) || !nullableGrammar(p["request"], `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`) {
			return refuse("resource.failed payload is invalid")
		}
	case "resource.released":
		m := obj(p["read_back"])
		if !contains(strings.Fields("release by-itself observed"), str(p["how"])) || !exactKeys(m, strings.Fields("at state provider_state ended_at request")) || !validTimestamp(m["at"]) || str(m["state"]) != "terminated" || !match(`[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`, str(m["provider_state"])) || (m["ended_at"] != nil && !validTimestamp(m["ended_at"])) || !nullableGrammar(m["request"], `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`) {
			return refuse("resource.released payload is invalid")
		}
	case "resource.cost":
		if !validTimestamp(p["started_at"]) || !validTimestamp(p["ended_at"]) || !priceValue(p["price"]) || (p["price"] == nil) != (p["cost"] == nil) || (p["cost"] != nil && !moneyValue(p["cost"])) || (p["cost"] != nil && str(obj(p["cost"])["currency"]) != str(obj(obj(p["price"])["per_hour"])["currency"])) {
			return refuse("resource.cost payload is invalid")
		}
	}
	return nil
}
func foldResources(db *sql.DB) (map[string]object, error) {
	rows, err := db.Query("SELECT " + eventColumns + " FROM events WHERE substr(kind,1,9)='resource.' ORDER BY seq")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := map[string]object{}
	for rows.Next() {
		e, err := readEvent(rows)
		if err != nil {
			return nil, err
		}
		if err = validateResource(str(e["kind"]), str(e["lane"]), obj(e["payload"])); err != nil {
			return nil, integrity("%s: %s", eventLabel(e), err)
		}
		if err = resourceOrder(records, e); err != nil {
			return nil, integrity("%s: %s", eventLabel(e), err)
		}
		applyResource(records, e)
	}
	return records, rows.Err()
}
func resourceOrder(records map[string]object, e object) error {
	kind := str(e["kind"])
	p := obj(e["payload"])
	id := str(p["resource"])
	r := records[id]
	if kind == "resource.intent" {
		if r != nil {
			return refuse("resource.intent: resource is stored already; an id has one intent")
		}
		return nil
	}
	if r == nil || str(r["lane"]) != str(e["lane"]) {
		return refuse("resource event has no matching intent of this lane")
	}
	wanted := map[string]string{"resource.acquired": "intent", "resource.failed": "intent", "resource.released": "acquired", "resource.cost": "released"}[kind]
	if wanted == "" || str(r["state"]) != wanted {
		return refuse("resource event is out of order")
	}
	if kind == "resource.cost" && flag(r["cost_recorded"]) {
		return refuse("resource.cost: resource has its cost already")
	}
	return nil
}
func applyResource(records map[string]object, e object) {
	p := obj(e["payload"])
	kind, id := str(e["kind"]), str(p["resource"])
	if kind == "resource.intent" {
		r := clone(p)
		r["lane"] = e["lane"]
		r["state"] = "intent"
		r["intent_at"] = e["occurred_at"]
		if r["intent_at"] == nil {
			r["intent_at"] = e["recorded_at"]
		}
		r["started_at"] = nil
		r["cost_recorded"] = false
		records[id] = r
		return
	}
	r := records[id]
	if kind == "resource.cost" {
		r["cost_recorded"] = true
		return
	}
	r["state"] = strings.TrimPrefix(kind, "resource.")
	if kind == "resource.acquired" {
		r["started_at"] = p["started_at"]
	}
	if kind == "resource.released" {
		r["read_back"] = p["read_back"]
	}
}
func checkResourceAppend(db *sql.DB, e object) error {
	records, err := foldResources(db)
	if err != nil {
		return err
	}
	if err = resourceOrder(records, e); err != nil {
		return err
	}
	lane := str(e["lane"])
	var text string
	if err = db.QueryRow("SELECT projection FROM lanes WHERE lane=?", lane).Scan(&text); err == sql.ErrNoRows {
		return refuse("resource event: lane is not known")
	} else if err != nil {
		return err
	}
	row, err := decodeProjection(text)
	if err != nil {
		return err
	}
	p := obj(e["payload"])
	if str(e["kind"]) == "resource.intent" {
		if integer(p["run"]) > integer(row["run"]) {
			return refuse("resource.intent: lane has no such run")
		}
		if contains([]string{"merged", "abandoned"}, str(row["state"])) {
			return refuse("resource.intent: a closed lane takes no new resource")
		}
		held := 0
		for _, r := range records {
			if r["lane"] == e["lane"] && contains([]string{"intent", "acquired"}, str(r["state"])) {
				held++
			}
		}
		if held >= 256 {
			return refuse("resource.intent: lane holds the most resources a lane.state can list")
		}
	}
	if str(e["kind"]) == "resource.cost" {
		r := records[str(p["resource"])]
		start := str(r["started_at"])
		if start == "" {
			start = str(r["intent_at"])
		}
		end := start
		began, err := time.Parse(time.RFC3339Nano, start)
		if err != nil {
			return integrity("resource start is invalid")
		}
		back := obj(r["read_back"])
		for _, v := range []any{back["ended_at"], back["at"]} {
			if v == nil {
				continue
			}
			at, err := time.Parse(time.RFC3339Nano, str(v))
			if err != nil {
				return integrity("resource end is invalid")
			}
			if !at.Before(began) {
				end = str(v)
				break
			}
		}
		var cost any
		if r["price"] != nil {
			ended, _ := time.Parse(time.RFC3339Nano, end)
			micros := (ended.Unix()-began.Unix())*1000000 + int64(ended.Nanosecond()-began.Nanosecond())/1000
			amount := big.NewInt(int64(number(obj(obj(r["price"])["per_hour"])["amount_micros"])))
			amount.Mul(amount, big.NewInt(micros))
			amount.Add(amount, big.NewInt(3599999999))
			amount.Quo(amount, big.NewInt(3600000000))
			cost = object{"amount_micros": json.Number(amount.String()), "currency": obj(obj(r["price"])["per_hour"])["currency"]}
		}
		if !bytes.Equal(canonical(p["price"]), canonical(r["price"])) || str(p["started_at"]) != start || str(p["ended_at"]) != end || !bytes.Equal(canonical(p["cost"]), canonical(cost)) {
			return refuse("resource.cost is not the intent's price times the observed held time, rounded up")
		}
	}
	return nil
}
