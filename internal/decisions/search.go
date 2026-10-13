package decisions

import (
	"database/sql"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type candidate struct {
	record, row object
	lane        bool
}
type ranking struct {
	ids     []string
	matches map[string][]object
	scores  map[string]float64
}

func emptyRanking() *ranking {
	return &ranking{ids: []string{}, matches: map[string][]object{}, scores: map[string]float64{}}
}
func sortScores(scores map[string]float64) []string {
	ids := make([]string, 0, len(scores))
	for id := range scores {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if scores[ids[i]] != scores[ids[j]] {
			return scores[ids[i]] > scores[ids[j]]
		}
		return ids[i] < ids[j]
	})
	return ids
}
func dateBound(s string, upper bool) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if len(s) == 10 {
		t, e := time.Parse("2006-01-02", s)
		if e != nil {
			return time.Time{}, invalid("invalid search date")
		}
		if upper {
			t = t.AddDate(0, 0, 1)
			if t.Year() > 9999 {
				return time.Time{}, invalid("invalid search date")
			}
		}
		return t, nil
	}
	return timestamp(s, "search date")
}
func scopeMatches(v object, a *arguments) bool {
	level := ""
	if n, ok := integer(v["level"]); ok {
		level = strconv.FormatInt(n, 10)
	}
	if a.get("scope") == "own-or-level" {
		return level == a.get("level") || v["instance"] == a.get("instance")
	}
	return (!a.has("level") || level == a.get("level")) && (!a.has("instance") || v["instance"] == a.get("instance"))
}
func (s *store) candidates(a *arguments) (map[string]candidate, error) {
	for _, field := range []string{"date-from", "date-to"} {
		if a.has(field) && a.get(field) == "" {
			return nil, invalid("search date must be an ISO 8601 timestamp with offset")
		}
	}
	start, e := dateBound(a.get("date-from"), false)
	if e != nil {
		return nil, e
	}
	end, e := dateBound(a.get("date-to"), true)
	if e != nil {
		return nil, e
	}
	exclusive := len(a.get("date-to")) == 10
	if !start.IsZero() && !end.IsZero() && (start.After(end) || (exclusive && start.Equal(end))) {
		return nil, invalid("date-from must not be after date-to")
	}
	out := map[string]candidate{}
	rows, e := s.query("SELECT * FROM records ORDER BY id")
	if e != nil {
		return nil, e
	}
	for _, row := range rows {
		v, e := s.checkedRecord(row)
		if e != nil {
			return nil, e
		}
		if !scopeMatches(v, a) {
			continue
		}
		if len(a.values["status"]) > 0 {
			if !member(str(v["status"]), strings.Join(a.values["status"], " ")) {
				continue
			}
		} else if !a.flag("all") && !member(str(v["status"]), "in_force fulfilled") {
			continue
		}
		match := true
		for _, f := range []string{"id", "project", "area", "kind"} {
			if a.has(f) && v[f] != a.get(f) {
				match = false
			}
		}
		if !match {
			continue
		}
		if a.has("topic") {
			match = false
			for _, t := range list(v["topics"]) {
				if t == a.get("topic") {
					match = true
				}
			}
			if !match {
				continue
			}
		}
		t, _ := timestamp(v["answered_at"], "answered_at")
		if !start.IsZero() && t.Before(start) {
			continue
		}
		if !end.IsZero() && (t.After(end) || (exclusive && t.Equal(end))) {
			continue
		}
		out[str(v["id"])] = candidate{v, row, false}
	}
	if a.get("mode") == "keyword" && (a.get("kind") == "" || a.get("kind") == "lane_record") {
		include := true
		for _, f := range []string{"id", "project", "area", "topic", "status", "date-from", "date-to"} {
			if len(a.values[f]) > 0 {
				include = false
			}
		}
		if include {
			rows, e = s.query("SELECT * FROM lane_records ORDER BY id")
			if e != nil {
				return nil, e
			}
			for _, row := range rows {
				v, e := s.checkedLane(row)
				if e != nil {
					return nil, e
				}
				if scopeMatches(v, a) {
					out[str(v["id"])] = candidate{v, row, true}
				}
			}
		}
	}
	return out, nil
}
func quoted(term string) string { return `"` + strings.ReplaceAll(term, `"`, `""`) + `"` }
func sameFTSTerm(left, right string) (bool, error) {
	if left == right {
		return true, nil
	}
	if utf8.RuneCountInString(left) != utf8.RuneCountInString(right) {
		return false, nil
	}
	db, e := sql.Open("sqlite", ":memory:")
	if e != nil {
		return false, e
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, e = db.Exec("CREATE VIRTUAL TABLE fold USING fts5(text, tokenize='trigram')"); e != nil {
		return false, e
	}
	if _, e = db.Exec("INSERT INTO fold(rowid, text) VALUES (1, ?), (2, ?)", left, right); e != nil {
		return false, e
	}
	var n int
	if e = db.QueryRow("SELECT count(*) FROM fold WHERE fold MATCH ? AND rowid = 2", quoted(left)).Scan(&n); e != nil {
		return false, e
	}
	if n == 0 {
		return false, nil
	}
	if e = db.QueryRow("SELECT count(*) FROM fold WHERE fold MATCH ? AND rowid = 1", quoted(right)).Scan(&n); e != nil {
		return false, e
	}
	return n != 0, nil
}
func distinctTerms(query string) ([]string, error) {
	out, short, long := []string{}, map[string]bool{}, []string{}
	for _, term := range strings.FieldsFunc(query, whitespace) {
		if utf8.RuneCountInString(term) < 3 {
			folded := casefold(term)
			if short[folded] {
				continue
			}
			short[folded] = true
		} else {
			duplicate := false
			for _, other := range long {
				same, e := sameFTSTerm(term, other)
				if e != nil {
					return nil, e
				}
				if same {
					duplicate = true
					break
				}
			}
			if duplicate {
				continue
			}
			long = append(long, term)
		}
		out = append(out, term)
	}
	return out, nil
}
func (s *store) termMatches(term string, candidates map[string]candidate) ([]object, error) {
	out := []object{}
	if utf8.RuneCountInString(term) < 3 {
		for id, c := range candidates {
			columns := [][3]string{{"id", "question", "id"}, {"q_text", "question", "q_text"}, {"d_text", "decision", "d_text"}}
			if c.lane {
				columns = [][3]string{{"id", "lane", "lane_id"}, {"text", "lane", "lane_text"}}
			}
			for _, col := range columns {
				count := strings.Count(casefold(str(c.row[col[0]])), casefold(term))
				if count > 0 {
					out = append(out, object{"id": id, "index": "keyword:substring", "text": col[1], "field": col[2], "score": float64(count)})
				}
			}
		}
		return out, nil
	}
	for _, part := range []struct {
		table   string
		columns [][3]string
		lane    bool
	}{{"keyword_index", [][3]string{{"id", "question", "id"}, {"q_text", "question", "q_text"}, {"d_text", "decision", "d_text"}}, false}, {"lane_keyword_index", [][3]string{{"id", "lane", "lane_id"}, {"text", "lane", "lane_text"}}, true}} {
		for _, col := range part.columns {
			rows, e := s.query("SELECT id, bm25("+part.table+") AS score FROM "+part.table+" WHERE "+part.table+" MATCH ? ORDER BY score, id", col[0]+" : "+quoted(term))
			if e != nil {
				return nil, e
			}
			for _, r := range rows {
				id := str(r["id"])
				if c, ok := candidates[id]; ok && c.lane == part.lane {
					n, ok := number(r["score"])
					if !ok {
						return nil, integrity("invalid keyword index score")
					}
					out = append(out, object{"id": id, "index": "keyword:fts5", "text": col[1], "field": col[2], "score": -n})
				}
			}
		}
	}
	return out, nil
}
func exactSum(values []float64) float64 {
	sum := new(big.Rat)
	for _, x := range values {
		sum.Add(sum, new(big.Rat).SetFloat64(x))
	}
	v, _ := sum.Float64()
	return v
}
func (s *store) keywordRanking(query string, candidates map[string]candidate) (*ranking, error) {
	r := emptyRanking()
	terms, e := distinctTerms(query)
	if e != nil {
		return nil, e
	}
	if len(terms) == 0 {
		return r, nil
	}
	common := map[string]bool{}
	for id := range candidates {
		common[id] = true
	}
	perTerm := [][]object{}
	for _, term := range terms {
		matches, e := s.termMatches(term, candidates)
		if e != nil {
			return nil, e
		}
		if len(matches) == 0 {
			return r, nil
		}
		found := map[string]bool{}
		for _, m := range matches {
			found[str(m["id"])] = true
		}
		for id := range common {
			if !found[id] {
				delete(common, id)
			}
		}
		perTerm = append(perTerm, matches)
	}
	type rankedMatch struct {
		rank int
		m    object
	}
	evidence := map[string][]rankedMatch{}
	contributions := map[string][]float64{}
	for _, matches := range perTerm {
		best := map[string]float64{}
		for _, m := range matches {
			id := str(m["id"])
			if !common[id] {
				continue
			}
			score, _ := number(m["score"])
			old, ok := best[id]
			if !ok || score > old {
				best[id] = score
			}
		}
		ids := sortScores(best)
		ranks := map[string]int{}
		rank := 0
		previous := math.Inf(1)
		for i, id := range ids {
			if best[id] != previous {
				rank = i + 1
				previous = best[id]
			}
			ranks[id] = rank
			contributions[id] = append(contributions[id], 1/float64(60+rank))
		}
		for _, m := range matches {
			id := str(m["id"])
			if common[id] {
				evidence[id] = append(evidence[id], rankedMatch{ranks[id], m})
			}
		}
	}
	for id, entries := range evidence {
		sort.SliceStable(entries, func(i, j int) bool {
			a, b := entries[i], entries[j]
			if a.rank != b.rank {
				return a.rank < b.rank
			}
			av, _ := number(a.m["score"])
			bv, _ := number(b.m["score"])
			if av != bv {
				return av > bv
			}
			for _, f := range []string{"text", "field", "index"} {
				if a.m[f] != b.m[f] {
					return str(a.m[f]) < str(b.m[f])
				}
			}
			return false
		})
		for _, entry := range entries {
			r.matches[id] = append(r.matches[id], entry.m)
		}
		r.scores[id] = exactSum(contributions[id])
	}
	r.ids = sortScores(r.scores)
	return r, nil
}
func (s *store) vectorRanking(query string, candidates map[string]candidate, p *provider) (*ranking, error) {
	r := emptyRanking()
	model, e := s.one("SELECT * FROM models WHERE model = ?", p.model)
	if e != nil {
		return nil, e
	}
	if model != nil {
		if e = checkedModel(model); e != nil {
			return nil, e
		}
	}
	n, _ := integer(model["dimension"])
	if model == nil || n != int64(p.dimension) || model["provider"] != p.name {
		return nil, invalid("model has no compatible embeddings; run embed with this config first")
	}
	type vectorCandidate struct {
		row    object
		vector []float64
	}
	kept := []vectorCandidate{}
	rows, e := s.query("SELECT * FROM vectors WHERE model = ?", p.model)
	if e != nil {
		return nil, e
	}
	for _, row := range rows {
		vector, e := checkedVector(row, p.dimension)
		if e != nil {
			return nil, e
		}
		c, ok := candidates[str(row["record_id"])]
		if !ok || c.lane {
			continue
		}
		column := "q_sha256"
		if row["which_text"] == "d_text" {
			column = "d_sha256"
		}
		if row["text_sha256"] == c.row[column] {
			kept = append(kept, vectorCandidate{row, vector})
		}
	}
	if len(kept) == 0 {
		return r, nil
	}
	q, e := s.embedQuery(p, query)
	if e != nil {
		return nil, e
	}
	qnorm := 0.0
	for _, x := range q {
		qnorm += x * x
	}
	qnorm = math.Sqrt(qnorm)
	matches := []object{}
	for _, c := range kept {
		norm, dot := 0.0, 0.0
		for i, x := range c.vector {
			norm += x * x
			dot += x * q[i]
		}
		score := dot / (qnorm * math.Sqrt(norm))
		score = math.Max(-1, math.Min(1, score))
		side := "question"
		if c.row["which_text"] == "d_text" {
			side = "decision"
		}
		matches = append(matches, object{"id": c.row["record_id"], "index": "vector:" + p.model, "text": side, "field": c.row["which_text"], "score": score})
	}
	sort.Slice(matches, func(i, j int) bool {
		a, b := matches[i], matches[j]
		as, _ := number(a["score"])
		bs, _ := number(b["score"])
		if as != bs {
			return as > bs
		}
		if a["id"] != b["id"] {
			return str(a["id"]) < str(b["id"])
		}
		return str(a["text"]) < str(b["text"])
	})
	for _, m := range matches {
		id := str(m["id"])
		if len(r.matches[id]) == 0 {
			score, _ := number(m["score"])
			r.scores[id] = score
		}
		r.matches[id] = append(r.matches[id], m)
	}
	r.ids = sortScores(r.scores)
	return r, nil
}
func fuse(parts ...*ranking) *ranking {
	r := emptyRanking()
	for _, p := range parts {
		for i, id := range p.ids {
			r.scores[id] += 1 / float64(61+i)
			r.matches[id] = append(r.matches[id], p.matches[id]...)
		}
	}
	r.ids = sortScores(r.scores)
	return r
}
func (s *store) weight(r *ranking, candidates map[string]candidate, a *arguments) (map[string]object, error) {
	moment := time.Now().UTC()
	var e error
	if a.get("now") != "" {
		moment, e = timestamp(a.get("now"), "now")
		if e != nil {
			return nil, e
		}
	}
	lives := map[string]float64{}
	for _, k := range strings.Fields(kinds + " lane_record") {
		lives[k] = 60
	}
	for _, k := range strings.Fields("lane_record ledger report board bulletin") {
		lives[k] = 14
	}
	for _, override := range a.values["half-life"] {
		parts := strings.SplitN(override, "=", 2)
		if len(parts) != 2 || parts[0] == "owner-decision" {
			return nil, invalid("half-life must be KIND=DAYS; owner-decision never decays")
		}
		if _, ok := lives[parts[0]]; !ok {
			return nil, invalid("half-life must be KIND=DAYS; owner-decision never decays")
		}
		n, e := strconv.ParseFloat(parts[1], 64)
		if e != nil || n <= 0 || math.IsNaN(n) || math.IsInf(n, 0) {
			return nil, invalid("half-life days must be a positive finite number")
		}
		lives[parts[0]] = n
	}
	events, e := s.feedback()
	if e != nil {
		return nil, e
	}
	byID := map[string][]object{}
	for _, event := range events {
		t, e := timestamp(event["at"], "feedback.at")
		if e != nil {
			return nil, integrity(e.Error())
		}
		if !t.After(moment) {
			byID[str(event["case_id"])] = append(byID[str(event["case_id"])], event)
		}
	}
	details := map[string]object{}
	scores := map[string]float64{}
	for _, id := range r.ids {
		c := candidates[id]
		if c.record["status"] == "superseded" {
			continue
		}
		kind := str(c.record["kind"])
		field := "answered_at"
		if c.lane {
			kind = "lane_record"
			field = "created_utc"
		}
		created, e := timestamp(c.record[field], "case time")
		if e != nil {
			return nil, e
		}
		seconds := float64(moment.Unix()-created.Unix()) + float64(moment.Nanosecond()-created.Nanosecond())/1e9
		age := math.Max(0, seconds/86400)
		life := lives[kind]
		recency := 1.0
		var halfLife any = life
		if kind == "owner-decision" {
			halfLife = nil
		} else {
			recency = math.Exp2(-math.Min(age/life, 1022))
		}
		rewards := byID[id]
		if rewards == nil {
			rewards = []object{}
		}
		reward := 0
		negative := false
		for _, event := range rewards {
			if member(str(event["event"]), "abandoned refusal") {
				reward--
				negative = true
			} else {
				reward++
			}
		}
		outcome := math.Exp2(math.Max(-8, math.Min(8, float64(reward))))
		relevance := math.Max(0, r.scores[id])
		scores[id] = relevance * recency * outcome
		details[id] = object{"relevance": relevance, "recency": recency, "outcome": outcome, "half_life_days": halfLife, "as_of": iso(moment, true), "feedback": rewards, "do_not_repeat": negative}
	}
	r.scores = scores
	r.ids = sortScores(scores)
	return details, nil
}
func (s *store) search(a *arguments) ([]object, error) {
	if a.get("scope") == "own-or-level" && (!a.has("level") || !a.has("instance")) {
		return nil, invalid("own-or-level scope requires both level and instance")
	}
	if a.get("rank") != "time" && (a.get("now") != "" || len(a.values["half-life"]) > 0) {
		return nil, invalid("now and half-life require --rank time")
	}
	candidates, e := s.candidates(a)
	if e != nil {
		return nil, e
	}
	query := a.positionals[0]
	if !utf8.ValidString(query) || strings.ContainsRune(query, 0) {
		return nil, invalid("query must be text without NUL")
	}
	mode := a.get("mode")
	r := emptyRanking()
	if mode == "exact" {
		for id, c := range candidates {
			if !c.lane && (query == "" || query == id) {
				r.scores[id] = 1
				r.matches[id] = []object{{"id": id, "index": "exact", "text": "question", "field": "id", "score": 1.0}}
			}
		}
		r.ids = sortScores(r.scores)
	} else {
		keyword := emptyRanking()
		if mode == "keyword" && a.get("rank") == "time" && trimmed(query) == "" {
			for id, c := range candidates {
				side, field := "question", "id"
				if c.lane {
					side, field = "lane", "lane_id"
				}
				keyword.scores[id] = 1
				keyword.matches[id] = []object{{"id": id, "index": "keyword:history", "text": side, "field": field, "score": 1.0}}
			}
			keyword.ids = sortScores(keyword.scores)
		} else if mode == "keyword" || mode == "hybrid" {
			keyword, e = s.keywordRanking(query, candidates)
			if e != nil {
				return nil, e
			}
		}
		r = keyword
		if mode == "vector" || mode == "hybrid" {
			p, e := providerFromConfig(a.get("config"))
			if e != nil {
				return nil, e
			}
			if trimmed(query) == "" {
				return nil, invalid("vector and hybrid queries cannot be empty")
			}
			vector, e := s.vectorRanking(query, candidates, p)
			if e != nil {
				return nil, e
			}
			r = vector
			if mode == "hybrid" {
				r = fuse(keyword, vector)
			}
		}
	}
	var details map[string]object
	if a.get("rank") == "time" {
		details, e = s.weight(r, candidates, a)
		if e != nil {
			return nil, e
		}
	}
	limit, _ := strconv.Atoi(a.get("limit"))
	if limit > len(r.ids) {
		limit = len(r.ids)
	}
	selected := r.ids[:limit]
	cautions, _ := strconv.Atoi(a.get("cautions"))
	if details != nil && cautions > 0 {
		reserved := map[string]bool{}
		for _, id := range r.ids {
			if details[id]["do_not_repeat"] == true && len(reserved) < cautions && len(reserved) < limit {
				reserved[id] = true
			}
		}
		chosen := map[string]bool{}
		for id := range reserved {
			chosen[id] = true
		}
		for _, id := range r.ids {
			if len(chosen) >= limit {
				break
			}
			chosen[id] = true
		}
		selected = []string{}
		for _, id := range r.ids {
			if chosen[id] {
				selected = append(selected, id)
			}
		}
	}
	hits := []object{}
	for _, id := range selected {
		evidence := r.matches[id]
		strongest := evidence[0]
		if mode == "hybrid" {
			for _, m := range evidence {
				if strings.HasPrefix(str(m["index"]), "vector:") {
					strongest = m
					break
				}
			}
		}
		matches := []object{}
		for _, m := range evidence {
			copy := object{}
			for k, v := range m {
				if k != "id" {
					copy[k] = v
				}
			}
			matches = append(matches, copy)
		}
		index := strongest["index"]
		if mode == "hybrid" {
			index = "hybrid"
		}
		hit := object{"score": r.scores[id], "index": index, "matched_text": strongest["text"], "matches": matches}
		if details != nil {
			hit["ranking"] = details[id]
			hit["do_not_repeat"] = details[id]["do_not_repeat"]
			if details[id]["do_not_repeat"] == true {
				hit["warning"] = "do not repeat"
			}
		}
		c := candidates[id]
		if c.lane {
			hit["lane_record"] = c.record
		} else {
			hit["record"] = c.record
		}
		hits = append(hits, hit)
	}
	return hits, nil
}
