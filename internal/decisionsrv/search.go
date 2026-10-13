package decisionsrv

import (
	"context"
	"database/sql"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type pair struct{ name, value string }
type searchArguments struct {
	query, mode, id, project, area, topic, kind, dateFrom, dateTo, instance, scope, rank, now string
	status, halfLife                                                                          []string
	limit, level, cautions                                                                    int
	all                                                                                       bool
	idSet, projectSet, areaSet, topicSet, instanceSet, dateFromSet, dateToSet                 bool
}

func (a searchArguments) key() object {
	return object{"query": a.query, "mode": a.mode, "id": a.id, "project": a.project, "area": a.area, "topic": a.topic, "kind": a.kind, "date-from": a.dateFrom, "date-to": a.dateTo, "instance": a.instance, "scope": a.scope, "rank": a.rank, "now": a.now, "status": a.status, "half-life": a.halfLife, "limit": a.limit, "level": a.level, "cautions": a.cautions, "all": a.all, "given": []bool{a.idSet, a.projectSet, a.areaSet, a.topicSet, a.instanceSet, a.dateFromSet, a.dateToSet}}
}
func parseSearch(pairs []pair) (searchArguments, error) {
	a := searchArguments{mode: "keyword", limit: 20, scope: "intersection", rank: "relevance"}
	taken := map[string]bool{}
	query := false
	for _, p := range pairs {
		k, v := p.name, p.value
		switch k {
		case "from", "since":
			k = "date-from"
		case "to", "until":
			k = "date-to"
		}
		if taken[k] && k != "status" && k != "half-life" {
			return a, invalid("parameter given twice: " + k)
		}
		taken[k] = true
		switch k {
		case "query":
			a.query = v
			query = true
		case "mode":
			if !wordsSet("exact keyword vector hybrid")[v] {
				return a, invalid("mode is not a supported choice")
			}
			a.mode = v
		case "id":
			a.id = v
			a.idSet = true
		case "project":
			a.project = v
			a.projectSet = true
		case "area":
			a.area = v
			a.areaSet = true
		case "topic":
			a.topic = v
			a.topicSet = true
		case "kind":
			if !kinds[v] && v != "lane_record" {
				return a, invalid("kind is not a supported choice")
			}
			a.kind = v
		case "status":
			if !statuses[v] {
				return a, invalid("status is not a supported choice")
			}
			a.status = append(a.status, v)
		case "date-from":
			a.dateFrom = v
			a.dateFromSet = true
		case "date-to":
			a.dateTo = v
			a.dateToSet = true
		case "limit", "level", "cautions":
			n, e := strconv.Atoi(v)
			if e != nil || n < 1 {
				return a, invalid(k + " must be a positive integer")
			}
			if k == "level" && (n < 3 || n > 6) {
				return a, invalid("level must be an integer from 3 to 6")
			}
			switch k {
			case "limit":
				a.limit = n
			case "level":
				a.level = n
			case "cautions":
				a.cautions = n
			}
		case "all":
			if v != "1" && v != "true" {
				return a, invalid("all must be 1")
			}
			a.all = true
		case "instance":
			a.instance = v
			a.instanceSet = true
		case "scope":
			if v != "intersection" && v != "own-or-level" {
				return a, invalid("scope is not a supported choice")
			}
			a.scope = v
		case "rank":
			if v != "relevance" && v != "time" {
				return a, invalid("rank is not a supported choice")
			}
			a.rank = v
		case "now":
			a.now = v
		case "half-life":
			a.halfLife = append(a.halfLife, v)
		default:
			return a, invalid("unknown parameter: " + k)
		}
	}
	if !query {
		return a, invalid("query is required")
	}
	return a, nil
}
func dateBound(v string, upper bool) (time.Time, bool, error) {
	if v == "" {
		return time.Time{}, false, nil
	}
	if len(v) == 10 {
		t, e := time.Parse("2006-01-02", v)
		if e != nil || t.Year() < 1 {
			return time.Time{}, false, invalid("invalid search date")
		}
		if upper {
			t = t.AddDate(0, 0, 1)
			if t.Year() > 9999 {
				return time.Time{}, false, invalid("invalid search date")
			}
		}
		return t, true, nil
	}
	t, e := timestamp(v, "search date")
	return t, true, e
}
func scopeMatches(r object, a searchArguments) bool {
	l, ok := integer(r["level"])
	sameLevel := ok && l == int64(a.level)
	sameInstance := r["instance"] == a.instance
	if a.scope == "own-or-level" {
		return sameLevel || sameInstance
	}
	return (a.level == 0 || sameLevel) && (!a.instanceSet || sameInstance)
}
func hasString(a []string, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}
func hasTopic(r object, topic string) bool {
	if topic == "" {
		return true
	}
	a, _ := r["topics"].([]any)
	for _, v := range a {
		if v == topic {
			return true
		}
	}
	return false
}
func filteredCases(s *snapshot, a searchArguments) (map[string]storedCase, map[string]storedCase, error) {
	if (a.dateFromSet && a.dateFrom == "") || (a.dateToSet && a.dateTo == "") {
		return nil, nil, invalid("search date must be an ISO 8601 timestamp with offset")
	}
	start, from, e := dateBound(a.dateFrom, false)
	if e != nil {
		return nil, nil, e
	}
	end, to, e := dateBound(a.dateTo, true)
	if e != nil {
		return nil, nil, e
	}
	exclusive := len(a.dateTo) == 10
	if from && to && (start.After(end) || (exclusive && start.Equal(end))) {
		return nil, nil, invalid("date-from must not be after date-to")
	}
	if s.damage != nil {
		return nil, nil, s.damage
	}
	eligible := map[string]storedCase{}
	lanes := map[string]storedCase{}
	for _, c := range s.records {
		r := c.record
		if !scopeMatches(r, a) {
			continue
		}
		if len(a.status) > 0 {
			if !hasString(a.status, str(r["status"])) {
				continue
			}
		} else if !a.all && r["status"] != "in_force" && r["status"] != "fulfilled" {
			continue
		}
		if (a.idSet && r["id"] != a.id) || (a.projectSet && r["project"] != a.project) || (a.areaSet && r["area"] != a.area) || (a.kind != "" && r["kind"] != a.kind) || (a.topicSet && (a.topic == "" || !hasTopic(r, a.topic))) {
			continue
		}
		if from && c.answered.Before(start) {
			continue
		}
		if to && (c.answered.After(end) || (exclusive && c.answered.Equal(end))) {
			continue
		}
		eligible[str(r["id"])] = c
	}
	if a.mode == "keyword" && (a.kind == "" || a.kind == "lane_record") && !a.idSet && !a.projectSet && !a.areaSet && !a.topicSet && len(a.status) == 0 && !a.dateFromSet && !a.dateToSet {
		if s.laneDamage != nil {
			return nil, nil, s.laneDamage
		}
		for _, c := range s.lanes {
			if scopeMatches(c.record, a) {
				lanes[str(c.record["id"])] = c
			}
		}
	}
	return eligible, lanes, nil
}

type match struct {
	id, index, side, field string
	score                  float64
	termRank               int
}

func (m match) json() object {
	return object{"index": m.index, "text": m.side, "field": m.field, "score": m.score}
}

type ranked struct {
	order    []string
	evidence map[string][]match
	scores   map[string]float64
}

func newRanked() *ranked {
	return &ranked{order: []string{}, evidence: map[string][]match{}, scores: map[string]float64{}}
}
func (r *ranked) sort() {
	r.order = r.order[:0]
	for id := range r.scores {
		r.order = append(r.order, id)
	}
	sort.Slice(r.order, func(i, j int) bool {
		a, b := r.order[i], r.order[j]
		if r.scores[a] == r.scores[b] {
			return a < b
		}
		return r.scores[a] > r.scores[b]
	})
}
func quoted(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }
func sameFTSTerm(a, b string) (bool, error) {
	if a == b {
		return true, nil
	}
	if utf8.RuneCountInString(a) != utf8.RuneCountInString(b) {
		return false, nil
	}
	db, e := sql.Open("sqlite", ":memory:")
	if e != nil {
		return false, databaseError(e, true)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, e = db.Exec("CREATE VIRTUAL TABLE fold USING fts5(text, tokenize='trigram')"); e != nil {
		return false, databaseError(e, true)
	}
	if _, e = db.Exec("INSERT INTO fold(rowid,text) VALUES (1,?),(2,?)", a, b); e != nil {
		return false, databaseError(e, true)
	}
	var count int
	e = db.QueryRow("SELECT count(*) FROM fold WHERE (fold MATCH ? AND rowid=2)", quoted(a)).Scan(&count)
	if e != nil || count == 0 {
		return false, databaseError(e, true)
	}
	e = db.QueryRow("SELECT count(*) FROM fold WHERE fold MATCH ? AND rowid=1", quoted(b)).Scan(&count)
	return count > 0, databaseError(e, true)
}
func distinctTerms(query string) ([]string, error) {
	kept := []string{}
	short := map[string]bool{}
	long := []string{}
	for _, term := range strings.Fields(query) {
		if utf8.RuneCountInString(term) < 3 {
			f := casefold(term)
			if short[f] {
				continue
			}
			short[f] = true
		} else {
			duplicate := false
			for _, old := range long {
				same, e := sameFTSTerm(term, old)
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
		kept = append(kept, term)
	}
	return kept, nil
}
func termMatches(ctx context.Context, s *snapshot, term string, eligible, lanes map[string]storedCase) ([]match, error) {
	matches := []match{}
	columns := []struct{ name, side string }{{"id", "question"}, {"q_text", "question"}, {"d_text", "decision"}}
	if utf8.RuneCountInString(term) < 3 {
		fold := casefold(term)
		for id, c := range eligible {
			for _, col := range columns {
				count := strings.Count(casefold(str(c.row[col.name])), fold)
				if count > 0 {
					matches = append(matches, match{id, "keyword:substring", col.side, col.name, float64(count), 0})
				}
			}
		}
		for id, c := range lanes {
			for _, col := range []string{"id", "text"} {
				count := strings.Count(casefold(str(c.row[col])), fold)
				if count > 0 {
					matches = append(matches, match{id, "keyword:substring", "lane", "lane_" + col, float64(count), 0})
				}
			}
		}
		return matches, nil
	}
	for _, col := range columns {
		rows, e := readRows(ctx, s.db, "SELECT id,bm25(keyword_index) AS score FROM keyword_index WHERE keyword_index MATCH ? ORDER BY score,id", col.name+" : "+quoted(term))
		if e != nil {
			return nil, e
		}
		for _, row := range rows {
			if _, ok := eligible[str(row["id"])]; ok {
				n, _ := number(row["score"])
				matches = append(matches, match{str(row["id"]), "keyword:fts5", col.side, col.name, -n, 0})
			}
		}
	}
	for _, col := range []string{"id", "text"} {
		rows, e := readRows(ctx, s.db, "SELECT id,bm25(lane_keyword_index) AS score FROM lane_keyword_index WHERE lane_keyword_index MATCH ? ORDER BY score,id", col+" : "+quoted(term))
		if e != nil {
			return nil, e
		}
		for _, row := range rows {
			if _, ok := lanes[str(row["id"])]; ok {
				n, _ := number(row["score"])
				matches = append(matches, match{str(row["id"]), "keyword:fts5", "lane", "lane_" + col, -n, 0})
			}
		}
	}
	return matches, nil
}

// Error-free partial summation supplies the same rounding as math.fsum.
func accurateSum(values []float64) float64 {
	partials := []float64{}
	for _, v := range values {
		x := v
		at := 0
		for _, y := range partials {
			if math.Abs(x) < math.Abs(y) {
				x, y = y, x
			}
			hi := x + y
			lo := y - (hi - x)
			if lo != 0 {
				if at < len(partials) {
					partials[at] = lo
				} else {
					partials = append(partials, lo)
				}
				at++
			}
			x = hi
		}
		partials = append(partials[:at], x)
	}
	n := len(partials)
	if n == 0 {
		return 0
	}
	n--
	hi := partials[n]
	lo := 0.0
	for n > 0 {
		x := hi
		n--
		y := partials[n]
		hi = x + y
		lo = y - (hi - x)
		if lo != 0 {
			break
		}
	}
	if n > 0 && ((lo < 0 && partials[n-1] < 0) || (lo > 0 && partials[n-1] > 0)) {
		y := lo * 2
		x := hi + y
		if y == x-hi {
			hi = x
		}
	}
	return hi
}
func keywordRanking(ctx context.Context, s *snapshot, query string, eligible, lanes map[string]storedCase) (*ranked, error) {
	r := newRanked()
	terms, e := distinctTerms(query)
	if e != nil {
		return nil, e
	}
	if len(terms) == 0 {
		return r, nil
	}
	common := map[string]bool{}
	for id := range eligible {
		common[id] = true
	}
	for id := range lanes {
		common[id] = true
	}
	perTerm := [][]match{}
	for _, term := range terms {
		matches, e := termMatches(ctx, s, term, eligible, lanes)
		if e != nil {
			return nil, e
		}
		if len(matches) == 0 {
			return r, nil
		}
		present := map[string]bool{}
		for _, m := range matches {
			present[m.id] = true
		}
		for id := range common {
			if !present[id] {
				delete(common, id)
			}
		}
		perTerm = append(perTerm, matches)
	}
	contributions := map[string][]float64{}
	for _, matches := range perTerm {
		best := map[string]float64{}
		for _, m := range matches {
			if common[m.id] {
				v, ok := best[m.id]
				if !ok || m.score > v {
					best[m.id] = m.score
				}
			}
		}
		ids := []string{}
		for id := range best {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool {
			if best[ids[i]] == best[ids[j]] {
				return ids[i] < ids[j]
			}
			return best[ids[i]] > best[ids[j]]
		})
		ranks := map[string]int{}
		rank := 0
		previous := math.NaN()
		for i, id := range ids {
			if best[id] != previous {
				rank = i + 1
				previous = best[id]
			}
			ranks[id] = rank
			contributions[id] = append(contributions[id], 1.0/float64(60+rank))
		}
		for _, m := range matches {
			if common[m.id] {
				m.termRank = ranks[m.id]
				r.evidence[m.id] = append(r.evidence[m.id], m)
			}
		}
	}
	for id, values := range contributions {
		r.scores[id] = accurateSum(values)
		sort.SliceStable(r.evidence[id], func(i, j int) bool {
			a, b := r.evidence[id][i], r.evidence[id][j]
			if a.termRank != b.termRank {
				return a.termRank < b.termRank
			}
			if a.score != b.score {
				return a.score > b.score
			}
			if a.side != b.side {
				return a.side < b.side
			}
			if a.field != b.field {
				return a.field < b.field
			}
			return a.index < b.index
		})
	}
	r.sort()
	return r, nil
}
func vectorNorm(v []float64) float64 {
	return math.Sqrt(exactDot(v, v))
}
func exactDot(left, right []float64) float64 {
	sum := 0.0
	for i := 0; i < min(len(left), len(right)); i++ {
		product := float64(left[i] * right[i])
		sum += product
	}
	return sum
}
func rankVectorEntries(model string, candidates []vectorEntry, query []float64) *ranked {
	out := newRanked()
	norm := vectorNorm(query)
	for _, entry := range candidates {
		score := math.Max(-1, math.Min(1, exactDot(query, entry.vector)/(norm*entry.norm)))
		side := "question"
		if entry.side == "d_text" {
			side = "decision"
		}
		out.evidence[entry.id] = append(out.evidence[entry.id], match{entry.id, "vector:" + model, side, entry.side, score, 0})
	}
	for id, matches := range out.evidence {
		sort.SliceStable(matches, func(i, j int) bool {
			if matches[i].score == matches[j].score {
				return matches[i].side < matches[j].side
			}
			return matches[i].score > matches[j].score
		})
		out.scores[id] = matches[0].score
	}
	out.sort()
	return out
}
func vectorRanking(s *snapshot, r *resident, query string, eligible map[string]storedCase, p *embeddingProvider) (*ranked, error) {
	out := newRanked()
	table := s.table(p)
	if table.err != nil {
		return nil, table.err
	}
	candidates := []vectorEntry{}
	for _, entry := range table.entries {
		if _, ok := eligible[entry.id]; ok {
			candidates = append(candidates, entry)
		}
	}
	if len(candidates) == 0 {
		return out, nil
	}
	q, e := r.queryVector(p, query)
	if e != nil {
		return nil, e
	}
	return rankVectorEntries(p.model, candidates, q), nil
}
func fused(parts ...*ranked) *ranked {
	out := newRanked()
	for _, p := range parts {
		for i, id := range p.order {
			out.scores[id] += 1.0 / float64(61+i)
			out.evidence[id] = append(out.evidence[id], p.evidence[id]...)
		}
	}
	out.sort()
	return out
}
func halfLives(overrides []string) (map[string]float64, error) {
	lives := map[string]float64{}
	for kind := range kinds {
		lives[kind] = 60
	}
	for _, kind := range []string{"lane_record", "ledger", "report", "board", "bulletin"} {
		lives[kind] = 14
	}
	lives["owner-decision"] = 0
	for _, given := range overrides {
		k, v, ok := strings.Cut(given, "=")
		if !ok || k == "owner-decision" {
			return nil, invalid("half-life must be KIND=DAYS; owner-decision never decays")
		}
		if _, ok = lives[k]; !ok {
			return nil, invalid("half-life must be KIND=DAYS; owner-decision never decays")
		}
		n, e := strconv.ParseFloat(v, 64)
		if e != nil || !finite(n) || n <= 0 {
			return nil, invalid("half-life days must be a positive finite number")
		}
		lives[k] = n
	}
	return lives, nil
}
func weighted(ctx context.Context, s *snapshot, result *ranked, eligible, lanes map[string]storedCase, a searchArguments) (*ranked, map[string]object, error) {
	moment := time.Now().UTC().Truncate(time.Microsecond)
	var e error
	if a.now != "" {
		moment, e = timestamp(a.now, "now")
		if e != nil {
			return nil, nil, e
		}
	}
	lives, e := halfLives(a.halfLife)
	if e != nil {
		return nil, nil, e
	}
	events := map[string][]any{}
	rows, e := readRows(ctx, s.db, "SELECT * FROM feedback ORDER BY id")
	if e != nil {
		return nil, nil, e
	}
	for _, row := range rows {
		event, e := checkedFeedback(row)
		if e != nil {
			return nil, nil, e
		}
		at, e := timestamp(event["at"], "feedback.at")
		if e != nil {
			return nil, nil, e
		}
		if !at.After(moment) {
			id := str(event["case_id"])
			events[id] = append(events[id], event)
		}
	}
	out := newRanked()
	details := map[string]object{}
	for _, id := range result.order {
		c, ok := eligible[id]
		if !ok {
			c = lanes[id]
		}
		if c.record["status"] == "superseded" {
			continue
		}
		kind := str(c.record["kind"])
		if kind == "" {
			kind = "lane_record"
		}
		seconds := float64(moment.Unix()-c.answered.Unix()) + float64(moment.Nanosecond()-c.answered.Nanosecond())/1e9
		age := math.Max(0, seconds/86400)
		life := lives[kind]
		recency := 1.0
		var printedLife any
		if life != 0 {
			printedLife = life
			recency = math.Exp2(-math.Min(age/life, 1022))
		}
		reward := 0
		negative := false
		rewards := events[id]
		if rewards == nil {
			rewards = []any{}
		}
		for _, event := range rewards {
			n := feedbackEvents[str(obj(event)["event"])]
			reward += n
			negative = negative || n < 0
		}
		outcome := math.Exp2(math.Max(-8, math.Min(8, float64(reward))))
		relevance := math.Max(0, result.scores[id])
		out.scores[id] = relevance * recency * outcome
		out.evidence[id] = result.evidence[id]
		details[id] = object{"relevance": relevance, "recency": recency, "outcome": outcome, "half_life_days": printedLife, "as_of": moment.Format("2006-01-02T15:04:05.000000+00:00"), "feedback": rewards, "do_not_repeat": negative}
	}
	out.sort()
	return out, details, nil
}
func searchSnapshot(ctx context.Context, s *snapshot, r *resident, a searchArguments, p *embeddingProvider) ([]object, error) {
	if a.scope == "own-or-level" && (a.level == 0 || !a.instanceSet) {
		return nil, invalid("own-or-level scope requires both level and instance")
	}
	if a.rank != "time" && (a.now != "" || len(a.halfLife) > 0) {
		return nil, invalid("now and half-life require --rank time")
	}
	eligible, lanes, e := filteredCases(s, a)
	if e != nil {
		return nil, e
	}
	if strings.ContainsRune(a.query, 0) || !utf8.ValidString(a.query) {
		return nil, invalid("query must be text without NUL")
	}
	result := newRanked()
	if a.mode == "exact" {
		for id := range eligible {
			if a.query == "" || id == a.query {
				result.scores[id] = 1
				result.evidence[id] = []match{{id, "exact", "question", "id", 1, 0}}
			}
		}
		result.sort()
	} else {
		var keyword, vector *ranked
		if a.mode == "keyword" && a.rank == "time" && strings.TrimSpace(a.query) == "" {
			keyword = newRanked()
			for id := range eligible {
				keyword.scores[id] = 1
				keyword.evidence[id] = []match{{id, "keyword:history", "question", "id", 1, 0}}
			}
			for id := range lanes {
				keyword.scores[id] = 1
				keyword.evidence[id] = []match{{id, "keyword:history", "lane", "lane_id", 1, 0}}
			}
			keyword.sort()
		} else if a.mode == "keyword" || a.mode == "hybrid" {
			keyword, e = keywordRanking(ctx, s, a.query, eligible, lanes)
			if e != nil {
				return nil, e
			}
		}
		if a.mode == "vector" || a.mode == "hybrid" {
			if p == nil {
				p, e = providerFromConfig(r.config)
				if e != nil {
					return nil, e
				}
			}
			if strings.TrimSpace(a.query) == "" {
				return nil, invalid("vector and hybrid queries cannot be empty")
			}
			vector, e = vectorRanking(s, r, a.query, eligible, p)
			if e != nil {
				return nil, e
			}
		}
		switch a.mode {
		case "keyword":
			result = keyword
		case "vector":
			result = vector
		case "hybrid":
			result = fused(keyword, vector)
		}
	}
	var details map[string]object
	if a.rank == "time" {
		result, details, e = weighted(ctx, s, result, eligible, lanes, a)
		if e != nil {
			return nil, e
		}
	}
	selected := result.order[:min(a.limit, len(result.order))]
	if details != nil && a.cautions > 0 {
		reserved := []string{}
		for _, id := range result.order {
			if details[id]["do_not_repeat"] == true {
				reserved = append(reserved, id)
				if len(reserved) >= min(a.cautions, a.limit) {
					break
				}
			}
		}
		chosen := map[string]bool{}
		for _, id := range reserved {
			chosen[id] = true
		}
		for _, id := range result.order {
			if len(chosen) >= a.limit {
				break
			}
			chosen[id] = true
		}
		selected = []string{}
		for _, id := range result.order {
			if chosen[id] {
				selected = append(selected, id)
			}
		}
	}
	hits := []object{}
	for _, id := range selected {
		evidence := result.evidence[id]
		strongest := evidence[0]
		if a.mode == "hybrid" {
			for _, m := range evidence {
				if strings.HasPrefix(m.index, "vector:") {
					strongest = m
					break
				}
			}
		}
		index := strongest.index
		if a.mode == "hybrid" {
			index = "hybrid"
		}
		matches := []object{}
		for _, m := range evidence {
			matches = append(matches, m.json())
		}
		hit := object{"score": result.scores[id], "index": index, "matched_text": strongest.side, "matches": matches}
		if details != nil {
			hit["ranking"] = details[id]
			hit["do_not_repeat"] = details[id]["do_not_repeat"]
			if hit["do_not_repeat"] == true {
				hit["warning"] = "do not repeat"
			}
		}
		if c, ok := eligible[id]; ok {
			hit["record"] = c.record
		} else {
			hit["lane_record"] = lanes[id].record
		}
		hits = append(hits, hit)
	}
	return hits, nil
}
