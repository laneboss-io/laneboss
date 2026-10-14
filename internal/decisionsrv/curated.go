package decisionsrv

import (
	"context"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type curatedEntry struct {
	line int
	text string
}

var headingPattern = regexp.MustCompile(`^(#{1,6})\s+\S`)
var bulletPattern = regexp.MustCompile(`^(?:[-*+] |[0-9]+[.)] )`)
var boardRule = regexp.MustCompile(`^[\s|:\-]+$`)

func splitLines(text string) []string {
	lines := []string{}
	start := 0
	for at, r := range text {
		if at < start {
			continue
		}
		size := utf8.RuneLen(r)
		if r == '\n' || r == '\r' || r == '\v' || r == '\f' || r == 0x1c || r == 0x1d || r == 0x1e || r == 0x85 || r == 0x2028 || r == 0x2029 {
			end := at + size
			if r == '\r' && end < len(text) && text[end] == '\n' {
				end++
			}
			lines = append(lines, text[start:end])
			start = end
		}
	}
	if start < len(text) {
		lines = append(lines, text[start:])
	}
	return lines
}
func curatedEntries(text, kind string) []curatedEntry {
	lines := splitLines(text)
	out := []curatedEntry{}
	if kind == "board" {
		for i, line := range lines {
			if strings.TrimSpace(line) != "" && !headingPattern.MatchString(line) && !boardRule.MatchString(line) {
				out = append(out, curatedEntry{i + 1, line})
			}
		}
		return out
	}
	type heading struct{ at, depth int }
	headings := []heading{}
	plain := []int{}
	fenced := false
	for i, line := range lines {
		left := strings.TrimLeftFunc(line, unicode.IsSpace)
		if strings.HasPrefix(left, "```") || strings.HasPrefix(left, "~~~") {
			fenced = !fenced
		}
		if !fenced {
			match := headingPattern.FindStringSubmatch(line)
			if len(match) > 0 && len(match[1]) > 1 {
				headings = append(headings, heading{i, len(match[1])})
			}
			plain = append(plain, i)
		}
	}
	starts := []int{}
	if len(headings) > 0 {
		depth := 7
		for _, h := range headings {
			depth = min(depth, h.depth)
		}
		for _, h := range headings {
			if kind == "report" || h.depth == depth {
				starts = append(starts, h.at)
			}
		}
	} else {
		for _, i := range plain {
			if bulletPattern.MatchString(lines[i]) {
				starts = append(starts, i)
			}
		}
		if len(starts) == 0 {
			for i, line := range lines {
				if strings.TrimSpace(line) != "" && !headingPattern.MatchString(line) && (i == 0 || strings.TrimSpace(lines[i-1]) == "") {
					starts = append(starts, i)
				}
			}
		}
	}
	if len(starts) == 0 {
		return out
	}
	for _, line := range lines[:starts[0]] {
		if strings.TrimSpace(line) != "" && !headingPattern.MatchString(line) {
			starts = append([]int{0}, starts...)
			break
		}
	}
	starts = append(starts, len(lines))
	for i := 0; i+1 < len(starts); i++ {
		start, end := starts[i], starts[i+1]
		content := strings.Join(lines[start:end], "")
		if strings.TrimSpace(content) != "" {
			out = append(out, curatedEntry{start + 1, content})
		}
	}
	return out
}
func curatedCase(id, kind, text, source, created string, identity object, line int) (object, error) {
	lines := splitLines(text)
	if len(lines) == 0 {
		return nil, invalid("curated entry is empty")
	}
	question := kind
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			question = strings.TrimRight(l, "\r\n\v\f\x1c\x1d\x1e\u0085\u2028\u2029")
			break
		}
	}
	return validateRecord(object{"id": id, "kind": kind, "asked_at": created, "answered_at": created, "project": "org-history", "area": kind, "topics": []any{kind}, "question": object{"text": question, "background": "Curated org history"}, "answer": object{"verbatim": text, "channel": source}, "scope": object{"applies_to": "This org"}, "status": "in_force", "level": identity["level"], "instance": identity["instance"], "provenance": object{"recorded_by": identity["instance"], "recorded_at": utcNow(), "sources": []any{object{"path": source, "line": line, "sha256_of_line": digest(lines[0]), "line_text": lines[0]}}}})
}
func citationWord(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsNumber(r) || r == '_' || strings.ContainsRune("./:-", r)
}
func containsCitation(text, id string) bool {
	offset := 0
	for offset <= len(text) {
		at := strings.Index(text[offset:], id)
		if at < 0 {
			return false
		}
		at += offset
		end := at + len(id)
		left, right := false, false
		if at > 0 {
			r, _ := utf8.DecodeLastRuneInString(text[:at])
			left = citationWord(r)
		}
		if end < len(text) {
			r, _ := utf8.DecodeRuneInString(text[end:])
			right = citationWord(r)
		}
		if !left && !right {
			return true
		}
		offset = at + 1
	}
	return false
}
func citations(ctx context.Context, w sqlWriter, o *orgContext, text, source, created string, identity object) ([]string, error) {
	receipts, e := recentInjections(o)
	if e != nil {
		return nil, e
	}
	moment, e := timestamp(created, "citation time")
	if e != nil {
		return nil, e
	}
	cited := map[string]bool{}
	for _, receipt := range receipts {
		if receipt["instance"] != identity["instance"] {
			continue
		}
		at, e := timestamp(receipt["at"], "injection time")
		if e != nil {
			return nil, e
		}
		if at.After(moment) {
			continue
		}
		ids, _ := receipt["ids"].([]any)
		for _, v := range ids {
			id := str(v)
			if id != "" && !cited[id] && containsCitation(text, id) {
				if _, e = appendFeedback(ctx, w, id, "cited", source, created); e != nil {
					return nil, e
				}
				cited[id] = true
			}
		}
	}
	ids := []string{}
	for id := range cited {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}
func ingestRecords(args options) (object, error) {
	o, e := openOrg(args.get("org-dir"))
	if e != nil {
		return nil, e
	}
	if e = o.checkStore(args.get("db")); e != nil {
		return nil, e
	}
	identity, _, _, e := o.instance(args.get("instance"))
	if e != nil {
		return nil, e
	}
	kind := args.get("kind")
	if kind == "" {
		kind = "ledger"
	}
	if !wordsSet("ledger report board bulletin")[kind] {
		return nil, invalid("kind is not a supported curated kind")
	}
	text, e := readRegular(args.get("file"), maxTextBytes)
	if e != nil {
		return nil, e
	}
	pieces := curatedEntries(text, kind)
	if len(pieces) == 0 {
		return nil, invalid("curated file has no entries")
	}
	source, e := realPath(args.get("file"))
	if e != nil {
		return nil, e
	}
	info, e := os.Stat(source)
	if e != nil {
		return nil, invalid("cannot read curated source time")
	}
	fallback := info.ModTime().UTC().Format("2006-01-02T15:04:05.000000+00:00")
	records := []object{}
	for _, piece := range pieces {
		created := stampInText.FindString(splitLines(piece.text)[0])
		if created == "" {
			created = fallback
		}
		h, e := canonicalHash(object{"kind": kind, "instance": args.get("instance"), "content": piece.text})
		if e != nil {
			return nil, e
		}
		record, e := curatedCase("C-"+h, kind, piece.text, source, created, identity, piece.line)
		if e != nil {
			return nil, e
		}
		records = append(records, record)
	}
	db, e := openStore(args.get("db"), false, 10*time.Second)
	if e != nil {
		return nil, e
	}
	defer db.Close()
	added, existing := 0, 0
	ids := []string{}
	cited := []string{}
	ctx := context.Background()
	e = writeTransaction(ctx, db, func(w sqlWriter) error {
		for _, record := range records {
			rows, e := readRows(ctx, w, "SELECT * FROM records WHERE id = ?", record["id"])
			if e != nil {
				return e
			}
			if len(rows) > 0 {
				prior, e := checkedRecord(rows[0])
				if e != nil {
					return e
				}
				if obj(prior["answer"])["verbatim"] != obj(record["answer"])["verbatim"] || prior["instance"] != identity["instance"] || !equalValue(prior["level"], identity["level"]) || prior["kind"] != kind {
					return invalid("curated content id conflicts with a stored case")
				}
				existing++
			} else {
				if e = insertRecord(ctx, w, record); e != nil {
					return e
				}
				added++
			}
			ids = append(ids, str(record["id"]))
		}
		var e error
		cited, e = citations(ctx, w, o, text, "curated:"+source+":"+digest(text), fallback, identity)
		return e
	})
	if e != nil {
		return nil, e
	}
	return object{"rows_added": added, "rows_existing": existing, "ids": ids, "cited": cited, "level": identity["level"], "instance": identity["instance"]}, nil
}
