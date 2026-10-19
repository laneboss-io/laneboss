package laneturns

import (
	"strings"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/decisionsrv"
	"laneboss.io/laneboss/internal/rolepolicy"
)

// decidedQuestion answers a question from the org's recorded decisions (docs/decisions.md, "Guiding agents"). It returns
// the result to print when a decision of the asking lane's project and level already answers the question. Otherwise it
// returns nil and the check that was made: "related" lists the decisions that the judge scored as bearing on the
// question, and "judge" says what became of the judge, so that a question that went unchecked is never taken for one that
// was checked. A failure to read the decisions never stops the message: it is sent as it always is, and "judge" says so.
func decidedQuestion(c *configuration, a arguments, data []byte, sender caller.Principal) (object, object) {
	check := object{"judge": "no-org", "related": []any{}}
	root, err := rolepolicy.ConfigRoot(c.home, c.data)
	if err != nil || root == "" {
		return nil, check
	}
	g, err := decisionsrv.OpenGuide(root)
	if err != nil {
		check["judge"] = "store-error"
		return nil, check
	}
	project, level, known := askerScope(c, sender, a.get("lane"))
	if !known {
		// A lane that the configuration does not know cannot be asked: sendMessage says so, and nothing is answered here.
		check["judge"] = "no-lane"
		return nil, check
	}
	answer, err := g.AnswerFor(string(data), project, level)
	if err != nil {
		check["judge"] = "store-error"
		return nil, check
	}
	related := []any{}
	holds := func(text string) bool {
		rule, _ := findCredential(text)
		return rule != ""
	}
	for _, item := range answer.Related {
		related = append(related, object{"id": decisionsrv.SafeEchoLabel(item.Decision.ID, holds), "score": item.Score})
	}
	check["judge"], check["related"] = answer.Judge, related
	if answer.Decided == nil {
		return nil, check
	}
	d, withheld := answer.Decided.Decision.ScreenedEcho(holds)
	return object{
		"lane": a.get("lane"), "decided": true, "sent": false, "match": answer.Decided.Match, "score": answer.Decided.Score,
		"withheld": withheld,
		"judge":    answer.Judge, "related": related,
		"decision": object{"id": d.ID, "kind": d.Kind, "project": d.Project, "answered_at": d.AnsweredAt, "question": d.Question, "answer": d.Answer},
	}, check
}

// askerScope is the project and level whose decisions can answer the question: those of the lane that asks. That is the
// authenticated sending lane, else the lane that receives the message. A lane
// sender whose latest record is unreadable has no scope; it cannot fall back
// to the target. known requires both a known target and a readable scope.
func askerScope(c *configuration, sender caller.Principal, target string) (project string, level int, known bool) {
	s, err := openSession(c, false)
	if err != nil {
		return "", 0, false
	}
	defer s.close()
	if s.state == nil {
		return "", 0, false
	}
	_, err = s.known(target)
	if err != nil {
		return "", 0, false
	}
	lane := target
	if strings.HasPrefix(sender.ID, "lane:") {
		lane = strings.TrimPrefix(sender.ID, "lane:")
	}
	if !lanePattern.MatchString(lane) {
		return "", 0, false
	}
	if _, err = s.known(lane); err != nil {
		return "", 0, false
	}
	previous, err := s.latest(lane)
	if err != nil || previous == nil {
		return "", 0, false
	}
	if context := obj(previous["role_context"]); context != nil {
		level = integer(context["level"])
	}
	return str(previous["project"]), level, true
}
