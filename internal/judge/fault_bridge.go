//go:build laneboss_faults

package judge

import (
	"encoding/json"
	"fmt"
	"io"
)

// OwnerProbe supplies a real foreign state to the shared ask path, before it
// can record ownership, create a judges directory, append a log or run a judge.
func OwnerProbe(stdin io.Reader, stdout, stderr io.Writer) int {
	var input struct {
		State    string            `json:"state"`
		Config   string            `json:"config"`
		Judge    string            `json:"judge"`
		Question string            `json:"question"`
		Prompt   string            `json:"prompt"`
		Subjects map[string]string `json:"subjects"`
	}
	if err := json.NewDecoder(stdin).Decode(&input); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	states, err := loadConfiguration(options{config: input.State, configSet: true})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	c, err := loadConfiguration(options{config: input.Config, configSet: true})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	state, err := states.openState(true)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	defer state.close()
	o := options{action: "ask", config: input.Config, configSet: true, judge: input.Judge, question: input.Question, questionSet: true}
	subjects := []textPair{}
	for _, name := range sortedKeys(input.Subjects) {
		subjects = append(subjects, textPair{name, input.Subjects[name]})
	}
	r, err := buildRequest(o, input.Prompt, subjects)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	definition, exists := c.judges[o.judge]
	if !exists {
		fmt.Fprintln(stderr, "judge not configured")
		return 2
	}
	_, _, _, err = askJudgeInState(c, state, o, definition, r)
	if encodeErr := emitJSON(stdout, map[string]any{"refused": err != nil}); encodeErr != nil {
		fmt.Fprintln(stderr, encodeErr)
		return 2
	}
	return 0
}
