package laneturns

import (
	"math"
	"sort"
	"strings"
	"unicode"

	"laneboss.io/laneboss/internal/lane"
)

// Use the ordinary lane scanner for every turn-based refusal and retry.
func analyseShell(command, directory string) ([]string, []string) {
	return lane.AnalyseShell(command, directory)
}

func resolveShellPath(word, directory string) string { return lane.ResolveShellPath(word, directory) }

func sortedSet(set map[string]bool) []string {
	result := []string{}
	for s := range set {
		result = append(result, s)
	}
	sort.Strings(result)
	return result
}
func shellShingles(text string) map[string]bool {
	squashed := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return -1
	}, cutText(text, 65536))
	r := []rune(cutText(squashed, 16384))
	set := map[string]bool{}
	if len(r) < 5 {
		if len(r) > 0 {
			set[string(r)] = true
		}
		return set
	}
	for i := 0; i+5 <= len(r); i++ {
		set[string(r[i:i+5])] = true
	}
	return set
}
func shellSimilarity(later, refused map[string]bool) object {
	if len(later) == 0 || len(refused) == 0 {
		return nil
	}
	shared := 0
	for s := range later {
		if refused[s] {
			shared++
		}
	}
	containment := float64(shared) / float64(len(later))
	coverage := float64(shared) / float64(len(refused))
	if containment >= 0.8 && (coverage >= 0.8 || coverage >= 0.2 && shared >= 20 || shared >= 200) {
		return object{"containment": math.Round(containment*1000) / 1000, "coverage": math.Round(coverage*1000) / 1000}
	}
	return nil
}
