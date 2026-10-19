package orghook

import "path/filepath"

// argvWordsMatch anchors the executable, then consumes exact argv words in
// order. It never searches inside an argument or across separate commands.
func argvWordsMatch(argv, words []string) bool {
	if len(words) == 0 || len(argv) < len(words) || filepath.Base(argv[0]) != words[0] {
		return false
	}
	next := 1
	for _, word := range argv[1:] {
		if next < len(words) && word == words[next] {
			next++
		}
	}
	return next == len(words)
}

func argvWordsOperator(word string) bool {
	return contains([]string{";", "&&", "||", "|", "|&", "&", "(", ")", ";;", ";&", ";;&",
		">", ">>", "<", "<<", "<<-", "<<<", ">|", "<>", "&>", "&>>", ">&", "<&", "!"}, word)
}
