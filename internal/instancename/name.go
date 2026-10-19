// Package instancename defines the single grammar for org instance identities.
package instancename

import "regexp"

const Pattern = `[A-Za-z0-9][A-Za-z0-9_.-]{0,95}`
const MaxLength = 96

var Expression = regexp.MustCompile("^" + Pattern + "$")

func Valid(name string) bool { return Expression.MatchString(name) }
