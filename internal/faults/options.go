// Package faults provides inert call sites in release builds. Instrumentation
// and its environment parser are compiled only with the laneboss_faults tag.
package faults

type Options struct {
	Point    string `json:"point"`
	Marker   string `json:"marker"`
	Continue string `json:"continue"`
	Record   string `json:"record"`
	State    string `json:"state"`
}
