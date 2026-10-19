package orghook

import "path/filepath"

// DelegableTools preserves tool denials without treating recorded allowlists
// as grants. Caller and policy integrity are still checked for a bound instance.
func DelegableTools(org, name string, additions, denied, candidates []string) ([]string, error) {
	if name != "" {
		inst, err := loadInstance(filepath.Join(org, ".laneboss", "instances", name))
		if err != nil {
			return nil, err
		}
		if _, err := loadRules(inst); err != nil {
			return nil, err
		}
	}
	result := []string{}
	for _, candidate := range candidates {
		if !contains(denied, candidate) {
			result = append(result, candidate)
		}
	}
	return result, nil
}
