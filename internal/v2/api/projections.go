package api

type SettingValue struct {
	Key     string    `json:"key"`
	Boolean *bool     `json:"boolean,omitempty"`
	Integer *int64    `json:"integer,omitempty"`
	String  *string   `json:"string,omitempty"`
	Strings *[]string `json:"strings,omitempty"`
	Source  SourceRef `json:"source"`
}

// ConfigView.Projection refers to this committed, screened view, never a
// caller-selected TOML/SQLite path or an environment/settings dump.
type ConfigProjection struct {
	Schema     string            `json:"schema"`
	Config     string            `json:"config"`
	View       string            `json:"view"`
	Generation Generation        `json:"generation"`
	Context    *RoleContext      `json:"context,omitempty"`
	Names      []string          `json:"names"`
	Settings   []SettingValue    `json:"settings"`
	Resources  []Resource        `json:"resources"`
	Sources    []SourceRef       `json:"sources"`
	Binding    *InstalledBinding `json:"binding,omitempty"`
	Warnings   []string          `json:"warnings"`
}
