package api

type RootGrantManifest struct {
	Resources []ResourceGrant `json:"resources"`
	Schema    string          `json:"schema"`
	Data      []DataGrant     `json:"data"`
	Secrets   []SecretGrant   `json:"secrets"`
	Profiles  []ProfileGrant  `json:"profiles"`
	Network   []NetworkGrant  `json:"network"`
	Channels  []ChannelGrant  `json:"channels"`
}

type ObjectManifest struct {
	Schema  string        `json:"schema"`
	Entries []ObjectEntry `json:"entries"`
}

type ObjectEntry struct {
	Assembly   *ObjectAssembly `json:"assembly,omitempty"`
	Path       string          `json:"path"`
	Kind       string          `json:"kind"`
	Mode       uint32          `json:"mode"`
	Content    *BlobRef        `json:"content,omitempty"`
	LinkTarget string          `json:"link_target,omitempty"`
}

type ObjectAssembly struct {
	SHA256 Digest    `json:"sha256"`
	Bytes  int64     `json:"bytes"`
	Parts  []BlobRef `json:"parts"`
}

type BoxSpec struct {
	Schema          string `json:"schema"`
	Region          string `json:"region"`
	ImageID         string `json:"image_id"`
	MachineType     string `json:"machine_type"`
	Architecture    string `json:"architecture"`
	MaxHourlyMicros int64  `json:"max_hourly_micros"`
	DiskBytes       uint64 `json:"disk_bytes"`
}

type WorkerPlan struct {
	Schema     string     `json:"schema"`
	Kind       string     `json:"kind"`
	Executable Executable `json:"executable"`
	Argv       []string   `json:"argv"`
	Input      BlobRef    `json:"input"`
	GrantSetID ID         `json:"grant_set_id"`
	Budget     Budget     `json:"budget"`
}

type MigrationManifest struct {
	Schema         string         `json:"schema"`
	SourceVersion  string         `json:"source_version"`
	SourceProtocol string         `json:"source_protocol"`
	SourceRevision string         `json:"source_revision"`
	Inventory      ObjectManifest `json:"inventory"`
	Quiescence     BlobRef        `json:"quiescence"`
	Verification   BlobRef        `json:"verification"`
}

type AdoptionManifest struct {
	Schema         string    `json:"schema"`
	Workspace      Workspace `json:"workspace"`
	Session        Session   `json:"session"`
	PrivateHistory BlobRef   `json:"private_history"`
	Quiescence     BlobRef   `json:"quiescence"`
	SourceVersion  string    `json:"source_version"`
}
