package admin

import (
	"path/filepath"

	"laneboss.io/laneboss/internal/v2/api"
)

// Runtime enrollment is mutable helper state, not an installation source.
// The installer owns the private config root; only its helper creates this
// child namespace, already inside the shipped unit's config-scoped write path.
func workspaceRegistryDirectory(config string) string {
	return filepath.Join((installation{Config: config}).statePath(), "workspaces")
}

func workspaceRegistryFile(config string, id api.ID) string {
	return filepath.Join(workspaceRegistryDirectory(config), string(id)+".json")
}

// Paths are helper-derived and live only in its protected journal/registry.
// No lane, effect payload or worker result can select these paths.
type cleanupEnrollment struct {
	Schema, Config                      string
	LeaseID                             api.ID
	Workspace                           api.CleanupWorkspace
	Parent, Repository, GitDir, GitPath string
	GitArtifact                         api.ReleaseArtifact
}

type workspaceJournal struct {
	ReservedBytes   uint64 `json:"reserved_bytes,omitempty"`
	ImportedTree    string `json:"imported_tree,omitempty"`
	Enrollment      cleanupEnrollment
	StageID         api.ID
	InputSHA256     api.Digest
	Result          api.WorkerResultReceipt
	ClaimID         api.ID
	ClaimGeneration api.Generation
	Phase           string
}

func validateWorkspaceJournal(p leaseRecord) error {
	if p.Storage == nil || p.Storage.Workspace == nil {
		return nil
	}
	j := p.Storage.Workspace
	if len(p.Storage.Directories) != 3 {
		return failure(api.CodeIntegrity, "native workspace journal lost its storage inventory")
	}
	e, w := j.Enrollment, j.Enrollment.Workspace
	if e.Schema != "laneboss.workspace-native.v2" || e.Config != p.Request.Config || e.LeaseID != p.Lease.ID ||
		w.ID != p.Storage.Binding.WorkspaceID || w.Target != p.Storage.Binding.Target || w.Generation != p.Storage.Binding.Home.Generation ||
		!validID(w.RootID) || !validID(w.RepositoryID) || w.ID == w.RootID || w.ID == w.RepositoryID || w.RootID == w.RepositoryID ||
		w.RootIdentity == "" || w.DirectoryIdentity != p.Storage.Directories[0].Device+":"+p.Storage.Directories[0].Inode ||
		w.Branch != "lane/"+string(w.Target.LifeID) || !validID(j.StageID) || !validDigest(j.InputSHA256) ||
		!validID(j.ClaimID) || j.ClaimGeneration == 0 || !validDigest(e.GitArtifact.SHA256) || e.GitArtifact.Bytes <= 0 ||
		e.GitPath != "/usr/bin/git" || e.Parent != filepath.Join("/var/lib/laneboss-v2/lanes", e.Config, string(p.Lease.ID)) ||
		e.Repository != filepath.Join(e.Parent, "repository-"+string(w.ID)) || e.GitDir != filepath.Join(e.Repository, "worktrees", string(w.ID)) {
		return failure(api.CodeIntegrity, "native workspace journal changed its allocated owner or stable pins")
	}
	switch j.Phase {
	case "reserved", "budget_refused":
	case "repository":
		if w.GitIdentity == "" {
			return failure(api.CodeIntegrity, "native workspace repository lost its inode pin")
		}
	case "imported", "linked", "published":
		if w.GitIdentity == "" || !cleanupGitHead(w.Head) {
			return failure(api.CodeIntegrity, "native workspace lost its measured Git base")
		}
	default:
		return failure(api.CodeIntegrity, "native workspace has an unknown producer phase")
	}
	for _, job := range p.DataJobs {
		if job.Reg.Request.StageID == j.StageID && job.Result != nil && job.Result.InputSHA256 == j.InputSHA256 &&
			job.Result.ResultReceipt == j.Result && job.Result.Data.Workspace.ID == w.ID && job.Result.Data.Target == w.Target {
			if j.ReservedBytes > job.Reg.Plan.Budget.DiskBytes || j.ImportedTree != "" && !cleanupGitHead(j.ImportedTree) {
				return failure(api.CodeIntegrity, "native workspace quota or imported tree pin is invalid")
			}
			return nil
		}
	}
	return failure(api.CodeIntegrity, "native workspace lacks its original measured materialization")
}
