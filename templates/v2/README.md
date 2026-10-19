# V2 prompt source samples

These are authored org sources, not generated rule files. They install no hooks,
start no session and grant no filesystem, network, cloud or messaging rights.
Initial administrator enrollment may establish the baseline. Every later change
to an existing org requires the L6 exact-diff and direct-human D6 transaction.

The source mapping consumed from the approved draft.3 snapshot is:

| Source in this directory | Approved org-relative path |
| --- | --- |
| `org/default.md` | `.laneboss/shared/templates/default.md` |
| `org/drivers.toml` | `.laneboss/shared/templates/drivers.toml` |
| `org/workflow.toml` | `.laneboss/shared/workflow.toml` |
| `roles/L3/executor.md` | `.laneboss/L3/roles/executor.md` |
| `roles/L3/executor.toml` | `.laneboss/L3/roles/executor.toml` |

The same `roles/L<N>/<role>` mapping applies to the other role pairs. The service
uses `OrgSnapshot`, `TemplateSources` and `Source` to obtain their committed
content references, then checks actual object metadata and bytes. Source IDs
are distinct from blob IDs. A source reference carries the current snapshot
generation; `ResourceFile.RevisionGeneration` retains older unchanged file
history. This mapping does not reinterpret `ConfigView.projection` as a catalog.
The store, publisher and installed bootstrap pins still require integration;
see the contract note in the templates module.

An absent local Markdown/TOML pair uses the explicit org default pair. A partial,
malformed, stale, hash-mismatched or wrong-role pair fails. Markdown must have
Scope, Responsibilities, Deliverable and Must not sections. It is literal text,
never an executable template. Driver TOML contains only `drivers`, with distinct
entries chosen from `claudock-cli` and `codex`, bounded by the org primary
catalog. This is agent-driver selection, not a tool or command allowlist. Scoped
review-driver exceptions need their own reviewed contract and cannot be smuggled
into this primary catalog.

The baseline workflow source has exactly twelve named entries and their
existing Instead routes. Its six tmux entries refer to raw agent session
management; private build/test tmux remains ordinary work. There are no added
secret, network, Git, script, PR or plugin bans. Org policy may explicitly add
scoped entries through D6; the examples are separate from these seeds.

The pure renderer keeps the selected source hash in `TemplateRef.source_sha256`
and the applied snapshot generation in `TemplateRef.generation`. All consumed
source and driver references accompany the document. The rendered digest is
computed over the final bytes and returned separately to avoid a self-referential
hash. The task is the exact final byte sequence after `## Assigned task`; its
committed length and hash are printed before it. No trailing newline is added.
