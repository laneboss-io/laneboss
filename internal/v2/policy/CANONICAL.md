# Approved configuration sources

The canonical reader consumes committed objects from one authenticated
OrgSnapshot. It opens no host path and accepts no source path from an RPC.
The org baseline is `.laneboss/policy.json`. Optional role layers use
`.laneboss/L3/policy/executor.json`, with the actual level and role in the
inventory path. Defining scope is derived from that path. A role with no
local file inherits the org baseline and applicable higher roles.

Each file has schema `laneboss.policy-source.v2`, `thresholds`, `rules`,
`skip` and `settings`. These arrays must be explicit, including when empty.
Rules, skip entries, thresholds and typed settings use their existing API
structures. A rule or setting may omit its source contents by using the zero
SourceRef; the loader assigns the actual retained source. A nonzero supplied
source must equal that exact source. No source is selected by a client label.

The org baseline additionally requires `judge`,
`guidance_half_life_seconds`, `guidance_min_relevance` and
`profile_exclusions`. These are explicit approved inputs. Role documents
cannot redefine them. Settings accept the existing typed settings keys and
exactly one typed value, with credential screening. Org settings are
overridden only by the selected role's settings. Higher-role settings are
not inherited as defaults. An explicit lane instance claim must match its
authenticated actor ID. The public configuration reader resolves the actual
life before preserving that claim; this invents no org instance graph.

Every policy source is decoded and validated, including unselected roles.
Resolve constructs the org + own pair + every higher role union while
preserving defining thresholds and applicability. It independently rebuilds
the retained default context and checks its approved policy digest before
returning another context. Source and policy generations remain distinct.
Changing bytes without the corresponding approved projection refuses.

Config show/settings/roles/plugins/channels use this same reader. Names
include configured policy roles and template role pairs. Plugin and channel
catalogs come from approved inventory entries below `plugins/` and
`channels/`. Their content references and original revision generations are
retained. Declaration is not verified loading or delivery. Settings carry
the actual defining SourceRef, and no environment value is discovered.
The protected read projection retains its actual frame, inputs and ACL.

Existing installations with only the older flattened policy retain their
original context's legacy reads. They cannot supply another role's union
or complete configuration views. Those operations return a typed missing
canonical-source prerequisite. The serve bundle now emits the canonical
baseline and its matching generation-one policy. Initial administrator
publication makes its exact approved source inventory readable to config
lanes without exposing other imported objects.

The installed approval service uses the scoped data worker's fixed JSON/text
compiler for canonical proposals. It retains actual generated policy text,
before/after diff and manifest under the original proposal operation. Human
review can read those exact staged refs. Apply recompiles the same inputs,
then the existing publication effect installs a filesystem generation and
completes its org and policy projections in one store transaction. Public
reads keep checking the retained digest. Exact approved source refs also
remain usable as policy audit inputs despite an immutable uploader ACL.

The positive component tests reach propose, human readback, apply, measured
publication, config show, replay and restart verification. They supply an
explicit component approval; they do not establish a physical owner gesture
or full installed CLI acceptance. External executable renderers and channel,
grant and decision semantic compilers remain separate integration work.
