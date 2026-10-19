# Isolation as the Laneboss foundation

## 一頁摘要（繁體中文）

**已確認保留單一 Go binary：`laneboss serve` 管理狀態，其他指令透過 socket 操作。**
Service 使用獨立帳號，執行 lane 的 driver 保留 claudock-cli／codex。Linux 採
bubblewrap＋Landlock；macOS 候補驗證，若實機證明失敗，以 Linux VM 替代。
管理員一次安裝帳號、AppArmor profile 與 UID／cgroup helper；service、runner 不跑 root。

Lane 只能取得自己的 worktree、home、暫存及 spawner 交付的資料；child grants
不得超過 parent。Task secrets 由已確認的 native encrypted store 按名稱注入，
與 vendor 登入分開；Infisical 為 optional backend。測試 child code 的 sandbox
不得比 child 更寬。所有 org 資源與權威 decision store 都受保護；L6 的確切 diff
要人直接核准，其他 lane 只能向上提出建議，不能把自己的文字寫成跨 lane 決策。

人可在 dashboard 看 decisions、各層原始訊息／logs、組織樹、生命週期、refusals、
plugins、scripts／tools／核准歷史，也能傳訊給任一層及控制 lane。Agent 只能 spawn
更低層；平級／向下通訊範圍的解讀列在下方，向上走 report line；只有 L5／L6 能用
已授權 channel 對人傳訊。每個 lane 外層的受信任監控行程（run wrapper）直接從
pipe 捕捉 vendor 原始輸出。Claudock quota limit 由 service watchdog 換有餘額的
已授權 profile，保留 session／history，不算 failure／retry，沒有 agent cron。

**永遠只有黑名單，沒有指令白名單。** OS／service 保護檔案與身分，judge 處理文字
規則與每 turn guidance；skip list 只能放行。Judge 失效時建議只有 org 明列 critical
的規則 fail closed，其餘通知並記錄後放行；有效分數依 warn／refuse 門檻處理。

待您確認「對」的三組解讀：

1. 「time averaged」是否指歷史決策依時間衰減加權，而非一段時間內不重複提醒？
2. 是否由 judge 直接依文字判斷指令屬不屬於黑名單，完全取代 pattern 比對？
3. 「same root」是同一直接 parent，還是同一 L5／L6 子樹？向下的「same tree」
   是否限發話者自己的 starter 子樹？目前建議採較窄範圍，仍待確認。

Linux spike 在 Ubuntu 24.04.5：restriction 關閉時 **185/185 項隔離檢查通過**；
開啟時 **195/195 項通過（增加 10 項 AppArmor 安裝與驗證檢查）**。未裝 profile
的 bwrap 被拒；管理員載入僅對 bwrap 的 profile 後成功，host-wide 限制仍開啟。
另保留先前 **11 通過／2 失敗** 的 restricted run，及 diagnostic 修正後的結果。
這些是 kernel／fixture 檢查，不是完整產品或真實 agent 驗收。

**已決定 Clef 只評估現有自架 Clef-flash，不用 Cloudflare account／token。**
授權的兩張 24 GB A30 中目前用一張；context 是設定，先前 8,192，最新已調至
16,384 tokens。短題 Noul／Choice 的 P(yes) 約 0.95／0.01、每次約 85 ms；
近 16k 題約 2.4–3.0 秒且有 silent truncation，不能當完整輸入驗證。約 302 題與
Jev 的比較、shadow run、Infisical、startup p50／p95、真實 runner／macOS 仍待驗證。

**已決定以 36 小時完成 Linux 為目標**：約 2 小時凍結 contract，接著約 20 條 Codex
lanes 與所有有 headroom 的 Claudock profiles 平行，持續在 box 驗證；gating review
加 Gemini cross review，全部使用最高支援 effort；較難任務可交 Argon，各有自己的
worktree。已批准沿用 ladder 方法，把有 quota 的測試
登入寫入已驗證的 disposable box 一次，驗收後銷毀並確認。Mac 不阻擋 Linux；
Windows／WSL 在後。**63–98 工程工作天**僅是單一工程師等價工作量（含 macOS），
加 20% 為 76–118；不再是 elapsed schedule。36 小時是 owner 的目標，未通過的 gate
仍要如實列出，不能因 deadline 宣告成功。

Written 2026-10-15 against unchanged product code `cc17ebb`; documentation base
`e002f6e`, revised for addendum 6 and the Fable/Gemini reads. Owner decisions
R101–R107 are distinguished from pending readings below. This document lane edits
only this file and starts no build, agent, machine or model call. R102 authorizes
the supervising implementation track; it does not reinstate the cancelled 1.0.0
release or waive the redesigned release's executed acceptance.

## 1. Decision, goals and trust

**Decision:** make the operating system restrict every agent process, and make a
separate service the only writer of Laneboss records. A lane runs any ordinary
program inside the resources it was given. A hook can explain an org rule; it
cannot establish that a file is safe.

The owner requirements used here are R64–R99 (D1–D14), extended by the confirmed
R100–R107 decisions, with R26, R30, R48, R52 and R57–R61 still binding. R48
prohibits command/tool allowlists. R71 explicitly asks supervisors
to select data for children: selecting filesystem resources is the isolation
contract, not a list of permitted commands. Builds, tests, scripts, package
installs, Git, network clients, caches and temporary files remain ordinary work
within that contract. Only an explicit org blacklist adds workflow refusals.

### Current code facts and the design consequence

These are source observations, not newly executed exploit canaries. A suspected
escape in the supplied studies remains suspected until its control and canary run.

| Current behavior and evidence | Design consequence |
| --- | --- |
| The Linux backend probes Landlock and returns “runner continues without a Laneboss-files sandbox” in both outcomes (`internal/lanesandbox/runner_linux.go:12`). | Implement an enforcing backend; availability is never recorded as enforcement. |
| The Darwin profile begins with `(allow default)` and emits file-write denials; its comment explicitly excludes read, network and Unix-socket restrictions (`internal/lanesandbox/profile.go:11`, `internal/lanesandbox/profile.go:69`). | Replace its policy model. Turning this profile on by default would not satisfy this brief. |
| Vetted Codex instances receive the configuration state directory as a writable root; the documented remaining protection depends on the hook (`docs/configuration.md:167`, `docs/configuration.md:179`). | Remove that root, including for supervisors; provide RPC instead. |
| `identityd` has a separately owned journal and checks ownership, permissions and links (`internal/identityd/files.go:18`, `internal/identityd/files.go:83`). Its dispatch supports registration, lane identity and journal append, rather than the full lane lifecycle (`internal/identityd/server.go:471`). | Reuse its trust checks, ticket logic and bounded protocol; move the rest of state and operations behind it. |
| The executable installs a service identity resolver, while the CLI dispatches lane / state / report handlers locally (`cmd/laneboss/main.go:37`, `internal/cli/cli.go:45`, `internal/identityd/integration.go:127`). | This is a substantial integration change, not an existing complete service deployment. |
| A lane sees only its own events or events addressed to it; filtering precedes `--until` (`internal/event/event.go:133`, `internal/event/event.go:238`). | Add authentic starter-tree visibility, consistently across all readers. |
| Turn actor selection takes the first carried mail sender (`internal/laneturns/identity.go:65`, `internal/laneturns/turn.go:192`). Ordinary resume already uses its authenticated requester (`internal/lane/lifecycle.go:985`). | Separate the person/process requesting a turn from the senders whose mail it carries. |
| Darwin service mutations explicitly refuse pending verified peer lifetime support (`internal/identityd/peer_darwin.go:8`, `internal/identityd/peer_darwin.go:20`). | Native macOS service identity is an implementation gate, not a solved prerequisite. |

The supplied ladder summary, `SUMMARY-ladder-2026-10-15.md`, §3, reports the child
event wait hanging despite a stored successful end, and a probable turn actor
misattribution. Its §1 says no ladder passed. The bootstrap study `REPORT.md`,
§§1–3, identifies runner-kind assumptions, shared homes, report placement,
conversation identity and inherited sandboxes as integration problems. Those are
design inputs, not release evidence. Older study line references must not be
mistaken for the line numbers of this base.

### Protection and limits

| Protect | From | Enforced by |
| --- | --- | --- |
| Events, identities, claims, mail, reports, decisions, policy, hooks, settings, ledgers, archive receipts and dashboard credentials | Every lane, including L4–L6 and their descendants | Separate service ownership, no filesystem grant, authenticated service operations |
| A lane's work, home, temp, credentials and private services | Other lanes and accidental broad grants | Separate lane UID, OS filesystem / process / network boundary, grant checks |
| The human's home and ungranted repositories/files | All agent processes | Data absent from the Linux namespace; Darwin read/write restrictions plus account permissions |
| The scope of a child | An erroneous or overbroad parent request | Service checks a child grant against the parent's recorded capabilities and current owner policy |

Agents are not assumed hostile. Nevertheless, arbitrary code they execute, a
renamed program and an agent that ignores every prompt must still meet these
boundaries. Treat repo hooks, dependencies and generated code as untrusted too.

Root/administrator, the kernel, the installed launcher/helper, service account,
credential broker and owner-approved policy are trusted. Kernel exploits,
microarchitectural side channels, guaranteeing report truth, preventing all data
exfiltration after data is granted, and mutually hostile tenants on one kernel
are non-goals. Stronger tenants use a VM backend. CPU, memory, process and disk
limits reduce accidental exhaustion; they are not an absolute availability SLA.
Native macOS may expose some system process metadata; it must not expose another
process's memory, credentials, file contents or control endpoints.

## Owner requirements map

The owner's full D1–D5 input is preserved verbatim here; the table distinguishes
his confirmed rules from interpretations still awaiting confirmation:

> - aggressive guidance from decision store via hook, typesafe judge on each turn to determine whether to provide the past similar decision. Time averaged. - global and local config, from the org-wide to the (level, role): backlist for command, judge by typesafe. Use this design to split the responsibilities. Who can do E2E with GCP/AWS resources, who can make a PR, usage of plugin, etc. - prompt template for (level, role), control the scope when spawning executors. - lane spawner can determine what directory to share to the agent from org, and what worktree to given, according to the scope of assigned task. - if a task can be done by laneboss, each agent should use it directly instead of make up its own.

| Owner requirement | Status and how the proposal meets it | Required test in §10 |
| --- | --- | --- |
| **D1. Judged, time-averaged guidance each turn** | **proposed reading, awaiting the owner's 對**: TypeSafe decides which similar past decisions to surface each turn; newer decisions weigh more and older ones decay, not a reminder rate limit. The “Guidance and judged blacklist” section defines the proposed computation. | GUIDE-TURN: two turns each invoke selection; changed task/time changes selected history; old binding policy never expires. |
| **D2. Layered command blacklist and responsibility split** | Org → `(level, role)` entries describe forbidden actions in words, including cloud E2E, PR and plugin duties. R76 confirms “對 永遠只有黑名單 永遠沒有白名單”. TypeSafe judgment itself replacing deterministic matching is a **proposed reading, awaiting the owner's 對**. | BL-RESP: no matching entry allows ordinary work; non-testing roles' resource-creation entries refuse, testing role's unrelated calls proceed; no missing-positive-permission refusal. |
| **D3. `(level, role)` prompt templates bound spawn scope** | §4 records the resolved template, source generation/hash and task scope in the child start. Render templates plus the assigned task/grants; prompt text cannot expand OS rights. | TPL-SCOPE: correct role / template / task / grants appear, wrong-role source cannot widen scope, and exact input bytes are retained. |
| **D4. Spawner chooses shared org directories and worktree** | §5 gives a file-backed per-child choice bounded by the starter, including cross-repo data. Writable work is an independent task copy, not a write grant on canonical org assets. | GRANT-BOUND: wider request refuses before launch, narrower copy/mount succeeds and skip-check mutation fails. |
| **D5. Laneboss-first** | Preserve twelve named workflow rules and their Instead routes; every brief points to `org blacklist list`. A command not covered by Laneboss stays ordinary blacklist behavior. | LB-FIRST: raw equivalents receive the appropriate route, ordinary tool controls and authenticated Laneboss operations work. |
| **D6. All org resources: L6 plus direct human approval** | Owner: “L6 is allow to edit org's template, but need directly approval from human.” Widened: “every org's resources, including but not limited to: tools, scripts, config, template., can be updated from L6, but need direct approval from human”. §4 requires a fresh recorded approval bound to each exact diff; no lower level or lane filesystem write changes any org resource. | ORG-APPROVAL: approved L6 diff succeeds; L5, absent / stale / replayed / wrong-diff approval and direct writes fail. |
| **D7. Peer, downward and granted-human messaging** | Owner: “an agent can talk to all agent at the same level, and from the same root (like L4 can talk to each other if they are spawned from the same L5)”; “agent at higher level can always talk to the lower level of agents at the same tree.”; “and L5 and L6 and talk to human via the granted channel”. **Proposed readings, awaiting the owner's 對:** peers share a direct spawning parent rather than merely an L5/L6 root; “same tree” for downward messages means the sender's own authentic starter subtree. §11 preserves both broader readings; upward traffic follows the report line. | MSG-REL tests the confirmed peer/downward rule, including L3s below sibling L4s and L5→L3 alongside L4→L3; provisional narrow-policy outcomes are labelled pending, not owner-confirmed. Granted L5/L6 human controls and L3/L4 refusals remain. |
| **D8. Primary drivers and explicit later exceptions** | Owner's original direction “agent all driven by claudock-cli or codex” keeps Claudock/Codex as the primary catalog, with provider models behind profiles. Later **R103/R107 explicitly authorize opencode Argon** for gating cross-reviews and selected hard engineering tasks, each scoped and recorded; R107 requires its own worktree. These exceptions do not admit arbitrary custom drivers. | DRIVER-TWO/LB-FIRST preserves primary controls and the exact later exceptions; ARGON-WORKTREE proves worktree isolation, maximum supported effort and independent review. |
| **D9. Spawn/adopt only lower levels** | Owner: “agent can only spawn agent lower of its level”. §6 permits any strictly lower level, including L5→L3; it forbids equal/higher levels. Grants and messaging follow actual starter edges, not an assumed adjacent-level ladder. | SPAWN-LOWER: L5→L3 succeeds; L5→L5/L6 and forged-level adoption fail. |
| **D10. Human dashboard observation and direct messages** | Owner: “dashbarod, allow human to observe/borwse: decision store, raw messages/log from each level of agent's message (from CC or Codex), the tree structure of org, refusal statistics, installed plugin, scripts.” Addition: “human can send message to any level of agent from dashboard”. §4 specifies each read view and authenticated human→any-level mail. | DASH-* rows prove each view; HUMAN-SEND delivers human mail to L3 and refuses the same unauthenticated request. |
| **D11. One Go executable, service plus CLI** | R88 confirms “ok, stay with go binary”; §4 proposes `serve` as the service entry and keeps client subcommands in the same versioned Go artifact. | Packaging/CLI negotiation and service/CLI mismatch cells in phases 2/7. |
| **D12. Windows roadmap, at least WSL** | R90 says “supportness of windows is on the roadmap” / “at least wsl”; §2 keeps WSL2 as the first Windows target with kernel / filesystem / interop proof, not an initial gate. | Roadmap WSL2 capability / interop / DrvFS matrix before advertising support. |
| **D13. Spawner chooses secret injection** | R91: “spawner can control what env secret to be injected in the executor's sandbox”; §3/§5 require explicit named variables/files bounded by the starter. R93's local-store suggestion is an optional-backend decision. | GRANT-BOUND/CREDENTIAL-BOUND include both env and file injection, with absent undelegated names and no values in events. |
| **D14. Service watchdog swaps Claudock profiles automatically** | R96: “each lane should support auto-profile-swap if it is driven by claudock-cli”; R97: “i suggest use a system watch dog to do the swap, not via agent cronjob”. §3 uses service supervision, delegated eligible profiles, same private history and recorded resume. | WATCHDOG-SWAP: real classified limit triggers exactly one bounded swap/resume; text quoting a limit, no-room, stop and stale-run controls do not. |

### Carry-over ledger, including completed obligations retained by the port

This map includes the ledger's open items and the older confirmed requirements
that still constrain a port. A row names a design location and future evidence,
not a claim that this document fulfils an implementation/release gate. Only
the owner's explicit cancellation/supersession quoted below retires a release
action; elapsed deadlines or a “done” ledger heading do not erase functionality.

| R-number | Owner intent and disposition in this design |
| --- | --- |
| R1 | Keep the previously repaired defect; §8 feature parity and §11 phase 5 retain its existing regression/evidence rather than reset it. |
| R2 | Use granted Codex authoring seats and independent reviews; §11 gives parallel elapsed time and a first Linux milestone. No extra sessions are started by this document lane. |
| R3 | Public availability/marketing remains a release deliverable, gated by §10; R68 cancels the old publish, not the product objective. |
| R4 | Preserve synthetic dashboard screenshots; D10/§4/§8/§11 phase 7 refresh them after the new views pass privacy checks. |
| R5 | Keep dashboard shortcut hints behind the existing help affordance; §8 dashboard port. |
| R6 | Keep claudock-cli bundled and checksum verified; §3/§8 and D8. |
| R7 | Keep the companion repository/distribution; §8 packaging, no removal proposed. |
| R8 | Preserve profile_swap with private per-lane history and a swappable credential slot; §3 rotation test. |
| R9 | Bootstrap an org/group of projects; §4 root enrollment, §8 init, §11 Linux guide/tutorial. |
| R10, R12 | Keep explicit role templates and exact launcher drivers per `(level, role)`, narrowed to the two D8 drivers; §3/§8. This constrains spawning, not ordinary command execution. |
| R11 | Preserve account exclusions and room/profile choice; §3 credential-slot rotation and §8. |
| R13 | Keep generated Laneboss job catalog, warnings and correct Instead verbs; §7, judged-blacklist section and §10 LB-FIRST. |
| R14 | Keep profile-swap, owner sheet and Discord integrations; §8 and D10 inventories. |
| R15 | Preserve explicit environment-wrapper semantics; §3/§8 environment grants and §10 identity-spoof controls. |
| R16 | Preserve lane identity; §4 adds the lower-level protection now requested by R64–R71. No old identity claim is retroactively called OS isolation. |
| R17, R18 | Aggressive decision guidance with a judge-controlled dial; D1 and judged-blacklist section, GUIDE-TURN. Guidance alone never refuses. |
| R19 | Every applicable release gate must pass; §10/§11 retain failed/pending cells and move the date rather than fake completion. |
| R20 | Preserve report lines and dashboard; §6, D7/D10, MSG-REL and DASH-* tests. |
| R21 | ASAP delivery remains a planning objective under R19; §11 milestones. The old publish is explicitly cancelled by R68 “取消不發佈”. |
| R22 | Preserve recorded version/protocol compatibility; §8/§9. The next release number remains an owner release decision, not inferred from this draft. |
| R23 | Keep editable role templates as samples; §4 D3/D6 workflow, §8 library. Editing live resources now requires D6 approval. |
| R24 | Unknown scripts remain read-only; §4. Replacing existing-session `start --role` registration with confined top launches is a pending §11 owner decision, not silently approved. |
| R25 | Dedicated-user identity/state service, macOS outer sandbox replacing the vendor's; §2–§4 and platform identity tests. |
| R26, R28 | Ordinary coding, installs, Git, tmux, curl, kill, network, temp and caches work; §2/§10 ordinary controls. R28 was merged into R26 at the owner's request and is retained there. |
| R27 | Identified agents retain communication even detached; §4/§6, D7, MSG-REL. Human destinations follow the later explicit D7 rule. |
| R29 | Observe/warn defaults and avoid harmful restrictions; §1, judged-blacklist outage policy, §11 prerequisite-mode owner decision. |
| R30 | Words-first, level/role-aware blacklist judged by TypeSafe; D2, §7 and judged-blacklist section. No strict command allowlist. |
| R31 | Work as early as possible in parallel; §11 elapsed plan. The old release's ten-hour budget is preserved as historical context under R68's cancellation, not a new promise. |
| R32 | Keep full smoke intent; §10. R59/R60 explicitly change its work to read-only/ping-pong and a ten-instance seeded ladder; do not require the earlier development task as an extra hidden gate. |
| R33 | Layered typed settings, identity snapshot and bounded environment; §4/§8, D2/D3, grant/settings provenance tests. |
| R34 | Searchable records/vector store plus verified daily cleanup; §8/§9 archive/store port and receipt-before-removal tests. |
| R35 | The paid test Mac was cancelled: “算了 先不開”. §11 asks for a new test-Mac decision; no old authorization is reused. |
| R36 | Linux first; §2/§10/§11 keep native Mac evidence separate and unavailable cells explicit. |
| R37 | Use TypeSafe's actual state / instructions / criteria and probability contract; judged-blacklist section cites the saved official contract and requires pinned-provider replay. |
| R38 | Owner said “可以不用急著推0.7.0 直接推1.0.0也可以”; retain combined feature scope in §8. R68 cancels that publish; no new release is authorized here. |
| R39 | Single-use ticket fixes level/role at issue; §4 human authentication and atomic redemption tests. |
| R40 | Traditional Chinese five-minute domain status reporting remains the supervising release session's obligation, not a permission for this lane to send owner messages; §11 reports milestones/pending gates honestly. |
| R41 | Delete redundant tests, keep the smallest meaningful checks plus controls/mutants; §10 corpus and §11 acceptance. No E2E substitution or skipped security cells. |
| R42 | Retain focused judge/text checks plus a real L6→two L5→L4 ladder and progress; §10 uses two concurrent isolated runs as L6 requested. |
| R43 | Secrets stay outside org/repo; pass names and delegated handles only; §3, §5 and CREDENTIAL-BOUND. |
| R44 | Rewrite the Traditional Chinese complete Linux operating guide for administrator install, service launches, two drivers, D6/D7 and day-2 work; §8/§11 phase 7. |
| R45 | Missing role settings fall through to the org layer; §7. Whether “上層” means numerical N+1 remains a §11 owner question; do not invent scalar inheritance. |
| R46, R48 | Blacklist-only usability, Instead/history and the previously retained protections remain obligations. R64–R70 authorize OS/service enforcement; §7/§11 distinguish that boundary move from the reviewers' unresolved reading of an additional R47 gate for exact code deletion. |
| R47 | Laneboss-covered work uses Laneboss; other work is blacklist-only. D5/§7 preserve this, and §11 keeps uncertain readings for direct confirmation before implementation. |
| R49 | Union org, own role and all roles at higher levels; §7/judged-blacklist section. This is deny inheritance, not an allow grant. |
| R50 | Show L6 / L5 / L4 flow and hook/service responsibilities; §4 diagram and D9 real starter edges. |
| R51 | Show actual words-first blacklist examples; judged-blacklist responsibility examples and §7 list/Instead output. |
| R52 | Seed only the twelve Laneboss-first entries; §7/§8. Critical secret/network entries are owner-authored, never silently added. |
| R53 | Publish only after full ladder acceptance; §10 keeps both required runs and failure evidence; R68 keeps the old release cancelled. |
| R54, R55, R56 | Deliver the bootstrap tutorial together with the redesigned release, using the real harness steps; §8/§11 phase 7. Existing study is input, not runtime proof. |
| R57, R58 | Cross-runner coverage and ten instances with recorded random seed; §10 mixed ladder and focused driver cells. |
| R59, R60 | Owner chose read-only/ping-pong and option “A”: Claudock/Claude supervisors, mixed L3s; §10 preserves that primary gate. |
| R61 | Lane-aware rule list and source paths in every role brief; D3/D5, §7. No agent trial-and-error through `try`. |
| R62 | White-hat attack and ordinary-work over-block checks become actual canaries; §10 corpus, controls and independent security review. |
| R63 | Distinguish Codex authoring, independent review and R60's supervisor mix; §3/§10/§11, no all-Claude probe misreported as the mixed result. |
| R64 | Move file safety below command spelling; §1–§7 OS/service design and §10 direct syscall evidence. This boundary move is authorized; §11 records the review disagreement about whether exact legacy code deletion needs separate R47 confirmation. |
| R65 | Separate state/lane users; §2/§4 helper and leases. |
| R66 | Evaluate service/lane containers and Kubernetes; §2 alternatives, keep lightweight default and optional stronger backend. |
| R67, R68 | Re-architecture/design before code; owner “取消不發佈” cancels the old release. §1/§11 retain the hold. |
| R69 | Evaluate lighter tools than Docker with measured costs; §2 targets versus measurements and platform probes. |
| R70 | Owner chose scope “Ａ” and stopped running fixes with “停”; §1/§8 port useful parts, §9 retains stopped evidence, no rewrite-from-zero assumption. |
| R71 | Per-child scoped repo / path / file / worktree grants; D4/§5, GRANT-BOUND and CHILD-CODE tests. |
| R72 | Honest design status and delivery; this revision/report provides the requested result and names pending readings rather than treating silence as agreement. |
| R73 | D1: recency/time-averaged reading pending; judged-blacklist section and §11 explicitly await his 對. |
| R74 | D2: judge alone replacing matching pending; §7/judged-blacklist section and §11 explicitly await his 對. |
| R75 | All five full owner requirements are quoted above as D1–D5; their sections/tests are named, none dropped. |
| R76 | Confirmed “對 永遠只有黑名單 永遠沒有白名單”; D2 examples, positive-only judge-skip list and default allow preserve it. This does not confirm R73/R74 interpretations. |
| R77, R78 | D6 applies to all org resources, not just templates; §4 exact-diff direct-human approval protocol, ORG-APPROVAL. |
| R79, R80, R81 | D7: peer “same root” (direct parent versus common L5/L6 root) and downward “same tree” (sender subtree versus wider root) remain proposed readings awaiting the owner's 對; §6/§11 preserve the alternatives and MSG-REL follows the confirmed rule. L5/L6 granted-human channels remain explicit. |
| R82 | Preserve the original D8 primary Claudock/Codex catalog and provider profiles. Later owner decisions R103/R107 explicitly add scoped Argon review/hard-engineering exceptions; §3/§8 record their limits instead of treating the earlier two-driver wording as a refusal of those later tasks. |
| R83 | Only strictly lower starts/adoptions, any lower level; D9/§6, SPAWN-LOWER. |
| R84 | D10 read-only dashboard views, mapped with R4/R20; §4 data-source/view tests. Human-to-any-level mail addition also appears in §4/§10. |
| R85 | Owner “human can send message to any level of agent from dashboard”; D10/§4/§10 HUMAN-SEND implement that inbound exception without giving L3/L4 an outbound human channel. |
| R86 | Owner “consider use the cloudflare/clef to replace typesafe”; the judged-blacklist provider interface below includes a Clef evaluation gate and primary-source / latency / cost / accuracy questions. No replacement is claimed verified. |
| R87, R88 | Owner asked executable versus CLI, then confirmed “ok, stay with go binary”; §4 keeps one Go executable with a proposed `serve` mode and socket-client commands, not a new language/runtime. |
| R89 | Use all available authorized Claudock/Codex profile headroom and parallel build lanes; §11 elapsed plan has no artificial profile cap. Other L5 stop/collection is the supervising session's task, not permission for this document lane to stop processes. |
| R90 | Owner “supportness of windows is on the roadmap” / “at least wsl”; §2 Windows/WSL roadmap is retained, not silently a first-release gate. |
| R91 | Owner “spawner can control what env secret to be injected in the executor's sandbox”; §3/§5 named per-child secret grants are bounded by the spawner and recorded without values, tested by GRANT-BOUND/CREDENTIAL-BOUND. |
| R92 | Service controls lane lifecycle and reflects every transition in dashboard; §4/§6 and DASH-LIFECYCLE. R94 subsequently confirms human stop / resume / mark controls, included in DASH-CONTROL. |
| R93 | Owner suggests local Infisical and asks for a recommendation; §3 gives a pluggable outside-lane store with optional Infisical. R95 subsequently accepts the lightweight encrypted native default; no lane holds store-admin/machine credentials. |
| R94 | Owner confirms human dashboard lane control with “reply to your question on the control of the lane's sandbox from dashboard: yes”; §4/§6 and DASH-CONTROL include authenticated stop / resume / mark, recorded like CLI operations. |
| R95 | Owner “accept to your laneboss native secret store”; §3's native encrypted service-owned default is accepted, with optional Infisical and parent-bounded injection. This choice is no longer an open question. |
| R96, R97 | D14: automatically swap a limited Claudock profile via the service/system watchdog, never agent cron; §3/§10 retain session/history, room / grant / budget checks, quiescence and audit. |
| R98, R99 | The authorized existing judge host is the **pair of 24 GB-class A30 GPUs**; flash BF16 at short context runs the accuracy check there first, currently on one GPU. The 48 GB-class host serves the local executor model; moving judge work there needs the owner's word. Protected evidence keeps exact host/stop/rollback identifiers; §11 retains verified process ownership and no pattern kills. This document lane performs no host operation. |
| R100 | Preserve the owner's local/offline HTML delivery requirement; the supervising presentation track renders the reviewed Markdown separately. This lane's authorized output remains this one source file. |
| R101 | **Decided: CLEF-HOST = A.** Evaluate Clef only on the existing self-hosted Clef-flash on the authorized A30 host; no Cloudflare account/token or hosted Clef arm. Guidance/§11 record the target and configurable verified cap: copied evidence at 8,192, latest R106 report at 16,384. |
| R102 | **Decided:** Linux completion target 36 hours, about 2 h contract freeze then roughly 20 parallel Codex authoring lanes plus all available authorized Claudock headroom, continuous box verification and final integration/ladder. §11 replaces the old three-stream/day schedule; pending implementation defaults remain recorded and overridable. |
| R103 | **Decided:** every gating read gets the opencode `google-vertex/gemini-4-argon` cross review alongside the Claude read, with findings reconciled. This read-only review permission is distinct from R107's later hard-engineering exception; §10/§11. |
| R104 | **Decided:** maximum reasoning effort for every implementation/review lane: Codex/Claude `max`, maximum supported opencode Argon variant (`#high` in R107), with actual supported flags/version captured privately. §11 records it; no reviewer is launched by this document lane. |
| R105 | **Decided:** live acceptance may use any authorized Claudock profile with quota and the owner's Codex gcp setup, by the earlier ladder method: test logins written once onto a verified disposable acceptance box, destroyed and confirmed afterward. §10/§11 retain names-only receipts and cleanup proof. |
| R106 | **Decided: Clef context is adjustable**, not an A30 architectural 8k ceiling. The later operator report records a 16,384-token setting with memory fraction 0.86/concurrency 2, smoke pass and a near-full request silently cut to 16,377 tokens at 2.4–3.0 s. Guidance preserves the earlier 8,192 snapshot and requires a verified configured bound, full-token accounting and unchanged outage deadlines. |
| R107 | **Decided:** selected harder implementation tasks may use opencode `google-vertex/gemini-4-argon`, each in its own Git worktree, reviewed by Claude. The reported highest supported variant is `google-vertex/gemini-4-argon#high`; maximum effort means the actual highest supported setting, not an invented flag. §3/§10/§11 record the scoped engineering exception; this document starts none. |

The map now covers the supplied ledger through R107. Confirmed implementation
choices do not silently confirm the pending D1/D2/D7 readings.

## 2. Platform isolation and alternatives

**Decision:** use bubblewrap plus Landlock on Linux and a new sandbox-exec policy
on macOS, with a different unprivileged UID for each lane life on both. Provision
the service under a different UID again. A lane life starts at authentic start
or adoption and ends at clean; reusing its name creates a new life.

This accepts the proposed lightweight direction and adds UID separation. It
costs a small privileged launch helper and administrator setup, but avoids
relying on same-account process separation and gives macOS a reliable ownership
boundary. A container image or daemon per lane is unnecessary.

### Files and authority visible inside a lane

The following is the logical layout; macOS uses equivalent absolute directories
under its lane workspace because it has no bubblewrap mount namespace.

| Resource | Lane view and permission |
| --- | --- |
| Runtime and toolchains | Reviewed system executables/libraries and public SDK data, read/execute only. Never bind the host root or a user-owned tool directory wholesale. |
| Main project | `/work/main`, writable independent checkout by default; read-only for a read-only grant. Its own Git metadata belongs only to this lane. |
| Extra data | `/data/<grant-id>` or `/work/<repo-id>`, with each recorded mode. A live writable Linux projection must satisfy §5's UID-mapped single-writer/handoff contract; no implicit sibling repo access. |
| Home and vendor sessions | `/home/lane`, private and persistent across runs of this life; vendor settings/policy supplied separately read-only. |
| Temp, IPC and caches | Private `/tmp`, shared memory, runtime directory and writable caches. Optional shared cache inputs are immutable and verified, with a private writable layer. |
| Brief, policies and effective rules | A read-only, content-addressed projection for this lane. It contains no other instance's private configuration. |
| API | Only this lane's control socket and selected inference/credential endpoints. A socket grants no authority without OS identity checks. |
| Laneboss state, human home, other lanes | Absent/inaccessible. No state database, shared tmux socket, host SSH agent, Docker/Podman socket, system bus or whole credential directory. |

Read-only means the process cannot change that supplied object. It may read it
and write a derived copy in its private writable workspace; it cannot publish
that copy back without separate authority. Read access necessarily discloses
the granted bytes to that lane. Do not promise revocation can make it forget.

### Linux construction

#### Measured Linux feasibility evidence

The **Linux isolation spike** supplies evidence for namespace/filesystem construction
and the AppArmor administrator step. Its source is `spikes/linux-iso/spike.sh` on
`lb-spike-linux-iso`, revision `b38c634`; the earlier unrestricted captures used
`fc3d770`. These are separate spike revisions, not the product-code base.
The complete retained host records show **Ubuntu 24.04.5 LTS**, AWS kernels
`7.0.0-1013-aws` (amd64) / `7.0.0-1014-aws` (arm64), **bubblewrap 0.9.0** and
**Landlock ABI 8**. These observations do not prove the proposed 6.6/ABI 3 floor.

All paths in this table are relative to the protected evidence root
`~/.local/state/laneboss-top/evidence/`. Each directory retains the source archive
and its SHA-256 alongside the named verification output. No machine/account
identifiers are needed in this document.

| Evidence directory and log | Source | Observed result and scope |
| --- | --- | --- |
| box run `lb-spike-iso-bench` evidence, `verify-fc3d770-20261015-221904.log:152` | `fc3d770` | Initial benchmark capture: completion exit 0, **185/185**, zero failures. |
| box run `lb-spike-iso-stock` evidence, `verify-fc3d770-20261015-221907.log:152` | `fc3d770` | Initial stock-image capture: completion exit 0, **185/185**, zero failures. |
| box run `lb-spike-iso-bench2` evidence, `verify-fc3d770-20261015-222118.log:156` | `fc3d770` | Full host/results record: amd64, restriction **0**, profile `not_needed`, **185/185**. |
| box run `lb-spike-iso-stock2` evidence, `verify-fc3d770-20261015-222109.log:156` | `fc3d770` | Full host/results record: arm64, restriction **0**, profile `not_needed`, **185/185**; an AWS “stock” label did not imply restriction 1. |
| box run `lb-spike-iso-restricted` evidence, `verify-fc3d770-20261015-222311.log:95` | `fc3d770` | **Failed: 11 passed / 2 failed.** The unprofiled launch was denied, but `B.namespace_permission_diagnostic` failed to recognize “Permission denied”; `G.completed` then failed and the run stopped before profile recovery. Preserve this failed evidence. |
| box run `lb-spike-iso-restricted2` evidence, `verify-b38c634-20261015-222502.log:175` | `b38c634` | Restricted arm64: restriction **1**, original bwrap refusal, administrator-loaded **bwrap-only** AppArmor profile, subsequent unprivileged success, unchanged sysctls, **195/195**. The source diagnostic fix at `b38c634:spikes/linux-iso/spike.sh:176` enabled the full intended sequence. |

The measured paths and controls were:

- With `kernel.apparmor_restrict_unprivileged_userns=0`, the non-root bubblewrap
  availability probe succeeded without namespace-specific administrator setup.
  With it **1**, the original unprofiled launch was refused (“Permission denied”);
  installing the executable-specific profile once enabled the same unprivileged
  launch while both recorded sysctls stayed unchanged. The source checks the
  baseline before installing the exception (`b38c634:spikes/linux-iso/spike.sh:163`,
  `b38c634:spikes/linux-iso/spike.sh:506`, `b38c634:spikes/linux-iso/spike.sh:509`).
- In the minimal D layout, `/work/main` was writable, `/data/grant-ro` readable
  but write-protected (`EROFS`), and the fixture's host state and sibling paths
  were absent (`ENOENT`). A symlink could be created but writing through it failed;
  creating/writing the external hardlink failed. Parent-directory shell writes
  failed. Independent outside read-back and a canonical **fixture-tree hash,
  excluding only `lanes/a/worktree`**, showed no changes outside that worktree.
  This is a scoped fixture observation, not a hash of the whole host
  (`b38c634:spikes/linux-iso/spike.sh:214`, `b38c634:spikes/linux-iso/spike.sh:552`).
- Landlock write restriction worked alone and inside bubblewrap: permitted work
  and `/tmp` writes succeeded; outside create/truncate returned `EACCES`. The
  nested negative target was deliberately mounted **writable**, so a read-only
  mount could not fake this result; unrestricted copies succeeded first. Landlock
  here was write-only; the namespace supplied read hiding
  (`b38c634:spikes/linux-iso/spike.sh:275`, `b38c634:spikes/linux-iso/spike.sh:567`).

This is evidence for the proposed Linux construction, **not production acceptance**.
Separate lane/service UIDs, the production helper/cgroups, seccomp, controlled
egress, identity/RPC, credential adapters, descriptor/race coverage, real Claude
Code/Codex runs and macOS remain unmeasured by this spike. The root helper is
still needed for UID allocation and cgroup delegation; **that helper plus the
measured unprivileged bwrap/AppArmor route has not been measured together**.
Twenty warm `true` launches ran, but **their durations were not harvested into
the supplied evidence copy**, so startup p50/p95 remain unmeasured. They also do
not establish complete lane/runner startup or the 100-launch target below
(`b38c634:spikes/linux-iso/spike.sh:360`, `b38c634:spikes/linux-iso/spike.sh:597`).

#### Proposed service integration

1. The root-owned helper allocates the lane UID, workspace and cgroup v2 subtree
   and prepares privileged network resources. It switches to the lane UID,
   clears supplementary groups and drops capabilities before invoking the
   reviewed distro `/usr/bin/bwrap` launch. **Bubblewrap creates its namespaces
   unprivileged**, using the executable-specific AppArmor exception when the
   host requires it. This adopts the spike's measured namespace path; the
   production UID / cgroup / helper integration still needs its own proof.
2. In that setup, bubblewrap constructs a minimal root with user, mount, PID, IPC, UTS and
   network namespaces. Mount a fresh `/proc` for the lane PID namespace, a
   minimal `/dev` and private temp/shm. Do not expose host `/proc`, `/sys`, cgroup
   control, namespace descriptors or runtime management sockets.
3. Add the exact approved data and runtime projections. Bind read-only inputs
   read-only recursively, including nested mounts. Writable grants never include
   their parent directories. Reject mount layouts the backend cannot verify.
4. Set `no_new_privs`, drop capabilities, prevent setuid elevation, host namespace
   entry, ptrace of other principals and dangerous device/kernel interfaces.
   Use a reviewed syscall *deny* filter for these escape interfaces, not a
   program whitelist or a narrow build-tool syscall whitelist.
5. Apply Landlock to the filesystem rights available in the selected ABI:
   reading/execution on visible inputs/runtime and private work / home / temp,
   writing / removal / creation / truncation only on writable grants and private data.
   New build outputs and user-installed programs remain executable. Include `REFER` and
   `TRUNCATE` handling. Landlock is an additional boundary; it cannot subtract
   a denied subtree after allowing its broad parent. Never allow `/` and call
   that a protected-files policy.
6. Close every inherited descriptor except intentional pipes and explicitly
   prepared lane endpoints. A state/log file descriptor or host cwd must not
   smuggle access past the namespace. Only then exec the actual runner.

Run containment is the cgroup and PID namespace, not a sampled ancestry list.
Detached/double-fork children remain in the run and retain its lane identity.
The runner cannot move itself into another cgroup. The external supervisor owns
the kill handles and survives normal runner exit.

**Minimum supported baseline:** Linux 6.6 LTS or newer, Landlock ABI 3 or newer
enabled, usable user namespaces, cgroup v2 and bubblewrap 0.8 or newer with the
required options. This is a proposed support floor, not an assertion that every
distribution enables those features. Probe actual behavior at install/doctor
and pin a tested bubblewrap package in the support matrix. The existing socket
identity code already requires Linux 6.5 `SO_PEERPIDFD`
(`internal/identityd/peer_linux.go:32`); 6.6 avoids maintaining a separate lower
floor. Later ABI features may strengthen the backend without weakening the floor.

Landlock ABI 3 has no network rules: those arrive in ABI 4/Linux 6.7. Unix-socket
and signal scoping arrive in ABI 6/Linux 6.12. The 6.6 baseline therefore relies
on network/PID namespaces, separate UIDs and packet/IPC controls for those
boundaries, not on Landlock network/signal features it lacks. These kernel ABI
facts must be checked against the kernel's Landlock documentation in phase 1.
Debian 12's stock 6.1 and RHEL 9's stock 5.14 kernels are below this floor; their
distribution names alone do not imply support. An upgraded/backported kernel
must pass the same capability tests, not just a version-string comparison.

**Ubuntu 24.04 default AppArmor is a required target.** Its stock-install policy
restricts unprivileged user namespaces, but the measured AWS images had that
restriction **0**; detect the actual value rather than infer it from the distro
or architecture. The restricted-policy cell above measured **1** and established
the administrator recovery: install/read back/reload a profile attached only to
`/usr/bin/bwrap`, then launch bwrap unprivileged with the host-wide restriction
still **1**. The measured profile uses `abi <abi/4.0>`, `flags=(unconfined)` and
`userns,` (`b38c634:spikes/linux-iso/spike.sh:190`). This is an executable-specific
namespace exception, not the filesystem sandbox and not caller authentication;
it applies to users able to execute that bwrap. The service still constructs the
fixed outer layout, and no lane receives helper privileges or an arbitrary
privileged-command endpoint. Nested namespaces must remain within that outer
boundary. Do not make bwrap broadly setuid or turn off the host-wide restriction.

Administrator installation also provisions the dedicated accounts/systemd unit,
helper, cgroup and egress resources. The tested Ubuntu 24.04.5/AWS 7.0/ABI 8 cell
is recorded above; retain a restriction-on cell and the separate 6.6/ABI 3 floor
cell in §10. Private evidence keeps actual image/package identities and hashes.

After any privileged resource provisioning, bubblewrap, Landlock installation
and runner execution are unprivileged. **The complete design is not a no-administrator install:**
creating service/lane accounts, changing UID,
delegating cgroups and establishing network plumbing require a narrowly scoped
privileged helper or administrator provisioning. Neither the main service nor
the runner runs as root. The recommended response to missing namespace/LSM
prerequisites is to refuse an *isolated* launch and offer an explicit VM/container
backend. Whether the product also has a clearly labelled unprotected observation
mode is an owner decision under R26/R29 in §11; it is not decided unilaterally
here, and no such mode can claim an isolation pass.

### macOS construction

**Minimum target:** macOS 14, with certification of every supported major version
and architecture; require `/usr/bin/sandbox-exec`, a verified service identity
backend and a functioning privileged helper. This is a project support choice,
not the OS introduction date of Seatbelt APIs. Initial certification must cover
both Apple Silicon and Intel where those OS versions remain supported.

Use a LaunchDaemon for the service and a dedicated lane UID, never a LaunchAgent
sharing the human's account. The helper launches a per-run supervisor outside
the lane sandbox, then drops to that lane UID. Generate a new profile with deny
by default for file content access, explicit read/execute access to the tested
system runtime and granted inputs, and writes only to the work area/private
home/temp. Explicitly account for canonical `/private` aliases, case-insensitive
names, parent replacement, file linking and Mach/Unix IPC. Keep directory owners
and ACLs consistent with the profile; do not rely on mode 0444 on a lane-owned
file that the lane can chmod.

macOS native v1 uses independent copies/APFS clones, never hardlinks, for input
delivery. Read-only projections are owned by a trusted data UID and protected
by both permissions and Seatbelt; writable projections belong to the lane.
APFS clones are independent files, not live mounts. An explicit Linux-style
`delivery = mount` request is unsupported on the native backend and returns a
copy-or-Linux-backend route. No silent conversion from live data to a stale copy.
Live sharing on macOS is deferred pending a separately verified volume/ACL design.

Do not grant Keychain, launchd job submission, host Apple Events, accessibility,
automation, task ports, arbitrary Mach lookups or management sockets just to
make a runner start. Add the minimum measured system services needed by its
runtime; arbitrary build binaries within the lane remain executable. Missing
SDK access should identify a data/runtime grant to repair, not introduce a
command allowlist.

Use launch supervision plus kernel process identities and the dedicated UID to
find and stop even reparented children. The helper must prevent user service/job
submission that could launch a later process outside that run. It retains the
UID lease until there are no processes, connections, jobs or writable exports
left. A process-table failure is “containment unknown”, never zero survivors.
Do not recycle a UID on that result. This needs its own Darwin canaries; Linux
subreaper behavior is not evidence for it.

Sandbox-exec is a deprecated platform interface and lacks Linux namespace
parity. Certify the new file / read / process / network rules on real Macs; do not
extend the existing allow-default profile and infer success. If the kernel APIs
cannot meet the identity or confinement contract on a supported OS, native lanes
are unavailable there. A small Linux VM on the Mac is the explicit fallback.
R36 permits a Linux release while native macOS proof remains pending, provided
the product states that support boundary plainly.

### Network policy

Default to ordinary outbound Internet access for model requests, package
downloads, Git fetches and development tools. There is no per-command network
allowlist and no blanket refusal of `curl`, `wget` or `nc`. Deny access to the
host control plane (including container/runtime and credential administration),
the service/dashboard management sockets and ports, other lanes' leased listeners,
and cloud metadata endpoints. **Other private/LAN hosts remain reachable unless an
explicit org blacklist entry names a denial**; private-address space is not an
implicit allowlist. Apply these named management denies across address aliases,
redirects, IPv6 and rebinding. Do not pass proxy, SSH-agent or cloud credentials
by broad inheritance. A supervisor may delegate a project endpoint within its
own grants, but cannot grant a denied management endpoint.

On Linux, use a private network namespace and controlled forwarding/DNS with
packet rules on the host side. On macOS, use helper-owned per-UID packet rules
and Seatbelt restrictions on Unix/Mach connections. Account for IPv4, IPv6,
host public addresses, loopback, DNS rebinding and redirects. If those packet
rules cannot be established, fail networked launch rather than share the host
network. On Linux, a lane's own loopback servers and test ports work inside its
network namespace; publishing a port requires an explicit grant. An offline mode disables egress
while preserving private loopback tests and granted local inference.
Linux controlled egress adds helper capabilities `CAP_NET_ADMIN` for veth, routes and nftables, and `CAP_NET_BIND_SERVICE` for private TCP/UDP DNS on port 53.
The administrator must enable global `net.ipv4.ip_forward=1` for veth traffic to reach the uplink; the helper's read-only kernel-tunable protection remains enabled. This relaxes the host's global forwarding baseline, so the per-lane host firewall must be installed before a link comes up, deny all other destinations and IPv6, and withdraw the link on policy failure. Provisioning owns this host-wide choice and restores it when collecting the disposable harness.

Native macOS has no private network namespace. Its helper must lease explicit
local listener ports to a lane, restrict **host-local** bind/connect to those
leases and selected service endpoints, and deny sibling/management ports in the
kernel. Ordinary outbound Internet/private-LAN hosts remain reachable except
the named denies above. Test two real UIDs, including the host's own public
address. Do not claim a per-UID outbound rule alone identifies the recipient
process. Unmodified programs that require colliding fixed ports or unrestricted
ephemeral listeners need the Linux-VM backend until equivalent native behavior
is proved. That compatibility limit belongs in doctor and the support matrix;
it is not a reason to silently open all host loopback access. Phase 6 must prove
the proposed Seatbelt/packet-rule combination supports these leases at all;
this Mac-only proof is not on the Linux critical path.

The egress path forwards ordinary TCP/UDP traffic and does not decrypt TLS.
An inference credential proxy is a distinct, explicitly selected provider
adapter; general network forwarding cannot fetch arbitrary host files or
translate public traffic into access to a privileged host endpoint.

### Alternatives and startup cost

| Option | Decision and reason | Cost expectation to measure |
| --- | --- | --- |
| Separate users alone | Keep as one layer; insufficient for world-readable files and shared IPC/network. Add OS confinement. | Account pool setup once; no image boot. |
| Linux bubblewrap + Landlock | Default: direct process launch, no image management, kernel-enforced views and inherited restrictions. | Target warm boundary setup p95 below 250 ms, excluding data copy, credential refresh and vendor startup. |
| macOS UID + sandbox-exec | Native option after proof; low overhead but deprecated API and harder IPC/process supervision. | Target warm setup p95 below 500 ms, same exclusions. |
| Docker/rootless Podman | Optional backend for packaging/toolchain reproducibility. A service container alone does not isolate runners. Never pass its daemon socket to a lane. | Measure cold image fetch separately from warm container start; no universal comparison claimed. |
| gVisor | Optional stronger Linux syscall boundary if its compatibility and latency meet the task. | Additional runtime/support work; benchmark builds and model adapters. |
| Firecracker/other microVM or macOS-hosted Linux VM | Recommended for hostile dependencies/tenants or where native support fails. Separate kernel at higher operational cost. | Include VM boot, memory and file-transfer costs; no millisecond promise here. |
| Kubernetes | Defer to multi-host scheduling. Namespaces/RBAC alone do not supply lane filesystem isolation; each pod still needs the same data/identity contract. | Cluster operations are unjustified for the single-host default. |

These numbers are engineering targets, **not measurements**. Record p50/p95,
RSS and data size for 100 warm launches and separate cold launches in §10.
The Linux spike ran 20 warm `true` launches, but durations were not harvested
into the evidence copy; p50/p95 remain unmeasured. Full lane startup,
materialization, credential work and either real vendor runner remain pending.
Large repository snapshots may dominate startup; optimize only after the
independent-copy boundary passes.

### Windows and WSL roadmap placement

R90 explicitly keeps Windows support on the roadmap, at least WSL. First target
WSL2 with a Linux kernel meeting the same ABI / peer / cgroup floor, systemd/service
startup verified under WSL, and all private state/workspaces on its Linux
filesystem. Do not presume `/mnt/c`/DrvFS has the required POSIX ownership,
link and permission semantics; import selected Windows data as checked copies.
Prove user-namespace availability and that Windows interop sockets/executables
cannot launch a host process outside lane confinement. A dedicated WSL setup
may be needed; keep host/interop access absent until that proof. Native Windows
accounts/ACLs, process containment and authenticated IPC need a separate backend.
This roadmap is not an initial Linux/macOS gate unless the owner changes scope.
Its roadmap phase follows Linux and native macOS. Test both Linux Claudock/
Claude Code and Codex under WSL2, including login-slot/session continuation,
service socket peer identity and `laneboss serve` through WSL's actual systemd
setup. Windows-native vendor CLIs reached through interop are not an equivalent
proof of Linux confinement. The kernel must actually expose Landlock and usable
user namespaces; a “WSL2” label or kernel version alone is insufficient.

## 3. Runners, authentication and sessions

**Primary driver decision (D8): `claudock` (claudock-cli driving Claude Code) and
`codex`.** Their versioned adapters produce argv, private vendor state, a selected
credential slot, session identity and record stream. Later **R103/R107 explicitly
authorize scoped opencode Argon cross-review and hard-engineering operations**,
with the worktree/review requirements below. Record those exceptions in effective
role policy; the earlier two-driver rule cannot refuse the newly authorized
tasks. Bare `claude`, arbitrary other CLIs and generic shell/script agent launchers
remain outside this contract. Verify actual vendor binaries/manifests/hashes,
not basenames; ordinary coding tools remain blacklist-only.

No profile symlink may lead into a shared human/vendor home. Today's profile_swap
documentation requires shared Claude Code history (`docs/claudock.md:224`), and
the ladder's first probe stopped on worker homes linked to the shared `~/.claude`
(`SUMMARY-ladder-2026-10-15.md`, probe r60a). Preserve cross-profile continuation
without preserving that shared-history layout: each lane life has one private
vendor home and conversation history, independent of the selected login. Its
credential slot is swappable between quiescent runs; its history / cwd / session are
not moved to the new profile's global home.

The current Claude/Claudock templates use `--session-id`/`--resume`; init's Codex
definition has no resume (`internal/bootstrap/init.go:196`). The guide's manual
Codex example uses `resume --last` and explicitly cannot take turns
(`docs/getting-started.md:610`). Preserve the behavior distinction during
migration rather than pretending every runner has the same session interface.

R103 authorizes a **read-only gating cross-review** through opencode with
`google-vertex/gemini-4-argon`, alongside the Claude read. Later R107 also
authorizes **selected hard engineering tasks**, each in a dedicated Git worktree
and independently reviewed by Claude. These are explicit exceptions to the
earlier D8 direction, with their own scope/identity/evidence, not arbitrary
custom-driver authority or an exemption from grants/D6. The ordinary primary
catalog remains Claudock/Codex; any exposed Argon engineering operation must
carry the explicit R107 policy and tests. Record the actual maximum supported
variant: R107 reports `google-vertex/gemini-4-argon#high` as highest available.
This document uses supplied evidence and starts no reviewer/engineering process.

### Credential flow shared by both runners

**D13/ R91 secret delegation:** the spawner chooses per child which named
environment variables or secret files to inject, bounded by source handles it
was granted. Record name, type, source/version handle, parent grant and injection
outcome, never the value. Names in a caller's host shell do not become authority
just because they exist. Read only explicitly enrolled names through a human-
authorized import/broker path, keep values in protected memory/runtime slots,
and never enumerate/dump that shell environment. An undelegated name/file is
absent; a child cannot ask the store for a wildcard or mint its own grant.

**R95 accepted default:** put a narrow secret-store adapter
behind the credential worker. A lightweight encrypted store owned by the service
identity is the accepted default; local Infisical is an optional backend,
not a prerequisite. Its database/services and machine-identity lifecycle add
operations to a single-host setup, to be verified against its primary docs in
phase 1. The worker fetches only approved handles and injects them; no lane gets
an Infisical machine/admin credential or a general host-shell secret reader.
Protect/unlock the built-in store's key outside lane mounts and record rotation/
revocation by name. Replacing the store never changes parent-bounded grants.

Use authenticated encryption for stored secret records and separate protected
key material, with key IDs/rotation and crash-safe writes. A service restart
must reacquire its key through the approved protected provisioning/unlock path;
never place it in an environment dump, repo, log or lane home. The dedicated
service account/kernel remain trusted; encryption does not defend against their
compromise. Back up encrypted records and their key-recovery procedure separately.

1. The owner authenticates the chosen vendor/profile outside the repo and outside
   a lane, using that vendor's supported flow. Init/doctor do not sign in,
   select billing or send a model request. Record names and capability verdicts.
2. A credential worker outside the runner boundary owns vendor access. It is
   separate from the event service and exposes only the selected profile to a
   lane authenticated by launch identity. Its selection grant is bounded by
   the starter's profile-delegation grants; a label from argv is not enough.
3. Prefer a provider-supported credential/inference broker where it is actually
   compatible. Otherwise create a **private, run-scoped credential slot outside
   the checkout**, containing only that selected profile's required material.
   The vendor home points to that slot and this lane's session data. No entire
   `~/.claude`, `~/.codex`, SSH directory, registry or human Keychain is mounted.
4. Keep refresh and rotation serialized by profile in the credential worker.
   Do not blindly copy a runner-written auth/settings file back into the owner's
   store. Validate only the supported credential-refresh exchange. Shared refresh
   tokens whose provider rotates them need a broker or a single refresh owner;
   independent unsynchronized copies are not a supported concurrency strategy.
5. Revoke the run endpoint on stop; remove transient credential material after
   verified quiescence. Keep only selected account identity and auth outcome in
   events. Persistent session history excludes the credential slot from archives.

The model and tools may read credentials explicitly placed in their own process
environment or accessible slot. That is a disclosed property, not protection
against the model reading its own key. Other profiles, owner credentials and
broker administration must remain inaccessible. Use scoped/revocable credentials
where the provider supports them. File/env secret grants remain names plus
explicit source handles, never values in TOML, events, prompts or argv.

Use the following initial adapter choices; verify the exact vendor file/settings
contract before naming a build supported. A general credential proxy is optional,
not a promised replacement for a subscription login protocol.

| Selected mode | How the isolated process authenticates |
| --- | --- |
| Claudock long-lived headless token — first mode on Linux and macOS | Owner obtains the selected login's supported headless token outside the lane; the credential worker injects only its runtime token slot through the pinned Claudock/Claude adapter. Check the pinned CLI's headless-token support and lifetime before enabling it. No login Keychain is needed inside the Mac lane UID. |
| Claudock `apiKeyHelper` — second mode, both platforms | A read-only generated helper asks the credential worker for only this run's selected provider credential. Verify the actual helper contract/refresh behavior on the pinned build; it is not a general secret-store lookup. |
| Claudock API/provider profile — explicit fallback | A selected Claude/DeepSeek profile supplies its named API credential and provider configuration. API billing is an owner payment decision; never silently switch a subscription failure to this mode. |
| Codex file login — first mode on Linux and macOS | Private `CODEX_HOME/auth.json`, explicit file store, one refresh owner per login and no host-keyring fallback. Prefer an outside refresh worker plus access-only run projection if the pinned CLI supports it. Otherwise lease the full login to one active Codex process at a time so that process alone refreshes; the worker does not race it. |
| Codex API/provider profile — explicit fallback | Selected environment secret or one-profile file representation only. A local-model profile uses its granted inference endpoint without a cloud key. A paid provider change still needs owner approval. |

The slot and environment are runtime-only, excluded from repo snapshots and
fixture HOME directories. A brokered live test uses an authorized credential
endpoint instead; credential-free fixtures never receive a real login file.
Refresh safety and concurrent second-turn behavior are support gates for every
login mode, not just for initial sign-in.

For the serialized Codex file-login fallback, the service holds a per-login
lease through process exit and quiescence, then the credential worker imports
only validated credential fields through the versioned refresh adapter; it
never imports arbitrary settings or transcript bytes. If provider validation or
safe file import is unavailable, keep that login serialized in its credential
worker-owned runtime until a supported adapter exists. A second lane waits for
the lease; it does not get an unsynchronized copy of a refresh token. Claudock
uses the same serialization fallback when a headless-token/helper mode cannot
support concurrency. Loss of a mode is recorded; it is not an automatic paid fallback.

### D13 task secrets and optional Infisical: provenance and delivery

Task secrets and the runner's own login/profile credentials are **separate
grants**. A task-secret name cannot select a vendor profile or unlock a store;
a runner profile grant does not inject the parent's other task secrets. Before
exec, the service fetches only the spawner-selected, parent-bounded named
environment variables or files from its selected secret-store backend. Files
are private read-only runtime projections outside the worktree; the fixed
launcher / socket / home environment cannot be overwritten by a task-secret name.
Start events record `task_secret_names` and `task_secret_file_names` plus opaque
grant/source-version handles and injection outcome, **never secret values** or
an environment snapshot. Cleanup revokes/removes the runtime slots after verified
quiescence. An agent may read the secret it was deliberately given; this is not
a promise to hide its own grant from its tools.

The owner confirmed the **native encrypted service-owned store as default**
(R95: “accept to your laneboss native secret store”). It ships in the Go binary
with no additional secret-store service to install. Lanes never connect to that
store or hold backend credentials. A narrow profile helper can obtain only its
current selected run credential; it is not an Infisical/native-store client.

The separate official-documentation fetch stopped with
`curl: (6) Could not resolve host: infisical.com`.
The following Infisical-specific facts are therefore **unverified in this lane**;
the cited official pages are verification targets, not pages claimed fetched:

| Backend claim to verify | Official documentation target | Design consequence while unverified |
| --- | --- | --- |
| Self-hosting needs a database and supporting services, increasing one-host operations | Self-hosting overview (infisical.com, "overview"), Docker Compose deployment (infisical.com, "docker compose") | **Unverified** dependency / version / sizing details. Do not make Infisical-only installation mandatory; keep the accepted native default. |
| CLI `infisical run` can inject fetched secrets into a subprocess | CLI run (infisical.com, "run") | **Unverified** exact flags, scope and child-environment behavior. Do not invoke it in a lane as a general injection shortcut. A service-side adapter must fetch only already-authorized handles. |
| Machine identities and associated roles govern nonhuman secret access | Machine identities (infisical.com, "overview") | **Unverified** exact permission / token / renewal semantics. No lane receives such credentials. If backend authority is broader than a lane grant, handing it to the lane could bypass Laneboss's subset check; the outside service mediates instead. |
| UI, versioning and audit features may suit larger orgs | [Official documentation](https://infisical.com/docs) | **Unverified** edition / version / retention details; optional adapter choice after primary-source verification, not a promised feature of the native store. |

These limitations do not reopen the accepted native default. The architecture
reason for keeping Infisical optional is to avoid requiring an additional
control plane for one host and to keep all backend authentication outside lanes.
Do not claim Infisical inherently ignores its own permissions: the risk is a
backend credential whose scope exceeds the particular Laneboss child grant.

### Claude Code through Claudock

Start Claude Code headlessly with the saved prompt input and an explicit
session UUID; resume that exact UUID with the same isolated session directory
and logical cwd. Generated hook settings are read-only; logs, projects, caches
and conversation history are private writable data. Every Claude Code agent
starts through `claudock run SELECTED -- ...`; direct Claude agent launching is
dropped by D8, even where an older guide recommends it.

Claudock receives a projected registry containing only the selected profile,
and a credential source for that profile. Its Linux private file-store mode and
macOS default Keychain mode are documented separately
(`docs/claudock.md:63`). For native macOS, enroll the selected headless token
outside the lane. If the owner uses a login Keychain as its source, a separate
human-session credential helper obtains only that approved item through the
OS confirmation path and passes a protected slot to the credential worker.
Neither the service account nor lane assumes it can unlock the owner's Keychain;
the lane does not receive broad Keychain access.
The dedicated macOS lane UID has no unlocked login Keychain, so Claude Code's
default macOS credential path does not work there. The companion adapter must supply an actual supported private file/broker mode
to Claudock/Claude. This design does not invent an existing “export profile”
command. If the pinned companion cannot consume that projection, implement and
verify the adapter before claiming subscription-profile support.

Keep Claudock room/quota selection and exclusions outside lanes, returning only
eligible labels/capacity on every turn/resume. After a limit, stop/quiesce the
old process, choose another eligible delegated profile, replace only its
credential slot, then resume the exact session in the same private vendor home.
For managed lanes, the service watchdog performs the swap/resume operation,
never an agent's `profile_swap` call or shared-home link. The portable helper's
quota/exclusion logic remains useful for human diagnostics/previews; it does not
force managed continuation. A parent can delegate a profile without receiving its secret.
Retain provider-affinity and the current cross-provider refusal instead of
overriding it (`docs/claudock.md:193`, `docs/claudock.md:224`). The ROTATE-HISTORY
row must prove profile A's first turn and profile B's resumed turn share only
this lane's history, including after a room/limit event; another lane's token
and history remain unreadable.

### D14: system watchdog, not an agent cron job

The service's run watchdog observes externally captured, adapter-validated
provider usage/session-limit outcomes and real exit state. It does not trigger
on a model/tool merely quoting “limit”, and never treats a guard refusal,
credential/permission error or cross-provider resume refusal as permission to
switch accounts. The same refusal/Instead protocol still applies.

On a recognized limit it records the outcome, quiesces the old run, then chooses
among current supervisor-delegated Claudock profiles with room and budget. It
atomically leases the chosen credential slot and resumes the same session/private
vendor home/worktree with a new run ID and freshly validated grants. Record
old/new profile handles, reason, room decision, watchdog actor, causing run,
operation ID, a screened limit-text excerpt/hash and the reference to the exact
outside-captured limit bytes, plus resulting resume/start; never credentials.
Headroom comes from the outside worker's bounded `claudock usage` check and
eligible profile/window state (`docs/claudock.md:125`), not the agent's estimate.
Keep exclusions, current model / provider / session affinity and per-login refresh
leases; a cross-provider refusal is not overridden. Paid profiles are
eligible only if already explicitly granted with the payment/usage choice and
budget, not automatically enabled as a fallback.

Serialize watchdog, loop, manual resume and stop so they cannot launch duplicate
turns. Stop / abandon / clean / revocation cancels pending auto-resume. If no profile
has room, record no-room and bounded service-side backoff/notification through
permitted channels; do not spin an agent cron/loop, create another lane to evade
a limit, widen the grant or buy capacity. WATCHDOG-SWAP tests successful limit
rotation, preserved conversation, single refresh ownership, no-room, spoofed
limit text and concurrent manual-stop/resume races.

“Keep profile_swap/cos” in the port inventory preserves quota selection and
interactive client/attach intent. In the managed product these are service
clients; they do not launch an unconfined host agent, add a third driver or
perform D14 swaps from an agent tool. A human's manual administrative change is
recorded as that action, not disguised as an automatic quota event.

An automatic profile swap is **continuation, never a lane/task failure or a
retry**. Preserve the same logical turn, conversation and worktree; create an
honest new process/run record with `profile_continuation_of` and watchdog cause.
Keep the vendor's real exit code and the observed limit, while dashboard failure/
retry counters exclude this validated quota transition and show profile-wait/
continuing instead. Do not reset remaining time/spend budgets, duplicate the
brief or claim mail delivered merely because quota ended a process. Bind mail
to the logical turn and acknowledge only its actual successful completion;
retain cut/unknown prompt evidence and the required recovery. Version this
change from old per-run returned-mail semantics explicitly.

No lane-scoped API can force a swap, supply room results, mark its own output
as an authoritative quota event or disable the watchdog. The watchdog/state/
capture and usage worker are outside the lane's UID and writable grants. Check
trusted adapter/provider-limit structure and fresh outside usage evidence;
quoted text or a forged event is not enough. An agent may stop its own work or
request an authorized stop under R26, which cancels continuation; that is not
permission to suppress watchdog policy or choose another profile. Test direct
tamper / kill / control attempts against the watchdog as well as spoofed limit text.

### Codex

Give each lane a private `CODEX_HOME`, private session database / history / cache,
read-only generated configuration and only its selected authentication material.
The adapter chooses the supported file/credential-store or provider-environment
mode for the pinned binary. Never copy the whole human home or let the OS
keyring fall back to the human's keyring. OAuth/ChatGPT login and API-key login
are distinct modes and both need their own adapter proof; one passing API-key
request does not prove subscription refresh works.

Start `codex exec` against the lane's private cwd. Capture the actual vendor
conversation identifier from the pinned CLI's structured output, store its
mapping to Laneboss session/life, and resume that explicit identifier. Do not
invent a Codex start flag that accepts Laneboss's UUID. A private one-conversation
home plus `--last` is a labelled legacy migration path, not the new turn contract.
The new adapter must establish the explicit mapping before Codex turns/adoption
are supported. Preserve full model names in records and the separate API alias
mapping (`docs/configuration.md:274`).

For both runners, the **external run supervisor's capture of the vendor output
stream is the primary record**, taken directly from stdout / stderr / structured
output pipes before a lane can edit a transcript. It appends ordered byte ranges,
stream identity and hashes to service-owned storage/spool. Vendor transcripts
are supplementary, mutable until captured, and retained with observation time,
hash and replacement/gap markers. Never call a later lane-side file an immutable
history of what originally happened. Capture is evidence of bytes emitted, not
proof that the vendor's claims are true. A full spool pauses/ends capture with
an explicit incomplete record rather than silently dropping bytes. stdout text alone
is not tool-call coverage: the current `codex` raw-record format is unsupported
(`docs/configuration.md:388`). Build its adapter from real pinned-version records,
report missing coverage honestly, and never claim the OS boundary depends on
transcript completeness.

### Built-in sandboxes and local inference

The outer Laneboss sandbox is mandatory. On Linux, a vendor sandbox may further
narrow it when a compatibility row proves nested operation, communication and
network behavior. It can never add host access. The default supported adapter
may use the vendor's documented external-sandbox/full-access selector **only
after** the outer launch gate is active; if outer setup fails, do not exec it.
That choice is recorded per run. On macOS, use the owner's replacement approach:
one outer Seatbelt sandbox and vendor sandbox disabled in a generated read-only
overlay. Existing code already creates a Claude overlay only for its Darwin
replacement (`internal/lanesandbox/claude.go:15`, `internal/lanesandbox/claude.go:55`).

On Ubuntu 24.04, a nested vendor sandbox may itself request an unprivileged
user namespace and meet AppArmor's denial unless its actual executable has an
appropriate exception. The spike measured bwrap's exception, not either vendor
sandbox. The proposed baseline disables the vendor sandbox only after the full
outer launch gate passes; **Claude Code and Codex inside that boundary are still
unmeasured**. Enable nesting only after a separate vendor-profile/setup proof;
do not disable the host-wide switch or give agent code helper privileges.

Keep vendor tool approval UI separate from OS confinement. A vendor permission
mode or an enabled hook is not proof of containment. Acceptance runs with the
vendor's inner sandbox disabled as well, so it cannot hide a missing outer
boundary. Capture vendor help/version and official authentication, sandbox and
resume documentation for the exact supported builds in phase 1. Official OpenAI
documentation retrieval was unavailable in this design session; the Codex adapter
behavior above is a required implementation contract, not a newly verified CLI
compatibility claim.

A local model is reached through a **Codex provider profile**, with the model
outside the lane as an inference-only service with immutable
weights; grant its endpoint, not its model cache, admin API or host filesystem.
An owner-selected in-lane inference process instead receives explicitly granted weights
read-only and private scratch, with resource limits. An inference-only endpoint
must not expose filesystem-loading or arbitrary tool-execution APIs. Offline
lanes can use it without Internet egress. Cloud model credentials are unnecessary
for that mode; hardware or paid services are not provisioned automatically.

Claude accounts and DeepSeek remain selectable behind Claudock profiles; local
and other supported provider models remain behind Codex profiles. They do not
add agent drivers. Drop the product's generic/custom agent-runner adapter and
bare-Claude launch definitions. Credential-free vendor stand-ins are harness
fixtures only, never a third production agent driver or authenticated AI evidence.

## 4. Service ownership, socket API and caller identity

**D11 / R88 confirmed:** retain one versioned, checksummed Go executable. The
proposed `laneboss serve` entry point runs the long-lived service under its
dedicated UID, owns state and serves the human dashboard; state-bearing CLI
subcommands are clients of its authenticated socket. This command spelling is
a proposed replacement for the current identity-only `service run`, not a claim
that `serve` exists at this base (`internal/cli/cli.go:45`). Help/version expose
local binary metadata only. Every state-bearing CLI command uses the socket;
offline backup verification runs service code in an explicitly frozen restore
context, never a direct client-side SQLite fallback. The core needs
no Python / Node / Go runtime; OS isolation tools, Git and the two vendor CLIs remain
explicit platform dependencies, and optional integrations/model servers have
their own runtimes. Package the reviewed helper mode from that same Go source/
release artifact under administrator ownership; never expose a general root
command endpoint or a separately drifting launcher version.

**Decision:** retain the single Go executable as CLI and service, but move every
Laneboss state mutation and authoritative read into the service. The inside CLI
is an RPC client. It cannot fall back to directly opening SQLite after an outage.

```text
Owner terminal / human dashboard
              |
     protected administration API
              |
  Laneboss service (dedicated unprivileged UID)
    | state + policy + events + delivery outbox
    | authenticated, typed launch requests
    v
  small privileged helper --> external run supervisor
                                  |
                       UID + OS confinement gate
                                  |
                        lane runner and its tools
                                  |
                 lane-scoped socket --> service
```

### D11 installation, inside CLI and coherent upgrades

The release artifact contains one Go executable for the human CLI, the service,
the inside-lane CLI and its restricted internal helper/worker modes. They are
the **same version and checked bytes**, with different OS identities and exposed
operations, not separately drifting products. A lane sees only a read/execute
projection of those bytes and its endpoint binding; it cannot select root helper
mode or give the helper a shell/argv to run privileged. Ordinary clients ask
the service socket; only the trusted service can reach the administrator-started
helper endpoint. CLI parsing or possession of the binary confers no authority.

Installation has two explicit parts. The normal checksummed immutable binary
install needs no Go / Python / Node runtime. An administrator then installs root-owned
versioned executable paths, dedicated accounts/pool and protected state/runtime
directories, systemd/LaunchDaemon definitions and the reviewed AppArmor/helper
setup. The helper is started with fixed protected configuration, not made into a
general setuid entry point. Register the human confirmation key/root grants
outside lanes. Optional vendor CLIs, isolation tools, Discord runtime or a
self-hosted judge are separate declared dependencies, not additional Laneboss
core runtimes or agent drivers. Source builds remain an explicit build path in
the required disposable build environment.

For upgrade, the human approves the exact release digest/version through the
administration path; any canonical org-resource / config / template changes also
require the L6-plus-human D6 transaction. Stop new dispatch/watchdog scheduling,
quiesce affected runs, drain outside-captured streams/pending effects, and keep
a verified frozen state / config / secret-recovery backup before migration. Stage
and verify the new immutable bytes, then update service / helper / client references
as one compatible deployment. No lane downloads a replacement privileged binary.

Clients and service negotiate protocol / schema / artifact generations. A mismatched
old client refuses with an upgrade route rather than opening a DB directly.
Old immutable bytes remain until their verified processes have ended. Run the
credential-free service/install and state/read-back checks before dispatching
new work. Rollback restores the matching frozen data and prior version, retaining
new work/history; relinking a binary alone cannot downgrade state. These are
proposed installer/service changes, not host operations run by this document.

### Accounts and deployment

| Component | Ownership and allowed work |
| --- | --- |
| Service, one per configuration | Owns state directories 0700 and files 0600, policy/rendered sources and journals. Never runs project scripts or vendor agents. |
| Privileged helper | Root-owned, administrator-installed; accepts requests only from the installed service identity. Creates namespaces / accounts / leases, controls cgroups or Darwin supervision/network rules and launches fixed reviewed executables. No arbitrary shell, URL fetch, path copy or “run as root” RPC. |
| Data/Git worker | Separate unprivileged sandbox with only the relevant repository/snapshot grants. Handles Git / import / export / archive content; it has no event DB, credential broker or policy write access. |
| Run supervisor | Trusted process outside the runner sandbox; owns pipes and kill handles, observes real exits and streams bounded logs to the service. Cannot be signalled by the lane. |
| Lane | One UID per life, no service / sudo / admin groups; owns only its private writable objects. |
| Credential and external-channel workers | Separate narrow workers; selected credential or channel capability only. Tokens never enter the general service API response or repo. |

Keep systemd and LaunchDaemon deployment, but replace the old identity-only unit
contract. The old systemd example restricts address families to AF_UNIX and the
service is explicitly identity-only (`docs/service.md:55`). The deployment section
is `docs/service.md:318`; its actual AF_UNIX restriction is `docs/service.md:360`.
Give delivery/network workers the needed access individually; do not remove
service hardening to let an agent run under the state owner's UID.

A service-owned runtime directory contains lane-scoped sockets with narrow
ACLs. Linux binds only the connecting lane's endpoint into its namespace. macOS
permits only that endpoint by profile and ACL. The client authenticates the
server UID and installed binding, preserving the current separate-user check
(`internal/identityd/client.go:20`, `internal/identityd/client.go:32`). Lane-local
configuration contains a read-only endpoint/configuration projection, not the
host's complete configuration. A Linux client must not assume the host service's
PID is visible in its PID namespace, or that host UIDs are unchanged inside a
user namespace. The helper supplies a verified server-UID/GID mapping and pinned
endpoint generation; the namespace-aware client authenticates that server
identity without reading host `/proc`. Keep all UID-changing capabilities and
setuid execution disabled, including after the mapping is installed. The host
service still authenticates the actual host-side peer and containment record.
These changes need a real namespace/socket integration row; the existing client
cannot simply be copied unchanged. Keep explicit `--config NAME`; a conflicting
binding is an error, not a reason to clear session labels.

### Authentication is not a label

Before releasing the runner, the service persists the launch record: configuration,
immutable life ID, parent life/start event, level / role / instance, lane UID, launch
ID, process generation, containment handle, grant/policy hashes and endpoint
generation. The service, not a client `lane-started` claim, establishes this
record in the new model. Its launch gate ensures no unregistered interval.

Linux authenticates socket UID/PID and a lifetime-bound pidfd, then binds them to
the service-owned UID / cgroup / launch record. Read host-side kernel facts, not the
PID number as seen inside the namespace. Detached tools retain the same lane UID
and containment membership. A UID change is rejected, not a fallthrough to a
broader supervisor. Compare process generation before credentials; never treat
credential drift as “try the parent instead”.

Darwin must verify `LOCAL_PEERTOKEN`/audit-token process generation against a
live kernel process identity, plus the lane UID lease and launch record. Exact
API availability and PID-reuse behavior are phase-6 Mac-only proof work. Snapshot
`LOCAL_PEERPID` plus start-time polling is not an approved mutation fallback.
Keep native mutation closed until its peer-exit, PID-reuse and cross-UID rows
pass. Separate UIDs help but do not turn the current read-only backend into a
verified implementation.

Environment, cwd, request `actor`, `--from`, `claim`, role and instance names can
select/check context but cannot create authority. Registration tickets remain
human-issued, short-lived and single-use, fixing configuration, level and role
at issue (`docs/configuration.md:556`). Never hand an administrator ticket to a
lane. The human UI cannot authenticate agents as human merely because they are
descendants of a login shell.

**Proposed R24/R44 change, awaiting the §11 owner decision:** for isolated
top-level bootstrap, the human reads the briefing, selects root data/profile
grants and requests a service-launched L6/L5 life. Under that proposal,
`laneboss start` keeps its briefing/bootstrap intent and a ticket cannot register
an arbitrary already-running host agent as isolated; it must import/relaunch.
This is the recommended R102 implementation default, not a claim that R24
already approved removing existing-session registration. Until settled, preserve
legacy history/briefing without calling that host session confined.

Unix stream credentials describe the connector, not every writer of a passed
descriptor; the existing limit is explicit (`docs/service.md:483`). Do not claim
otherwise. Prevent cross-lane descriptor passing by excluding shared Unix IPC,
closing inherited descriptors and refusing descriptor-bearing requests. Recheck
the live launch on each operation; close all connections on run revocation.
The platform proof must include a passed-connection canary. If a supported IPC
route permits transferring authority to a different principal, require a
verified per-message credential transport or remove that route before release.

### Proposed API contract

These operation families are a new protocol design, not commands already
implemented by this revision. Keep existing CLI names where their intent survives.

| Family | Service decision and response |
| --- | --- |
| Identity / status / briefing / settings / rules | Derive caller; return only the permitted projection and rule provenance. Unknown callers get non-sensitive health/read views, no registration or mutations. |
| Start / resume / turn / stop / adopt / clean / archive | Authorize against authentic lives, current policy and grants; execute through trusted workers. Return durable operation/launch IDs and actual state. |
| Event tail / status / log / artifact reads | Apply the same life / ancestry / content-class visibility rules before returning bytes. Never return a DB file, vendor auth slot or arbitrary host path. |
| Mail / report | Lane-scoped typed submissions with input bytes/hash, derived actor, D7 routing and service-owned envelope/receipts. They cannot append arbitrary events or authoritative decisions. |
| Decision / store reads and proposals | Read applicable protected records. A lane may send a bounded proposal or decided-question request up its report line; proposals remain non-authoritative and are never surfaced to another lane as a decision. |
| Authoritative decision commit | Authenticated human dashboard/channel answer with operation-bound proof, or recorded L6 plus a D6-approved exact diff. No generic lane `decision`/`store` mutation endpoint. |
| Ledger / box outcomes | Only the trusted outside cloud-test (`box`) worker writes fresh resource/ledger facts from its verified job receipts; lane requests cannot supply authoritative outcomes. Offline administrator migration may import marked history. |
| Tool / refusal / coverage observations | Lane hook observations are untrusted claims. The service verifies coverage against the outside run wrapper's protected primary vendor/tool stream and actual correlated raw records; a forged or missing hook receipt cannot satisfy `accepted`. |
| Raw event append | Absent from lane sockets. Internal service events derive from authorized operations; raw historical append is limited to offline authenticated administrator migration/import and creates no live authority. |
| Owner / dashboard / gateway administration | Separate human/channel authority; absent from a lane endpoint. A lane reports up instead. |
| Data grants and outputs | Resolve parent grant IDs and relative paths, not caller-supplied host paths. Return an approved materialization/transfer receipt. |

For `--brief`, `--message`, `--file`, notes and exports, the inside CLI reads or
writes the file **inside its own boundary** and transfers bounded bytes. The
service must not open an arbitrary client absolute path as its privileged UID.
Large inputs use bounded chunks with a declared size/hash; verify the completed
object before referring to it in an event. Tar/import readers reject traversal,
links outside the object, special files and unexpected descriptor transfers.

All requests have protocol/configuration versions, an idempotency key and a
request-content digest. Duplicate identical mutations return the original
receipt; changed content under that key refuses. Keep atomic store/projection
updates, durable launch intent and an outbox for effects that cross process or
channel boundaries. Reconcile a crash between intent, launch and reply by the
operation ID; never launch a second run on an uncertain retry. The current
event append already compares duplicate IDs inside its transaction
(`internal/eventstore/store.go:425`); the present identity journal has no endpoint
idempotency contract (`docs/service.md:294`, `docs/service.md:302`).

Do not hold a global lifecycle lock while waiting for a model, upload, event
tail or judge. Use bounded per-life serialization and a short store transaction.
Slow watchers have bounded queues and resumable cursors, separate from mutation
capacity. A dead service leaves lanes confined and run supervisors enforcing
budgets; it starts nothing new. Recovery drains service-owned pending records
in order. Never reopen legacy local registration because a socket disappeared.

### Human identity, tickets and direct approval

**Decision:** the owner's UID, terminal ancestry, a bearer file or an agent's
claim is insufficient for administration. Enroll a human confirmation key through
an administrator-controlled bootstrap ceremony outside every lane. Recommended
mechanism: a hardware-backed WebAuthn credential requiring user verification/
presence, with its public key pinned in protected service state and the expected
dashboard origin/RP identity verified. Phase 1 must prove the local deployment
origin and authenticator flow; an independent owner confirmation device/channel
that no agent can reach is an alternative owner choice in §11. No hardware or
paid service is acquired by this design task.

The service issues a fresh challenge bound to configuration, operation, target,
exact request/diff digest, base generation, expiry and single-use nonce. The
trusted human UI displays that operation/diff, then returns a verified assertion;
the service checks signature, origin, presence, nonce, expiry and unchanged
content under the commit lock. This proof is required for ticket issuance, root
grants, human messages, key/channel enrollment and every D6 approval. It is not
a generic session permission for future changes. CLI administrators review the
same service-held request through that confirmation UI; no secret approval token
goes into an agent prompt or shell argument.

Read-only dashboard idle expiry is an **org setting, default eight hours**,
minted after human verification, configuration-scoped, revocable and kept outside
lane homes. Keep the session visible/revocable for long observation (R29).
Mutating requests require the fresh operation-bound proof above;
Origin/CSRF checks and the authenticated human session are still required. A
process the owner runs manually under the owner's UID cannot issue tickets or
approve a diff just by reaching the socket. **Residual:** an unconfined hostile
owner-account process may steal an active read session or manipulate a trusted
browser's display; hardware presence is not a proof against a compromised human
desktop or an inattentive approval. State this limit, isolate manual agents too,
and use an independent confirmation device for that stronger threat model.

### D6: all org resources, exact diff, L6 only

Canonical org resources are service-owned: tools, scripts, config, blacklists,
role and prompt templates, every config layer, plugin/catalog sources, notes,
**the decision store (`decisions.sqlite` and authoritative decision records)**,
and anything else in the org asset tree. No lane, including L6, receives a
writable mount. Only a verified human directly, or L6 through the exact-diff
D6 transaction below, may commit authoritative decisions. Lower lanes submit
proposals/decided-question requests upward; service validation never promotes
their report text into guidance for other lanes. Decision provenance records the
human/D6 approval and committed generation. Other org-resource updates use L6
plus direct human approval. Operational mail/log/event records and pending
store proposals are separate objects and convey no decision/ledger authority.

1. An authenticated **recorded L6 life** requests an editable draft/copy and writes
   proposed files with its file tool. Lower-level lanes may submit task artifacts
   to their parent, but cannot submit an org-resource update transaction.
2. The service stages exact source bytes and a manifest of all additions/removals,
   modes and hashes, the base generation, renderer/tool versions and derived
   outputs. Its operation-bound challenge covers that diff and generated effects.
3. The human reviews those exact bytes/diff through the independent confirmation
   path above. Record approver key identity, L6 requester/life, configuration/org,
   diff/manifest digest, base generation, approval time, expiry and nonce. Approval
   belongs to this change only; a session token or old “yes” is insufficient.
4. Under serialization, the service rechecks current L6 identity/role, unchanged
   base/diff, approval validity and nonce. It renders/validates in a confined
   worker and installs exactly the approved generation atomically. Record the
   approval and application receipts together; retries return that operation.

Missing approval, L5 / L4 / L3 requester, expired/replayed assertion, a changed file,
rebase, wrong org or a newly generated unapproved effect refuses without altering
resources. A changed diff requires fresh human approval. The refusal explains
the exact L6-and-human route; it never grants direct filesystem access. Initial
administrator enrollment creates the baseline; subsequent org-resource updates
all use this protocol, including changes to the approval policy itself.

### D3: spawn templates and retained scope

Resolve the effective `(level, role)` prompt template and immutable source
generation from service-owned org resources. Render role responsibilities,
assigned task, allowed tree relationships, effective blacklist/list source paths,
Laneboss-first routes, chosen worktree and exact grants. The spawner supplies a
task file, not a replacement policy/template path. Keep the source bytes/hashes
and the rendered prompt digest in the child start event. An absent role layer
inherits its documented org default; no numerical N+1 scalar inheritance is
invented while R45 is unanswered. Changing templates requires D6.

### D10: human dashboard data and actions

The dashboard is a human-only service client using the human authentication
above, not an agent-accessible local port. Browsing these views is read-only;
raw data renders as inert escaped text, never executable HTML or scripts.

| View | Authoritative service data | One required view test |
| --- | --- | --- |
| Decision store | Verified decision/history snapshot, exact text/provenance, relevance/recency metadata and version; no direct writable DB download. | DASH-DECISIONS: browse an actual seeded decision and provenance; a lane/unauthenticated request gets no data. |
| Raw messages and logs at every managed level | Outside-captured Claudock/Claude Code and Codex streams, immutable mail objects/events and supplementary captured transcripts, indexed by life / run / level / vendor and byte range. Show gaps/replacements honestly. | DASH-RAW: L3–L6 fixtures from both drivers reproduce exact stored bytes/mail; transcript tampering cannot erase the primary stream. |
| Org tree | Canonical instance/role sources plus authentic live/dead lane lives, levels, direct starters and descendant edges used by D7/D9. Distinguish configured instances from live launches. | DASH-TREE: L5→L3 and normal ladder edges render correctly; appended/forged parent labels add no authority or live node. |
| Refusal statistics | Service-stored hook / judge / OS outcomes with rule/version, probability, unavailable/critical status and source; aggregate by level / life / time without inventing zeroes for missing capture. | DASH-REFUSALS: known refusal/unscored fixtures produce correct separate counts and drill-down receipts. |
| Installed plugins | Protected installation manifests and D6-approved org/plugin catalog, versions / hashes / status and observed runner loading; label declared versus verified loading. | DASH-PLUGINS: installed fixture/version is shown; an unavailable inventory is an error, not an empty successful list. |
| Org scripts and tools | Service-owned resource catalog/source blobs, exact version/hash and the D6 approval/application history (who approved, which diff, when). | DASH-RESOURCES: view a real approved script/tool revision and its approval; browsing executes nothing and cannot update it. |
| Lane lifecycle | Authentic service projection/events for start, runs, resume, turns, stop, verifying, merged/abandoned and clean, with active / ended / pending state and real actor. | DASH-LIFECYCLE: drive a real lane through those valid transitions and compare every displayed life / run / state to committed service events within two seconds; missing/forged transitions cannot show success. |

Human message sending is an explicit action alongside those read-only views.
R94 confirms that the human also controls lanes from the dashboard: stop,
resume and mark merged/abandoned are typed authenticated service operations,
with the same current-life, review, budget and refusal checks as the CLI and
the operation-bound human confirmation. Record actor `human`, request/source,
operation ID and resulting lifecycle events; reflect them in the lifecycle/raw
views. DASH-CONTROL proves each operation and rejects the same unauthenticated
request. A dashboard mark cannot fabricate a Git merge or bypass acceptance.

For a message, the service authenticates the human and verifies a fresh challenge bound to target
life and message hash, stores the exact screened file bytes, and queues mail to
**any agent at any level**, including L3. Its sender/actor is `human`, with a
delivery/return receipt and source `dashboard`; an unauthenticated or lane
request cannot supply that actor. Mail reaches isolation through the same
service delivery/turn path as D7, never by opening a lane file or tmux socket.
Show the message, delivery and run correlation in agent history and raw-log
views. This inbound human exception does not grant L3/L4 a direct human channel:
their outbound reports still follow D7's report line. Existing guarded human
dashboard actions remain separate typed operations with their own approval
requirements, not mutations hidden inside a browse endpoint.

## 5. R71 data grants and cross-repository work

**Decision:** the supervisor writes a grant request file per child. The service
validates it, keeps the exact bytes and materialized identities, and records
the effective grants in the authentic start event before the runner executes.
The UI/CLI design must expose this as a file input; its final flag spelling is
phase-1 API work, not a flag to use with today's launcher.

The owner supplies the initial L6/root grant by importing selected project data
through an authenticated human-side client. That client reads only the named
source and uploads its bytes; a data worker creates an independent object.
Live exports must be explicitly enrolled broker-managed data volumes, not
arbitrary host paths with recursively altered ownership. A root grant neither
mounts the owner's home nor implicitly authorizes every registered project.

| Grant field | Meaning |
| --- | --- |
| ID and parent grant ID | Stable service-issued objects, bound to configuration and parent life; knowing an ID is not bearer authority. |
| Source | Registered repo / volume / snapshot and relative path or file; a repository also names a commit/history scope. |
| Access | Read-only or writable; child writes never imply publication to a parent/origin. |
| Delivery | Independent copy by default; Linux read-only bind or a single-lease live writable projection only with verified ID mapping/data-worker ownership. Native macOS remains copy-only. |
| Destination | A collision-free location in the child's logical data/work tree, never a runtime / policy / socket parent. |
| Delegation and expiry | Whether the child may regrant a subset, and its owner policy/lease generation. |
| Publication | None by default, or a specific reviewed output/import target and concurrency contract. |

The service checks these invariants by opened object identity and relative
resolution, not string prefix alone:

- A child source is contained in a parent grant; child access and redelegation
  rights are no greater. A parent with read-only `repo-b/api/` cannot give a live
  writable `repo-b/` or any sibling directory. Copying readable bytes into new
  private scratch does not grant write authority to their source.
- Private system/service state, credentials, other lane homes, runtime/admin
  sockets and human-home ancestors are never delegable data. Selecting an org
  directory for a project does not expose its control files. Export a project
  data view with those roots absent. The parent's level supplies no exception.
- Nested grants cannot widen a read-only subtree through a writable parent or
  alternate inode/mount alias. Reject ambiguous overlaps. Record source mount,
  file identity, snapshot/hash and destination identity in the materialization
  receipt; recheck before release.
- Resolve beneath an opened grant root without following escape symlinks or
  magic links; Linux can use `openat2` beneath/no-magic-link semantics. Walk/copy
  files by descriptors and recheck identity on Darwin. Reject external hardlinks,
  sockets, devices and FIFOs on data import. Do not recursively chown a supplied
  tree or preserve unknown ACLs, setuid bits, xattrs or file capabilities.
- A file grant is a fixed file snapshot. A directory grant includes its new
  descendants if live sharing was explicitly chosen; the manifest must say so.
  A copied snapshot does not grow when the source changes. Replacing a pinned
  mount/file name on the host must not redirect the run to a new object.

Resume and turn revalidate the grant chain against current owner policy and the
recorded parent's effective delegation rights. A completed parent may leave a
sealed delegation lease; its death does not invent new rights. An unresolvable
or revoked parent supplies no fallback broad grant. Expanding the parent's
rights never expands a child's running sandbox automatically.

For revocation, block new operations first, stop affected runs/descendants,
verify quiescence, revoke shared exports/endpoints, then build a new narrower
sandbox for the next run. An inherited Landlock rule cannot be relaxed or
replaced in place. Copied data already read cannot be recalled; credentials
already disclosed require provider revocation as well. Record the transition.

### Linux live writable export ownership and handoff

A Linux `delivery = mount`, `access = rw` grant requires either an **ID-mapped
mount** (`mount_setattr`, `MOUNT_ATTR_IDMAP`) or an equivalent confined data-worker
projection mapping the object to the **active leaseholder's UID**. Probe the
actual kernel/filesystem/idmap combination; a version string is insufficient.
If unsupported, refuse the live-mount request with the independent-copy route,
rather than chown the source or make a shared group/world-writable tree.

Only one lane life may mount that mutable generation. It is **never simultaneously
mounted into a parent or sibling**, even read-only; the worker is its scoped
observer. On handoff, stop/quiesce the writer and descendants, revoke mounts and
verify no writable descriptors remain. The confined data worker walks by
descriptors, rejects/scrubs escape symlinks and special files, strips unexpected
permissions/ACLs/xattrs/capabilities and creates a fresh sealed generation with
recorded hashes before another lease. Do not reuse prior-lane ownership blindly.
Immutable verified cache inputs are separate read-only objects, not a mutable
handoff channel.

A later parent/reader treats this generation as **unreviewed child code** under
§5's child-code rule: build/test it only within the child's grants, and publish
reviewed outputs explicitly. ID mapping repairs ownership semantics; it does
not make generated hooks/build scripts trusted. LEASE-HANDOFF in §10 must prove
both cross-UID successful controls and denied simultaneous/hazardous handoff.

### Git is data with its own escape paths

The current launcher selects a linked worktree beside the repository and
retains its common Git administration relationship
(`internal/lane/lifecycle.go:188`, `internal/lane/git.go:48`). Do not mount the
host common `.git` directory writable merely so `git status` works.

Default to an independent per-lane repository and object database, with the
requested branch/base identity recorded. No `--shared` clones, hardlinked
objects, alternates into host storage, shared hooks, credential helpers or
absolute `.git` pointers. A whole-repository grant specifies reachable history
and refs; a file/subtree grant gives a tree snapshot without an object database
that reveals the rest of the repo. Include submodules, LFS content and worktree
config only through separately checked data grants. Do not copy unrelated refs
or credential-bearing remote URLs.

Agents can commit and run ordinary Git commands in their own writable checkout
when org policy permits. Publication to a registered integration checkout is
an explicit parent/owner action: export a diff or bundle, validate its objects
and target, review/test, then import in the authorized integration workspace.
The state service never runs Git with repo-selected hooks, filters, config or
executables under the state-owning UID. Git parsing/import belongs to the
confined data worker. `lane mark --state merged` still records a decision; it
does not perform that import or a deployment.

### Child output is code, not a grant expansion

**Decision:** a parent may inspect a child's diff as inert data, but building,
testing, rendering with executable plugins, Git hooks/filters and any other
execution of child-written content must occur in a separate sandbox **no wider
than that child's effective grants**, intersected with current parent/owner
authority. The test worker has no parent session, credential slot, org-update
approval capability or broader service socket. Copy the candidate and inputs
through the artifact API; do not execute it in the parent's integration home.

Git import/parsing also runs in a confined data worker with hooks, filters,
credential helpers and repository-selected executables disabled. Promoting a
reviewed diff into an authorized integration checkout does not authorize running
its code with that checkout's wider rights. If required integration tests need
additional inputs, record a new explicit task/grant decision before proceeding;
never infer the extra rights from “the parent is reviewing”. A joint test cannot
silently union different children's private inputs. CHILD-CODE plants a parent-only
canary read in an actual child test/hook and proves it cannot access that data,
while an ordinary child-scoped build succeeds.

### Two examples

An L5 has writable copies of `web` and `api`, plus read-only `schema/public`.
It starts an L4 with those same or narrower grants. The L4 starts an L3 with
writable `web`, read-only `api/contracts` and read-only `schema/public/types.json`.
The L3 builds `web` against those inputs, reports a diff and cannot edit `api`.
The L4 reviews inert artifacts through the API, tests in the child-bounded
sandbox above, and only then imports the reviewed diff into its authorized copy.

For example, part of that child's **proposed request file**, not today's config
schema, would be:

```json
{
  "format": "laneboss-grants-v1",
  "grants": [
    {
      "parent_grant": "web-edit",
      "relative_path": ".",
      "access": "rw",
      "delivery": "copy",
      "destination": "/work/web",
      "delegate": false
    },
    {
      "parent_grant": "api-read",
      "relative_path": "contracts",
      "access": "ro",
      "delivery": "copy",
      "destination": "/data/api-contracts",
      "delegate": false
    }
  ]
}
```

The service adds the resolved parent life, source object/commit, effective
rights, materialization hash/identity and policy generation to the start event.
The caller cannot substitute an unrelated host path behind `parent_grant`.

For a coordinated API/client change, the L4 gives one child independent
writable copies of both `api` and `client`, with read-only test fixtures. The
child returns two diffs with base identities; the parent tests their combination
in a sandbox bounded by that child's two-repo grants before an explicit integration
action. Neither child gets another lane's worktree.
For coordinated live data on Linux, request one exclusive, UID-mapped writer
projection at a time under the handoff contract above. Parent and siblings use
separate reviewed snapshots, never simultaneous mounts of the mutable export.
A request requiring simultaneous writers is unsupported; use independent copies
and reviewed integration. No export may contain control state or host-home roots.

## 6. Lifecycle, visibility, communication and review

**Decision:** preserve the lane lifecycle and public command intent, with the
service launching sibling sandboxes on a supervisor's request. A child runner
is never forked out of an agent's already restricted process tree. The service
can therefore create a child without granting the parent state, Git-admin,
tmux or credential-directory access.

**D9:** for every agent start or adoption, the service derives the caller's
recorded level and requires `3 <= child_level < caller_level <= 6`. L5→L3 is
valid; L5→L5/L6 is not. Adoption checks this before import/registration, not
only on its later turn. The human bootstrap is the separate authenticated root
path, not an L7 agent. Record the actual direct starter life even when numerical
levels are skipped: D4 grants are bounded by that starter, and D7 relationships
follow those real edges. No environment or client `level` field changes them.

| Action | New execution and durable facts |
| --- | --- |
| Start | Authenticate requester; resolve role / drivers / settings, budget, account and grants; keep exact input bytes; persist launch intent; construct/probe boundary; record actual launch; release runner. A failed gate executes no agent. |
| Resume | Require ended, uncleaned life, zero survivors and the same valid session/workspace; recheck current policy/grants and selected account; create a fresh run sandbox around retained private data. |
| Turn | Preserve ordered mail/idle behavior and exact session; validate all carried senders separately from the requester; record request actor, trigger and message references. |
| Loop | Service scheduler starts eligible turns and respects backoff, room, idle payload ordering and budgets. It is a scheduler principal, not the first mail sender. |
| Stop / check / lost / gone | External supervisor/helper controls verified containment handles. Unknown observation never becomes a fabricated exit. Preserve reason, real exit/prompt status and survivors. |
| Mark/review | Authorized parent/reviewer checks diff, required tests, records and refusals. Successful model exit is never automatic acceptance. No self-acceptance. |
| Clean/archive | Stop all writers; verify archive / manifest / read-back receipt first; remove only owned disposable objects without force. Retain events, exact inputs, logs, raw-record inventory and reports. |
| Adopt | Keep historical adoption readable. New adoption requires a quiet session, explicit data/credential import, and its next run in a new verified sandbox; never label an already-running host agent retroactively isolated. |
| Attach | Relay authorized output / input / resize / stop through the service; no lane receives the shared tmux socket or another run's PTY. |

Use immutable life IDs in all relationships, not just lane names. Maintain
one lane/lease per work area across configurations, including nested/alias
overlap checks. UID leases and private endpoints are not reused until all old
processes and connections have ended. Reboot invalidates old process handles;
recovery records a real lost/unknown outcome, not a successful end.

### Fix the ladder's event visibility

A parent sees lifecycle / status / refusal summaries, authorized logs/artifacts and
reports for children it authentically started and their starter descendants.
Its own events and addressed messages remain visible. A sibling subtree's raw
logs, private mail and credential/session data remain private. Level alone is
not a configuration-wide read grant.

Derive this tree only from service-created start/adopt records and their parent
life IDs. Raw `event append` is not callable from a lane; only an offline,
authenticated administrator migration/import may append marked historical
observations. Such history cannot create parents, coverage, live runs or authority.
Apply the same decision in event tail, state events/lanes, status, store search,
briefing, dashboard-agent API and artifact reads. Direct DB access is absent,
so a bulk reader cannot undo filtering.

For `--follow --until`, first authorize the selected life, then stream visible
events from a consistent cursor. End only on an authentic event for the
selected life/run; a hidden event, historical run or appended observation does
not satisfy it. Preserve the existing `--since` usage after resume; the
current tail's external-event distinction must survive the port
(`internal/event/event.go:250`). The ladder acceptance must prove a parent
returns **within two seconds after the authentic selected end event is durably
committed**, under the defined healthy 20-agent/two-ladder test load, and a
sibling does not see that stream. Record commit/receive monotonic timings and
service event sequence; a disconnected/overloaded reader reports its deadline
or reconnects by cursor, not a successful end. The bound starts at commit,
separately from process cleanup time before an end can truthfully be recorded.

### Correct actors and keep communication usable

Manual resume/turn records the authenticated caller as `actor` on the launch
request and resulting resume/start events. Keep the original starter/report
line separately. Keep each mail's sender, original mail event and causing
sequence separately too. For an automatic turn, `actor` is the scheduler and
the recorded trigger names the mail/idle cause; it does not borrow a sender's
permissions. Revalidate all senders at delivery as well as enqueue.

**D7 relation checks:** upward reports go to the authentic direct spawning
parent (including L3→L5 when L5 started it). For peers, **“same direct spawning
parent” versus “same L5/L6 subtree root” is a proposed reading awaiting the
owner's 對**; recommend direct-parent siblings provisionally, not a confirmed
narrowing of “same root”. Include L3s below sibling L4s and mixed L5→L3/L4→L3
edges when the owner selects the rule.

For downward messages, use authentic starter edges, with **reading: “same tree”
= the sender's own starter subtree; awaiting the owner's 對**. The alternative
is any lower-level life sharing the selected L5/L6 root. §11 keeps both views.
The service evaluates the selected, versioned relation at enqueue/delivery;
MSG-REL tests that confirmed rule. Cross-root and direct upward skips remain
outside the report/channel contract. R102 permits the recommended narrow
implementation default while its status stays explicitly provisional.

Only L5/L6 may address the human, and only through that instance/life's granted
org-recorded channel: Discord role channel, owner file or dashboard. A missing
parent or channel never gives L3/L4 a fallback human destination. Channel grants
are canonical org resources and change only through D6. The service derives
these relationships from authentic parent lives and current grants at enqueue
and delivery; request labels do not authorize them. Human→any-level dashboard
mail is the explicit D10 exception in the other direction.

Service-owned mail reaches an isolated recipient as screened prompt bytes on
its authorized next turn, with sender / sequence / source and delivery/return
receipts; active runs receive a notification without exposing shared files.
R27 communication survives detaching and unsetting labels because OS
containment identifies the caller. `attach` remains a display/input source,
not authority. Keep `--ask`, file-backed messages and decided-answer handling.

### Event fields frozen in phase 1

Version the new payload contract and keep the existing envelope `actor`, `seq`
and `recorded_at` (`internal/eventstore/store.go:29`). Authentic start/adopt records add `life_id`, `parent_life_id`,
`starter_event_seq`, `root_life_id`, `requested_by`, `policy_generation`,
`grant_set_id`, `grants_sha256`, `prompt_template` (ID/source hash/generation),
`task_sha256`, `boundary_backend` and `endpoint_generation`. Resume/turn records
add `request_id`, `requested_by` and `trigger` (manual / mail / idle plus causing mail
event IDs); each mail keeps `sender`, `recipient_life_id`, `source` and its
content hash. `requested_at`/`observed_at` supplement commit time for latency;
none is client-provided authority. Record real `run`, `launch`, vendor session
mapping and prior run as today. External observations never synthesize these
authoritative relationships.

The frozen contract also names `task_secret_names`, `task_secret_file_names`,
`logical_turn_id`, `profile_continuation_of` and `profile_swap` (from/to opaque
profile handles, cause and captured limit-record reference). These preserve D13
names-only injection and D14 continuation without inventing a new identity.

Only reports addressed to the human reach its file/channel worker. Preserve
the corrected state-relative owner-file behavior already in this base
(`internal/report/channels.go:78`, `internal/report/channels.go:122`); do not
reintroduce the older bootstrap study's ConfigDir write. Channel delivery uses
a durable outbox and per-channel receipts. Partial delivery remains visible
and retrying it must not duplicate a successful owner message.

Give every lane a private report/artifact directory outside its Git tree.
The inside CLI submits report bytes, so a read-only task can report without
dirtying its repo or writing management files. A parent inspects returned
artifacts through the API or a narrow output grant, never by granting every
child home. Trusted cleanup freezes/quiesces live shared exports before taking
its archive snapshot, closing the arbitrary-writer removal window rather than
assuming a lifecycle lock stops all filesystem writers.

## 7. Org hooks: retained policy, deleted protection engine

**Decision:** retain blacklist rules and Instead routes as org policy, guidance
and records. **R64–R70 authorize moving file/worktree/obscured-call protection to
OS/service enforcement**; §10 must pass with the hook absent, disabled, bypassed
or allowing every call before deleting replacement-covered code. This architecture
decision is distinct from D2's still-pending judge-alone blacklist matching.
The reviews differ over whether exact legacy-code deletion also needs a separate
R47 confirmation; §11 records both readings rather than silently choosing one.
Retain that disputed deletion gate until resolved, while building the authorized
OS/service boundary. R46/R48 policy/Instead/history obligations remain.

Keep plain-language blacklist descriptions, refuse/warn bands, tool denies and the union of
org + own `(level, role)` + every higher level's roles. Keep the twelve
Laneboss-first entry identities and Instead routes, without broad secret,
network, script or Git bans. **Change the six `raw-tmux-*` seeds**: remove their
unconditional `pattern_only = true` / `argv_words` refusals and use descriptions
such as “using tmux to launch/control a raw agent session instead of Laneboss
start/stop/attach”. A private build/test tmux server is ordinary work; the
Laneboss management socket is absent from the lane regardless. This seed migration
requires D6 when applied to an existing org and must not wait for broad command
exceptions. Current inventory: `internal/orgtree/rawpack.go:5` (tmux seeds at
`internal/orgtree/rawpack.go:15`); role union is `docs/org-hooks.md:194`.
Retain twelve workflow entries, changing those six semantics rather than adding
a tool allowlist. Ordinary commands matching no explicit entry proceed.
The existing pack still routes its named raw agent / session / cloud-management
verbs through Laneboss; that explicit workflow policy is distinct from a
general ban on the tools themselves.

Today's optional patterns, `argv_words` and `pattern_only` are compatibility
inputs (`docs/org-hooks.md:115`, `docs/decisions.md:835`). If the owner confirms
D2's judge-alone reading, descriptions plus TypeSafe membership judgments
replace deterministic matching as the active command blacklist. Retain old
source bytes / readers / history, not a second hidden pattern refusal path. Until
that confirmation, retain the existing matching compatibility baseline **except
the six explicit tmux seed over-blocks changed above**; their old unconditional
refusals cannot survive as a hidden fallback against private build/test tmux.
This does not declare the global judge-alone replacement approved.

Keep lane-aware `org blacklist list` and its source/provenance display, and
point to it in every brief (R61). Human `try` remains a preview, not an agent's
trial-and-error workflow. Keep applicable decisions in briefs/turns and advisory
decision/job guidance; only an explicit refuse-band blacklist entry can turn
a judged match into refusal. Preserve bounded deadlines, unavailable notices
and honest incomplete observations (`docs/org-hooks.md:280`).

`org blacklist list` currently prints “Built-in refusals (not blacklist entries)”
(`internal/orghook/list.go:213`). After the approved migration it will show
“OS/service boundaries” separately from explicit org blacklist entries, including
the backend, grant summary, protected-state rule and Instead routes. A lane must
not infer that OS protection disappeared because it no longer sees a hook
refusal. Keep the command and source paths in every brief (R61).

### Conditional deletion and replacement map

Line references identify the current functions, not a patch to apply in this
documentation lane. The OS/service move is authorized; apply the exact deletion
map after replacement rows pass and the narrow R47 review disagreement in §11
is resolved. Remove tests as hook-protection assertions only after
the corresponding OS acceptance rows exist; retain relevant inputs as fixtures.

| Current code | Delete/change exactly | Replacement |
| --- | --- | --- |
| `internal/orghook/policy.go:1466` | Delete `builtInWriteRefusal`, `orgRootEntry` and `managedStateEffect`. | Service-owned objects are absent/unwritable; CLI writes are RPC, with no magic command exemption. |
| `internal/orghook/policy.go:1501` | Delete `hookLaneBoundary`, `recordedLaneWorktree`, `boundaryGrant`, `laneProcessBoundary`, `laneBoundary`, `rawLaneBoundaryRefusal` and `rawBoundaryWords` (through line 1748). | Uniform per-run OS grants, kernel process identity, private network/IPC. Remove the global `allow_worktree_writes` escape. |
| `internal/orghook/policy.go:1749` | Delete `builtInRawWriteRefusal` and the protected-suffix/alias heuristics it alone needs. Remove its call in `decide` at line 793 and the built-in gate in `decideBlacklist` at line 1937. | Same result for literal, encoded, aliased and opaque writes: the OS refuses. |
| `internal/orghook/writeeffects.go:10`, `internal/orghook/copyeffects.go:7` | Delete the speculative write inventory: `literalWriteCommand`, `findWriteTargets`, `literalCopierOperands` and their protection-only consumers. | No command-specific write enforcement. Explicit policy matching may retain literal argv extraction only. |
| `internal/orghook/xargs.go:161`, `internal/orghook/xargs.go:220`, `internal/orghook/policy.go:1216` | Delete `projectRawWriteCommands`, `projectArgumentFileWrites` and `rawProtectedScript`, including their calls from `decide`. | No second pass that predicts hidden write targets after an ordinary allow. |
| `internal/orghook/patchshell.go:23`, `internal/orghook/argv.go:630` | Remove `literalShellPatch`/shell-patch target projection and `writtenBy`/copier/find/sed/tar/Git write prediction from the protection path. | Vendor file tools and shell programs meet the same OS write boundary. |
| `internal/orghook/rawtargets.go:187`, `internal/orghook/rawtargets.go:451`, `internal/orghook/rawtargets.go:477`, `internal/orghook/rawtargets.go:574` | Remove `rawWriteTargets`, `rawTargetMatchesProtected`, `resolveWriteTarget`, `protectedRedirectSuffix` and assignment/alias tracking used to predict protected destinations. | No expansion interpreter or suffix guessing for access control. Keep small shared decoding helpers only where an explicit blacklist matcher uses them. |
| `internal/orghook/laneboss.go:24`, `internal/orghook/laneboss.go:35` | Delete `lanebossDeclaredWrites` and the inferred state-root/SQLite-sidecar write exemption in `lanebossCommand`. Remove `cliCall.pathEffects` protection metadata consumption (`internal/orghook/laneboss_syntax.go:207`). | CLI parser validates syntax; service validates actual requests. Shell wrappers do not acquire authority. |
| `internal/orghook/laneboss_code.go:27`, `internal/orghook/resolve.go:13` | Delete the built-in “obscured Laneboss” refusal scanner and label-assignment authority backstop; stop refusing an otherwise ordinary call because it cannot be parsed. | A copied / renamed / custom client still has only the authenticated socket caller's rights. Org-authored patterns remain policy. |
| `internal/orghook/receipt.go:17`, `internal/orghook/orghook.go:241` | Replace direct `hooks/callbacks.jsonl` writing and receipt-write-dependent blocking. | Bounded lane observations remain untrusted. The service correlates them with the outside run wrapper's primary protected vendor/tool stream; a fabricated receipt cannot pass acceptance. Telemetry gaps remain visible and never grant writable management directories. |
| `internal/orghook/policy.go:723`, `internal/orghook/policy.go:1260` | Simplify `decide`, `eventAction`/`actionEffects` consumers and `blacklistMatches`: remove the above protection calls and write-prediction fields. | Match explicit entries against tool / argv / declared vendor paths or judged text; default allow. |

Do not delete ordinary lexical helpers merely because the old protection also
used them. Retained explicit `path_glob`/secret-read entries can match literal
vendor paths and supported literal argv; opaque paths remain an incomplete
observation, with a judge notice where applicable. They cannot be advertised
as confidentiality for bytes already granted. To prevent reading a file in
every spelling, leave it out of the data grant.

Keep refusal reporting, historical suspicion/coverage readers and independent
text observations. A refusal remains a stopped action requiring its stated
route. Shell-write/rewording suspicion can remain an advisory/review tool in
the separate scan subsystem (`internal/lane/shellscan.go`, documented at
`docs/architecture.md:3617`); it must never be the OS protection boundary or
restore an implicit command allowlist. Record OS access failures distinctly
from hook refusals. `accepted` still requires supervisor review and honest
record coverage **verified by the service against outside-captured primary vendor
and actual tool/raw-event streams**. Lane UID authentication alone cannot make a
hook callback truthful. Correlate run/tool IDs and exact payload hashes; reject
forged/extra coverage and expose gaps. A text stream that never records a tool
call cannot cover it; missing vendor tool capture leaves acceptance incomplete.
A constant allow hook is useful for OS testing but cannot prove org-rule
compliance or repair that missing record.

## Guidance and judged blacklist

### R86/R101: replaceable provider, self-hosted Clef-flash only

Keep a versioned judge interface for D1 guidance and D2 blacklist membership:
named state/questions, pinned provider/model/stack, deadline/budget and complete
probabilities or an explicit unavailable result. Providers never select grants,
approvals or refusal thresholds. TypeSafe and self-hosted Clef share policy,
cache and audit behavior.

**R101 is confirmed: evaluate Clef only on the existing self-hosted Clef-flash
on the authorized 24 GB A30 pair, currently one GPU. No Cloudflare account/token
is used; the hosted Clef comparison arm is dropped.** The provider abstraction
remains replaceable, but it does not authorize another deployment target.

#### Inside hook → service → outside judge worker

The hook **inside** the lane sends D1/D2 requests over its lane-scoped service
socket. The service derives life/role/rule generation, validates scope and budgets,
and queues the **outside judge worker**. That worker, built in phase 4B, executes
the external-command adapter as a confined subprocess: one JSON stdin/stdout
object under the existing contract (`docs/judges.md:16`, `docs/judges.md:27`,
`docs/judges.md:33`; typed batches at `docs/judges.md:42`).

The worker holds any TypeSafe credential and reaches the registered local
forwarder/tunnel to the inference host's **`127.0.0.1:30000/v1/systemone`**.
The deployed endpoint or actual tunnel port is a protected service setting;
a lane's private `127.0.0.1` is a different namespace. The hook does not execute
the provider adapter, connect directly to host loopback, hold a provider key or
write `egress.jsonl`. The outside worker/service records reservations/outcomes,
`egress.jsonl` and the complete audit trail in protected state. It returns only
the scoped verdict/guidance receipt. Service failure is unavailable, not local
provider execution with broader access. Judge workers receive only screened
request bytes and inference access, never general management/secret-store rights.

#### Primary-source research and local deployment evidence

Retain the finished `lb-spike-clef/REPORT.md` with its gaps. Its research inspected
primary sources but did not itself run our hardware. This lane's earlier fresh
fetch stopped at `curl: (6) Could not resolve host: blog.cloudflare.com`;
independent fresh source verification remains unverified. Later runtime/deployment
evidence below is separate; secondary news is not primary verification.

| Research fact | Primary source recorded by the report | Limit |
| --- | --- | --- |
| Announcement 2026-10-01; repositories created 2026-09-30 | Cloudflare launch/changelog and publisher repository metadata | Reported primary dates; fresh re-fetch unverified. |
| Clef about 27.36B/BF16 repository about 55 GB; flash about 9.41B/about 19.1 GB | [Publisher model card](https://huggingface.co/Cloudflare/clef) and flash metadata | Artifact sizes, not measured serving VRAM. R101 evaluates flash only. |
| Apache-2.0 weights | Publisher LICENSE/model card | Research read the license header; fresh verification here unverified. |
| Fixed-option Noul, Choice and Score probabilities | Model card, launch and joint-schema reference implementation | Similar shape does not prove calibrated/drop-in Jev equivalence. |
| SGLang implementation and stack drift up to 0.068 | SGLang PR 42721 and publisher model card | Published cross-stack results, not a guaranteed error bound or our corpus result. |

Local source evidence **is now present** under the protected evidence root
`~/.local/state/laneboss-top/evidence/`:
`lb-clef-deploy-evidence`, `scan-copy/README.md:55`,
`lb-clef-deploy-evidence`, `scan-copy/README.md:93`, and
`lb-clef-deploy-evidence/scan-copy/smoke.py:13`,
`lb-clef-deploy-evidence/scan-copy/smoke.py:44`.
The source copy specifies the deployed flags, pins and smoke contract; this
revision reads it statically and does not run the client or re-audit the remote
host. The supervising deployment report retains the actual private deployment
log and measured responses; no private host name/path is published here.

#### A30 smoke, historical 8,192 setting and R106 update

`Cloudflare/clef-flash`, revision prefix **`8b2e5fd1…`**, is reported serving
through the pinned SGLang image on one of the authorized **24 GB A30s**, bound
to **`127.0.0.1:30000`**. The two command cases each ask **one Noul and one
two-option Choice question** (`lb-clef-deploy-evidence/scan-copy/smoke.py:44`,
`lb-clef-deploy-evidence/scan-copy/smoke.py:143`). Matching/non-matching P(yes)
was about **0.95/0.01**, at **about 85 ms per command request**. This is two
requests/four typed answers, not a 302-item accuracy result or a p95.

The **copied deployment snapshot** used
**`--context-length 8192 --max-prefill-tokens 8192`**, with
`max_model_len 8192` (`lb-clef-deploy-evidence`, `scan-copy/README.md:55`,
`lb-clef-deploy-evidence`, `scan-copy/README.md:93`). Its explanation of about
25 GiB at the generic 16,384 default was sizing arithmetic for those earlier
settings, not a permanent A30 limit.

**R106 supersedes a fixed 8k assumption.** The later deployment report in
laneboss's `owner-requirements.md`, row R106, records context
**16,384**, memory fraction **0.86**, maximum running requests **2**,
`max_model_len 16384`, a **63,665-token KV pool** and about **2.89 GB free GPU
memory**, with smoke passing. A near-full request (about **92 KB** of text) was
**silently cut to 16,377 tokens**, answered matching/non-matching about
**0.95/0.009**, and took **2.4–3.0 s**. Those are attributed operator measurements,
not a new run by this document lane or a verified full-context/no-truncation pass.
The earlier scan-copy remains historical source evidence; retain the newer exact
configuration/artifact/response bytes with corpus results. **32k was not tried.**

**Context is a service setting under D6.** The outside adapter validates the
actual pinned endpoint/configuration and derives effective cap `C`; it does
not hard-code 8,192 as a model/hardware maximum or assume every server has the
latest setting. The old snapshot requires requests **< 8,192**; the R106 setting
permits **< 16,384** only after its actual cap/template fit is verified. Count
the **complete formatted state + questions + criteria + serving template** with
the actual tokenizer and reserve a configured safety margin. Do not infer a
universal seven-token allowance from one truncated request.

The old 256 KiB guide bound is not token fit (`docs/decisions.md:861`,
`docs/decisions.md:877`). Unknown/stale configuration, unproved fit, a request
at/above its effective safe limit or any silent truncation is unavailable/partial,
never probability zero. Full state must survive; correct classification after
truncation is not sufficient evidence. Larger context also does not relax (b)'s
two-second command deadline: the reported near-16k latency exceeds it. Keep
bounded smaller/chunked command requests or report timeout under (a); D1's
separate guidance budget remains explicit. Raising a deadline/threshold is an
approved policy change, not a side effect of changing context.

Bounded chunking may split independent rule/candidate groups only while keeping
the **entire command and each question's necessary criteria/state** in every
relevant request. A verdict requires complete coverage; it cannot drop a suffix,
omit a critical rule, average a partial answer into “safe” or hide an overflow.
If that full context itself cannot fit, return unavailable. Cap-boundary,
long-suffix/CJK and missing-chunk controls are required before production.

#### Compatibility, calibration, cost and hardware scope

Jev and local SGLang use `/v1/systemone`; preserve the external-command schema,
typed validation and explicit normalized fields/version. Start with Noul/Choice.
The research flags differing Choice/Score `confidence` semantics and a suspected
Score-validator mismatch (`internal/typesafe/wire.go:317`); do not relax all
validators to pass it. The copied smoke validates the served model and joint-head
answers (`lb-clef-deploy-evidence/scan-copy/smoke.py:116`); the request's model
label alone cannot identify weights. Retain actual deployment pins.

Thresholds are **provider + exact snapshot + serving stack specific**. Published
drift up to 0.068 is not a bound on our errors. Calibrate and retain criteria/
threshold versions, apply D6 to policy changes and bind them in cache keys.
A failed provider is unavailable; no silent provider switch at old thresholds.

| Hardware/hosting scope | Decision, cost and evidence |
| --- | --- |
| **Existing pair of 24 GB A30s** | **Authorized R98/R99/R101 target.** Flash BF16 at short context runs the paired accuracy check here first; one GPU is used by the reported server, not an assumed two-GPU aggregate. Reported smoke about 85 ms; earlier snapshot at 8,192 and R106 reports a tuned 16,384 setting. Context is configurable; the near-16k 2.4–3.0 s result is not a two-second command pass. Measure actual corpus 1/12-question p50/p95, memory and concurrency. Existing power/operator/opportunity cost remains real; no rental is implied. |
| Existing 48 GB-class executor-model host | **Not authorized for moving this judge workload.** The earlier L40S recommendation is withdrawn for the current evaluation; moving there needs the owner's word and protects its existing executor model service. |
| 27B, rented GPU, GB10 or other targets | Deferred alternatives outside R101's evaluation. Capacity alone proves neither runtime support nor calibration; no new provisioning/payment or fit/performance claim. |

The hosted Clef arm, hosted pricing/latency comparison and hosted credentials
are dropped from this evaluation. Jev comparison cost uses actual approved
usage and the dated price source; no new payment choice is inferred. Self-hosting
keeps the selected model local but still has queue/OOM/crash/tunnel/restart
outages under (a). Local smoke gives no two-second p95 guarantee, no maximum
concurrency proof and no corpus accuracy. This document starts no new call,
deployment or host operation.

#### Clef-flash versus Jev: fixed approximately 302-item plan

R101 selects **only that self-hosted Clef-flash endpoint** for the Clef side.
The smoke has run; this corpus has not. Freeze labels, exact serving artifacts,
thresholds, token bounds and authorized secret/machine names before requests.
Use approximately **302 items**: 12 rawpack entries × five violating and five
near-miss commands (120); 16 public adversarial rows plus 16 quoting variants
(32); about 30 decisions with conflict/consistent/unrelated actions plus 20
decision-answer Choice items (about 110); 40 injection/over-budget/CJK/ANSI-C
cases. Label the revised tmux workflow meaning, including legitimate private
build-server near misses; legacy unconditional pattern matches are not truth.

One human labels and an independent pass checks; neither model creates ground
truth. Keep protected decision bytes screened and retained. Pair
`jev-1.14.0` / `jev-1.13.0` with the actual local flash stack using the same
typed, fully bounded requests. Verify live Jev availability; historical hashes
and probabilities cannot reconstruct missing prompt text
(`docs/judges.md:298`). There is **no hosted Clef comparison cell**.

Measure recall/false positives at 0.5 with 95% Wilson intervals, Brier/reliability,
paired McNemar disagreements, question/option-order flips, 1/12-question p50/p95
and validator rejects. Also inspect the selected operational thresholds; never
tune on final labels. Retain these research pass bars unchanged:

| Fixed acceptance bar | Required result |
| --- | --- |
| Alternative: recall | Within five percentage points of Jev, using the paired lower bound. |
| Alternative: false positives | No more than three percentage points above Jev. |
| Alternative: Brier | At most 1.1× Jev's Brier. |
| Alternative: order flips | At most two percentage points above Jev. |
| Alternative: bounds/shape | 100% of over-budget items unavailable/partial rather than low probability; zero validator rejections. |
| Default promotion | All alternative bars plus Brier at least 10% better than Jev and no worse injection-subset recall; then **two weeks of shadow asks**, acting on Jev and reviewing every disagreement. |

About 300 items catch gross failures, not differences below roughly five points.
Default promotion is distinct from completing Linux within 36 hours; retain the
incumbent default while the local alternative/shadow evidence is evaluated.
Infisical facts, full startup p50/p95, real runners inside the sandbox and macOS
remain separate incomplete cells.

D1 selects applicable history as context. D2 tests membership in an explicit
forbidden action with an Instead route. Neither grants files, credentials,
spawn levels, org-update approval or communication authority; OS/service checks
remain independent.

### Decisions, inheritance and responsibility examples

**D1 interpretation:** **proposed reading, awaiting the owner's 對**: each
Laneboss prompt-delivery turn (initial start, resume, mail/idle turn) invokes a
turn hook and one TypeSafe selection batch for similar past decisions. “Time
averaged” means newer decisions weigh more and older ones decay; it does not
mean delaying/suppressing a repeated reminder for a fixed interval. Whether the
owner means every internal vendor response as a turn is part of that pending
reading; do not silently charge a judge request per token or tool result.

**D2 interpretation:** **proposed reading, awaiting the owner's 對**: entries
are written in words, layered org-wide → `(level, role)`, and TypeSafe's judgment
that a command belongs to an entry itself allows/refuses, replacing pattern
matching. The owner has confirmed the separate responsibility rule with R76:
“對 永遠只有黑名單 永遠沒有白名單”. Keep those confirmation statuses separate.

Effective entries are the union of org-wide, the caller's own `(level, role)`
and all roles at higher levels, using R49's existing scope rules. A missing
local layer adds no denies and inherits the org layer; it does not mean “no
permissions”. Invalid source bytes are a configuration error before dispatch.
R45's numerical N+1 *scalar* inheritance remains unresolved; deny union is not
a reason to invent it. Sources, thresholds and critical flags are D6 resources.

| Responsibility example | Blacklist-only expression | Required control |
| --- | --- | --- |
| AWS/GCP E2E resources | Every non-testing `(level, role)` carries “Do not create or provision AWS/GCP E2E resources; Instead: ask the testing role through its report line / use laneboss box.” The testing role lacks that denial; no org-wide positive allow entry cancels it. Higher-level copies must be scoped to non-testing roles so inherited denies do not accidentally include the tester. | Non-testing resource creation is judged refused; a tester's properly delegated `laneboss box` request and ordinary read/build both proceed. Actual cloud credentials/budgets remain service grants. |
| Opening PRs | Non-publishing roles carry “Do not open or publish a pull request; Instead: report the reviewed diff to the publishing role.” The publishing role does not need a positive command entry. | PR creation under a listed role is refused; ordinary Git and an explicitly delegated role's PR action work when actually authorized. |
| Plugin usage | Roles that must not use a named org plugin carry that specific prohibition and an appropriate report route. Other tools/plugins are not implicitly banned. Plugin installation/update is separately D6. | Forbidden plugin use refuses; unrelated installed-plugin use/read works. |

These examples are bootstrap choices, not new seeded bans. R52 still seeds only
the twelve Laneboss-first entries. An ordinary command outside every applicable
deny proceeds even if it is unfamiliar to the hook. A role exempt from a scoped
denial is not an allowlist entry and receives no additional OS/service power.

### (a) Judge unavailable, timeout or exhausted budget

| Option | Consequence | Recommendation/status |
| --- | --- | --- |
| Closed for every unscored command | Outage blocks ordinary work, including unrelated tasks. | Do not choose as the default; conflicts with R26/R29 usability. |
| Open with notice and record for every entry | Ordinary work continues; an org's critical semantic denial may be missed. | Valid owner choice; OS/service boundaries stay intact. |
| Closed only for explicitly org-marked critical entries; otherwise open with notice and record | Critical command judgment is required only where the org chose that risk policy. | **L6/laneboss recommendation, owner decision pending in §11.** |

Under the recommendation, a timeout, unavailable / malformed / withheld answer,
partial input or per-turn/org cost cap is `unscored`, never probability zero.
For a refuse-band entry explicitly marked critical (for example secrets,
protected-state operations or raw network publication), unresolved judgment
within its role/scope stops the action with a critical-unscored reason and an
Instead route. Every other entry fails open with an explicit notice and audit
record. Warn-band entries never block. No critical classification is silently
added to the default pack or all network clients.

This can interrupt an otherwise ordinary command within an owner-marked
critical scope during an outage; state that tradeoff rather than call it a
confirmed R48 exception. The owner chooses the policy. Today's advisory guide
keeps baseline policy with a notice on unavailability (`docs/decisions.md:927`);
it is not evidence that this new critical behavior is already implemented.
An audit-service outage uses the external supervisor's protected spool; a full
spool gives a visible audit-gap notice and incomplete coverage, not a fake
record or a blanket ordinary-command refusal. Critical actions cannot proceed
without their required decision/receipt. No paid provider fallback is automatic.

### (b) Per-call latency, cost and positive-only judge skipping

Use one batch for applicable entries, not one network round trip per rule.
Proposed ceilings: two seconds total per command blacklist evaluation and
five seconds per turn's guidance selection, including queue/log-lock time;
timeouts follow (a). Retain the legacy 30-second combined guide/job and
60-second hook values as compatibility upper bounds, not an excuse to wait
that long on every new command. Measure p50/p95 at the named concurrent load.
Concurrency, request/token budgets and estimated spend caps are org settings,
with actual usage/cost and the owner-approved price source recorded. Cache hits
cost no new inference; skipped/unscored turns remain explicit. A budget stops
new judge requests, not ordinary unrelated work or a sandbox boundary.

A **judge skip list is a fast-allow optimization only**: exact authenticated
Laneboss self-observation calls (`whoami`/status/rule-list reads) and trivial
public project reads can proceed without asking when the approved effective
rules explicitly permit that exemption and no critical scoped rule is unresolved.
It never refuses a command; a miss goes through the judge. An explicit deny
cannot be overridden just because a program name looks safe. If a new rule
could apply to those reads, invalidate that exemption/cache. The list is not
an executable/tool allowlist and cannot be used to reject unfamiliar commands.

Cache key begins with `(normalized command, rule-set version)` and also binds
the complete raw payload digest, tool, effective `(level, role, instance)`, cwd,
grant/policy generation, judge model / criteria / threshold version and any declared
context dependencies. Normalization never executes expansions or drops quoted
arguments. Invalidate on a relevant rule / role / context change and use a short
proposed 30-second TTL; do not cache context-sensitive effects without those
dependencies. Service authorization and D6 approval are always rechecked, never
replaced by a cached semantic allow. Show a cache hit's original decision ID.

### (c) Untrusted command input and TypeSafe's actual contract

Commands, file text and retrieved decisions are data. Construct named JSON
`state.commands`, `state.rules`, `state.decisions` and context; do not concatenate
an agent command into system instructions. Fixed trusted `instructions` ask
whether `state.commands[0]` belongs to the forbidden action in `state.rules[i]`;
fixed `criteria.true` describes membership and `criteria.false` describes an
unrelated/permitted action. Text saying “ignore this rule” stays inside state.
Use one Noul per binary membership/relevance proposition; its probability is
confidence of that proposition, not severity. A near-0.5 answer is uncertain.

This follows the documented TypeSafe `state`/question `instructions`/`criteria`
split (`docs/judges.md:50`, `docs/judges.md:55`, `docs/judges.md:58`,
`docs/decisions.md:849`; official reference: <https://docs.typesafe.ai/api>).
Question IDs are lookup keys, not model instructions (`docs/judges.md:74`).
Validate full typed answers / model / usage; omitted / partial / truncated input is
unscored, never a safe judgment. Keep original bytes/hash and injection-focused
controls. This structure reduces injection risk; it is not a proof of semantic
model accuracy or a replacement for the OS boundary.

### (d) Every decision has an audit trail

Record the requesting life / run / turn / tool, exact input object/hash in protected
storage, effective rule ID / source / version / text hash, criterion version,
probability or `unscored` reason, selected and reported model, request ID,
threshold, critical flag, result/Instead, latency, usage/cost and cache/skip status.
No credential values enter events. Public exports use screened summaries;
authorized human raw views retain protected source bytes and withheld/gap markers.
Cache reuse points to its original receipt. Audit applies to allow, warn, refuse,
unavailable, skipped and over-budget outcomes, not just refusals.

Replay the recorded request against pinned adapter fixtures to reproduce the
policy decision from saved probabilities/thresholds. A live stochastic model
may return another probability: record that as a new evaluation, never rewrite
the old outcome or claim exact live reproducibility. Supervision can inspect
which entry caused a refusal and whether it was critical-unscored rather than
a confirmed semantic match.

### (e) Threshold ownership and default allow

Org defaults supply the membership/refusal threshold (proposed 0.85) and warning
threshold (proposed 0.50); `(level, role)` sources may supply explicit local
values. Bind each inherited entry to its defining scope's resolved threshold,
so a child override cannot silently weaken a higher-level denial. D6 governs
every change. A scored match at/above a refuse entry's threshold refuses with
that entry's Instead; a warn entry only warns. Below threshold does not create
an affirmative permission; absence of a matching deny simply leaves ordinary
work allowed. For a **valid complete scored answer**, `p < warn_threshold`
allows without warning; `warn_threshold <= p < refuse_threshold` warns with the
actual probability; `p >= refuse_threshold` refuses only for a refuse-band
entry (a warn-band entry still only warns). Thus the proposed `[0.40, 0.60]`
uncertainty label, if displayed, is descriptive only: 0.40–<0.50 allows and
0.50–0.60 warns under these defaults. It **never invokes (a)** or lowers a
critical entry's refusal threshold. (a) is reserved for actual errors/timeouts/
truncation/unscored input. These settings and outage policy remain recorded
implementation defaults pending owner choice, with D6 approval for changes.

### (f) R73 recency weighting and offered guidance

The following computation is **proposed reading, awaiting the owner's 對**, not
a claim that “time averaged” has been confirmed. Retrieve bounded applicable
similar **human-committed or D6-approved** decisions from the store per turn,
with source/version, authoritative provenance and current binding-policy status.
Lane reports/store proposals are never treated as cross-lane decisions.
Let `age_i = max(0, now - effective_time_i)` and
`w_i = 2^(-age_i / H)`, with proposed org-configured half-life `H = 14 days`.
The selected judge supplies each candidate's relevance `p_i`. **Require
`p_i >= warn_threshold` (proposed 0.50) before ranking** the eligible reminders
by `w_i * p_i`; no eligible candidate means no reminder, not five irrelevant
ones. Compute `S = sum(w_i * p_i) / sum(w_i)` over that eligible set, with zero
only for an actually empty eligible set.
Those are relevance/ranking values, not permissions or a severity measure.

Offer up to five relevant reminders after that one turn-selection hook, with
strong wording when relevant, exact decision IDs/provenance and a notice for
omitted/unscored candidates. A still-relevant reminder may appear on every
turn: no reminder cooldown/rate limit is inferred. Current binding approvals,
blacklists and authoritative decisions remain active regardless of age and are
included as policy context, not expired by recency scoring. Tests vary both
task and clock, exercise empty / old / new histories and prove policy never decays.

### (g) Isolation remains independent

The OS protects management state and data grants on every spelling and every
descendant. The judged blacklist steers/forbids explicitly described workflows,
including raw agent starts or assigned cloud / PR / plugin duties, with usable
Instead routes. A semantic false allow cannot expose an unmounted file or
write the service DB; a semantic false refusal remains a usability defect that
the ordinary-work and accuracy controls must catch. No allowlist is added to
make uncertainty disappear.

## 8. Port inventory: the cancelled release and existing product

**Decision:** retain the product's useful workflows, change their execution/
authority path, and drop the syntax-derived protection and unsafe compatibility
defaults. No implemented feature is silently replaced by “later”.

D8 changes the primary runner port to **Claudock and Codex**, with Claude/DeepSeek
and local models behind profiles. R103/R107 subsequently add explicit opencode
Argon cross-review/selected-hard-task exceptions, scoped and tested as §3/§10
specify. Bare Claude and arbitrary generic/custom agent launchers stay dropped;
“Keep” does not restore unrestricted custom-driver execution.
For D2 matching, keep source/history compatibility pending the owner's reading;
if he confirms judge-alone enforcement, patterns are historical inputs rather
than an independent active refusal engine (§7).

`D:N` below identifies line N in the supplied uncommitted 1.0.0 draft
`CHANGELOG.md`, not a published release or this checkout's changelog. Contiguous
draft bullets are grouped only when their disposition is the same. These are
port decisions, not assertions that the draft's claimed tests passed. Current
behavior claims elsewhere use repository `file:line` citations; the dispatcher
inventory is `internal/cli/cli.go:45`. The draft's historical Python descriptions
are history; the current executable is Go (`cmd/laneboss/main.go:1`).

### User-facing features and contracts

| Draft reference / feature | Keep / change / drop | Reason and port destination |
| --- | --- | --- |
| D:13, D:119–120 — deterministic Linux/macOS amd64/arm64 releases, SHA256SUMS, immutable installs, explicit source build | Keep | Preserve packaging, manifests, upgrade/rollback and checksum-before-execution; add separately installed service/helper artifacts and capability diagnostics. Checksums remain distinct from signatures. |
| D:14 — bundled claudock-cli, opt-out and explicit upgrade | Keep | Preserve companion choice and version verification; no automatic vendor sign-in. |
| D:15 — direct Claude/Codex and portable Claudock guides | Change/drop bare-Claude route | Rewrite for only Claudock/Codex, private history, swappable credential slot and actual authentication/sandbox matrix (§3). |
| D:16, D:180–183 — one-command org/project setup, source defaults/table order, top alias | Change | Keep transactional source/render initialization and runner selection; add an explicit administrator service-install step and root grants. Init launches no model. |
| D:17, D:97–100, D:121, D:325 — role library, built-ins, reviewer fallback, explicit role and exact driver policy, hashes | Keep | Preserve org source precedence, malformed-source refusal and start / adopt / resume / turn rechecks. Driver selection constrains what the service launches, not agents' ordinary commands. |
| D:18–23, D:221–227, D:327–329 — twelve-entry Laneboss-first pack and narrow init seeds | Change | Preserve twelve identities/Instead routes and existing-org D6 opt-in, but replace the six raw-tmux unconditional `pattern_only` seeds with scoped raw-agent-session descriptions (§7); private build/test tmux must work. No added secret/push/tool bans. |
| D:24–27 — ordered whole-word `argv_words`, flag-first matching, quoted-data control, `pattern_only` | Change conditionally | Preserve existing source bytes/readers/history. Proposed D2 judge-alone enforcement replaces active matching only after the owner's 對; no second implicit refusal path. |
| D:28–31 — role blacklists and higher-level union | Keep | Preserve own role plus all higher-level roles; no upward inheritance from lower levels. |
| D:32–37 — lane-aware blacklist list, source paths in prompts, human try | Keep | Read effective policy through the service; refresh source projection each run; agent reads list before work. |
| D:38 — report line, starter, level and permitted peers | Change | Bind to immutable authentic life IDs; enforce in the service and add ancestor event visibility. |
| D:39, D:261–263 — screened upward reports and per-channel outcomes, state-relative human queue only | Change | Service/outbox owns delivery; maintain terminal / mail / dashboard / Discord / file routes and visible partial outcomes. |
| D:40, D:187, D:215–220 — caller identity and unidentified read-only policy | Change | Kernel + launch containment + service-owned registration for all active lanes; unknown callers cannot start mutations. No environment-derived authority. |
| D:41 — human token-authenticated web dashboard, graph / lifecycle / activity / refusals / messages / logs / analytics / decisions / judges, EN/繁中, themes | Change | Keep every view and human action; dashboard becomes a service client, with token/Origin checks retained. It exists in code despite older walkthrough text (`internal/dashboard/dashboard.go:31`, `internal/dashboard/auth.go:22`). |
| D:42 — Node 22+ receive-only Discord gateway, allowed senders/channels, authority and reconnect/resume | Change | Keep gateway/filtering; grant only its delivery/receive capability outside lane sandboxes. Restart/history gaps remain documented, not silently called solved. |
| D:43 — bilingual owner `.xlsx` sheet, stable IDs, preserved answers / notes / closed questions and acknowledgment | Keep | Standalone human integration; one writer and external sync remain requirements. No spreadsheet or sync credentials enter lanes. |
| D:44, D:71–88 — applicable decisions in briefs/turns, TypeSafe advisory scores, decided-question answers, unavailable / withheld / window notices | Change | Keep guidance and honest unavailable outcomes; lane hook → scoped service socket → outside judge worker. Only authenticated human commits or approved L6 D6 transactions create authoritative decisions; lane questions/proposals go upward and are not cross-lane guidance. |
| D:45 — generated TypeSafe job catalogs, syntax/role sources, managed inventory caching, deadlines, stale/unavailable notices | Keep | Preserve catalogs, 30-second shared decision/job budget, at most ten remaining seconds per job ask and bounded hook timeout. Advice cannot become hidden command policy. |
| D:46, D:556–560 — AWS/GCP spot boxes, launch ledger, run/harvest, orphan collection and GCP live fence | Change | Keep provider / fence / cost / collection contracts in a privileged-capability worker, never a lane-wide cloud credential or host shell. Tests retain verified-machine transfer rules. |
| D:47 — credential-free install / start / resume / review / clean walkthrough and retained evidence | Change | Keep stand-in E2E, extend it through actual service / install / isolation setup. Continue to state it is not authenticated AI-service evidence. |
| D:48–65, D:127–129, D:192–204 — typed layered settings, explain / provenance / bytes, retained overrides, runner fixed, bounded environment grants/tool denies | Change | Keep precedence and union denies; service derives fresh delegation ceilings and materializes private paths. Values remain out of events; allow-add fields grant nothing. Future instance policy is protected by ownership, not enumeration. |
| D:66–70, D:130–135 — substitution observations, shared canonical payload/replay contracts, independent observation policy | Keep | Preserve advisory observations and exact event bytes/counts; no acceptance hold from observation alone and no access-control dependency. |
| D:89–91 — configuration-bound append-only records, keyword search, hashes/provenance, private names-only records and binary/credential refusal | Change | Keep data model and screening; filter every read by caller/life and keep all DB access behind the service. |
| D:92–96, D:138–155, D:164–166 — lane/daily archive, tar / manifest / read-back / uploader hash, receipt before unforced collection, retries/pending events and retained inventory/logs | Change | Preserve the complete contract, ancestry/life checks and failure behavior. Service quiesces writers and owns durable archive/outbox state. Never delete before verified read-back or force-remove dirty work. |
| D:116–118 — workspace source scanning, every flagged absolute line, prefixed / interpolated / grouped string credential recognition | Keep | Retain literal-aware scanner behavior and redaction diagnostics as publication/content checks, independent of confinement. |
| D:122 — protocol 1.3.0 and verbatim refusal/Instead recovery | Keep | Retain prior protocol bytes/hashes; version any new transport/grant semantics explicitly rather than rewriting historical briefs. |
| D:123–126, D:167–169 — per-run versus persistent account selection, room rotation, full model diagnostics and API alias expansion | Keep | Account/room work is brokered; credential switching preserves the session only when the provider supports it. Record full names while argv uses the configured API map. |
| D:136 — judge `org_dir` support | Keep | Resolve the same protected org source as roles/settings; no adapter-specific schema drift. |
| D:156–157, D:265–269 — exact refusal-first output, no-service notice, plugin argument limit and service ticket route | Change | Keep error/argument behavior and plugin briefing integration; active isolated mode has no open-registration fallback. A legacy offline view is explicitly labelled. |
| D:158–160 — judge egress reservations, bounded logs and killed-request accounting | Keep | Preserve reservation/outcome pairing and limits in the service/judge worker. Unavailable is not a fabricated probability. |
| D:161–162, D:170–172 — concurrent mail during stop, fresh permission/life recheck, attach display versus actor | Keep | Preserve queue semantics and actor separation; use per-life service serialization instead of a global lifecycle wait. |
| D:173–177 — authentic org retained on turn, current policy reload, idle payload ordering | Keep | Preserve these contracts while adding fresh grant checks and the corrected requester actor. |
| D:178–179 — `org validate` stable JSON and separate diagnostics warnings | Keep | Preserve the two-key JSON contract and explicit diagnostics form; expose service capability diagnostics separately. |
| D:205–214, D:443–444 — appended lifecycle history, origin markings, run/end spoof refusal, legacy mail markers | Change | Read marked history; raw event append is **offline authenticated administrator migration/import only**, never a lane socket. Service-derived events alone confer live authority; no imported event/receipt can fabricate parentage, coverage or run outcomes. |
| D:258–260 — one live lane per worktree, canonical/nested overlap checks | Keep | Extend to service-wide workspace/grant leases across configurations. A shared writable export is explicit, not overlapping lane ownership. |
| D:270–298 — protected tickets, current policy checks, issued level/role, single use, expiry/replay, adoption/first-turn integration | Change | Reuse ticket cryptography/policy and exact refusal routes; add native Darwin proof and launch-owned identities. Protect issuance from lanes and audit policy transitions. |
| D:331–343 — fixed environment base, names-only grants and reserved launcher variables | Change | Retain deny-by-default inheritance and subset delegation; synthesize private HOME / TMP / vendor paths and service labels rather than pass host roots. Credentials are explicit adapter inputs. |
| D:344–352 — historical unnumbered lanes and marked legacy reporting relationships | Change | Retain historical read/report compatibility; owner explicitly binds an imported life before active delegation. Do not promote old actor labels into new service authority. |
| D:353–355 — owner queue migration | Change | Import once into protected service state with hashes/receipt; retain the old file as evidence until read-back, rather than requiring a risky manual overwrite. |

### Existing features retained from the draft's development history

| Draft reference / feature | Keep / change / drop | Reason and port destination |
| --- | --- | --- |
| D:561–565, D:583–594, D:640–653 — generic rules, named configurations / projects / org rules, doctor, file-backed brief render / cost / preflight sections | Change | Keep names/binding, exact rule bytes and validation; service owns authoritative sources and exposes lane-specific projections. No configuration-to-instance guess. |
| D:587–589 — SQLite hashes, duplicate-safe appends, projection, event tail and state read / rebuild / verify | Change | Reuse storage invariants and replay; one service writer, scoped reads, owner-only rebuild. No lane gets SQLite sidecars. |
| D:595–605, D:958–1041 — lane routing, branch / base / workspace, budgets / quiet / limit / dropped, stop / status / check / mark / gone / clean, real exits / survivors / pending ordering/claims | Change | Preserve all user outcomes and diagnostics; independent Git data, launch intents and OS containment replace shared worktree admin and sampled-only tracking. |
| D:606–617, D:917–957 — raw-record refusals, suspicions, coverage, scan / list / review and acceptance gates | Keep | Preserve history and honest unsupported / cut / missing records; move collection outside the lane. Suspicion inference is evidence for review, never write protection. |
| D:618–639 — Markdown/JSON supervisor briefing and Claude plugin / path / manifests | Keep | Keep briefing groups, checks, recent events and plugin argument boundaries; a briefing still does not start an AI agent. Registration is a distinct authenticated side effect. |
| D:654–671 — stable session identity, stdin prompts and written/cut status | Change | Keep exact prompt/session semantics; map vendor-assigned IDs explicitly for Codex and preserve “written is not read”. |
| D:672–697 — immutable file mail, limits, ordered turns, delivery/return, waiting/idle state | Keep | Service owns files/events and screens input; maintain sequence, redelivery and per-run outcome contracts. |
| D:698–728 — singleton loop, idle / backoff / room scheduling, status/errors and filtered tmux environment | Change | Keep scheduling / status / backoff; run as service scheduler. Optional service-owned tmux/PTY is presentation, never an exposed lane management socket. |
| D:729–764 — attach, safe stream readers, notices / cost / mode labels, input / Ctrl-C / resize / exit semantics | Change | Keep terminal UX and output escaping; authenticated relay replaces raw socket access and keeps real stop ownership. |
| D:765–812 — account room contract, slot selection/exclusions, no-room behavior and quiet-session adoption | Change | Keep bounded room checks and adoption intent; room programs are isolated broker jobs and adoption crosses an explicit import/relaunch boundary. Do not claim the historical designed-only quota scheduler is built. |
| D:813–815, D:906–909 — publication scanner, optional private denylist and nonempty-input checks, pre-commit install hook | Keep | Retain content checks independently of OS isolation; private denylist bytes never enter a project/archive. |
| D:816–833 — external judge request / probability / egress contract, timeouts and credential screening | Change | Keep observable results and bounded accounting; no judge program runs with the state service's authority. |
| D:834–854, D:1042–1057 — portable decision DB, keyword / vector / hybrid search, embeddings/egress, import / export / load / migrate / verify and resident Unix search | Change | Keep formats/provenance and scoped queries. Lane `--db` uploads/imports remain private inputs or non-authoritative proposals; only verified human/D6 operations commit canonical decisions. Confined workers return bounded results; clients never open management SQLite or ask the service to open arbitrary host paths. Frozen legacy offline tools create no live decision authority. |
| D:855–868 — disk warning/stop latch shared by filesystem, resume/turn behavior | Change | Keep thresholds/latch semantics in the service; measure the actual lane/export filesystem and preserve honest unreadable-filesystem failure. |
| D:869–871 — installed-command/README walkthrough checks and Apache License 2.0 distribution | Keep | Preserve executable documentation checks, LICENSE and NOTICE; historical harness interpreter versions do not restore a Python product runtime. |
| D:872–874 — `cos` interactive helper and profile-swap integration | Keep | Keep standalone helpers, exclusions / subscription-first / explicit paid-profile opt-in and session affinity. Active lane switching is requested through the service; helpers never receive other profiles' stores. |
| D:875–881 — credential-bearing URL detector | Keep | Preserve shape-based screening and values withheld; it is a content safeguard, not complete secret detection. |
| D:1058–1070 — L3–L6 names and legacy level aliases, L1/L2 reserved | Keep | Keep level/role distinctions and lower-child authorization; no invented `reports_to` TOML key. Parent links are authentic launch data. |
| CLI ledger / refusal / tool views, org history/decision ingestion (`internal/cli/cli.go:45`, `internal/cli/cli.go:147`) | Change | Keep searchable scoped views; decision commits are human/D6, fresh ledger writes are trusted cloud-test worker outcomes, and tool/refusal coverage is verified against outside capture. Lane submissions stay untrusted observations/proposals; generic writes/raw event append are absent from lane sockets. |
| D:566–582 — old Python/source-fetch installer | Change/drop obsolete runtime | Keep immutable source-install/rollback intent, source/address checks and explicit trust warnings; Go remains the product runtime. CLI install stays user-local, while service/helper provisioning is an explicit administrator step. |
| D:910–916 — protocol 1.1.0/1.2.0 history and forward reads | Keep compatibility | A structurally valid store written under protocol 1.1.0 still verifies, reads and rebuilds after import. Preserve exact protocol/input bytes and hashes; new policy cannot rewrite old evidence. |
| D:1071–1122 — 0.5.0 configuration / event / projection incompatibilities and rollback | Keep documented limits | Retain the precise old compatibility matrix and frozen-copy rollback route (§9); do not relink an old binary onto a new active store. |
| R44, R54–R56 — complete Traditional Chinese Linux guide and bootstrap ladder tutorial | Change; ship with release | Rewrite installation/admin helper, human verification, two drivers, service-launched L6, D6 approvals, D7/D9, secret grants, review/archive, watchdog, dashboard and day-2 steps from actual tested CLI blocks. Phase 7 includes synthetic screenshots and privacy checks (R4/D10). |

### Removed mechanisms, resolved limits and retained limits

| Draft reference / behavior | Keep / change / drop | Reason |
| --- | --- | --- |
| D:104–115, D:188–191, D:246–257, D:299–310, D:311–315, D:885–904 — inferred effects, opaque-Laneboss refusal, ANSI-C / raw-target / copier backstops | Drop as protection | Delete the code identified in §7. Keep applicable explicit blacklist matching and old records; do not port grammar holes as the security model. |
| D:228–244 — L3-only boundary and org-wide `allow_worktree_writes` escape, raw network/detach blanket backstops | Drop | All levels get OS data grants. Cross-repo work uses per-child grants; ordinary network/detachment does not need a spelling exemption. |
| D:264, D:313–315, D:412–416, D:429, D:441–442 — Codex state writable root and PATH/hook as its integrity boundary | Drop | No lane can write state; authenticated RPC works for any client spelling. Keep immutable adapter/runtime selection for reproducibility, not file-write inference. |
| D:319–323 — strict/tool allowlists removed | Keep removal | Never reintroduce them under a sandbox or migration label. Retain compatibility metadata with a clear warning; explicit tool denies remain. |
| D:359–365, D:410–411 — Linux Codex-worker-only restriction; future-instance path expansion limit | Change | Service-spawned children enable a Codex-supervisor target; native role support still requires its adapter/turn tests. Service-owned policy trees protect future instance files too. |
| D:366–371, D:375–378, D:430–434 — same-account/open registration and human-login ancestry residuals | Proposed change, R24 decision pending | Recommend service-confined root launches and explicit legacy import/relaunch. Removing existing-session `start --role` registration awaits the §11 R24/R44 decision; preserve history/briefing and do not label a live host session isolated. R102 uses the recorded provisional default. |
| D:372, D:374, D:390 — demo versus real auth, review versus exit, checksum versus signature, sheet sync, own-key exposure | Keep limits | Publish those distinctions. None is cured merely by filesystem isolation. |
| D:373 — gateway restart/history continuity gap | Keep limit | Preserve current documented behavior; closing it requires its own receive-history contract, not this isolation port. |
| D:379–383 — unpassed medium/ladder evidence and obsolete post-release smoke promise | Change | Replace with §10's release gate on the exact new tree. A failed or diagnostic run is not publish evidence. |
| D:384–389 — reachable tmux socket and required writable hook callback directory | Drop | No shared control socket or writable hook policy/receipt directory reaches a lane; service relay and telemetry replace them. |
| D:391–409, D:439–440 — hook-version / alias / opaque-path / generic-route limits, unresolved delegation, advisory guide | Change | Pin tested runner versions; preserve honest blacklist/record limits and delegation refusals. OS denial replaces syntax routes for actual access. Guidance remains advisory. |
| D:417–428 — policy changes lacking live-run revocation/transition audit | Change | Record transitions; revoke API rights and stop affected containment before a narrower restart. Service outage never reopens authority. |
| D:435–438 — passed socket and unverified credential-drift/UID-hop concerns | Change | Address explicitly in §4 and gate on canaries; do not assert the old suspected conditions were exploited or already fixed. |
| D:446–547 — minimized test sets and retained private-suite removal inventories | Keep principle; change boundary rows | One meaningful contract/boundary check plus its control/mutant; convert the adversarial/write-shape corpus to executed isolation tests (§10). Do not restore deleted variants just to increase counts. |
| D:1124–1129 — designed-only features and historical Python/0.5 compatibility text | Keep as historical context | Do not advertise unimplemented quota inference, live executor messaging or unrelated remote-store features as part of this port. Supported current behavior is enumerated above. |

The cancelled draft contains contradictory “verified release run” and “smoke not
passed” statements, and some current docs contain older “not built” text. Port
the actual features/contracts, cite the source, and regenerate release evidence;
do not copy those outcome claims into a new release announcement.

## 9. Migration from 0.7.0 or a 1.0.0 candidate

**Decision:** perform an explicit, reversible, offline migration into new
service-owned storage. Never change ownership in place while old agents run,
and never let old and new writers share a store.

1. Inventory the binary/source revision, configuration/org paths, relocated
   state, SQLite databases and sidecars, inputs/protocols, mail, claims, live
   sessions, workspaces, decisions/embeddings, ledgers, hook receipts, archive
   attempts and owner queue. Keep an exact protected backup and manifest first.
   Report names/verdicts only; no credential dumps.
2. Freeze dispatch and loop scheduling in the old installation. Stop lanes by
   their verified identities and retain sessions/worktrees/evidence. Confirm
   actual quiescence; do not migrate a process based only on an ended event.
   Old stopped fix lanes remain evidence, not newly isolated running sessions.
3. Run the old version's verification on a frozen copy and the new importer's
   structural/hash checks. Corruption or missing evidence stops that import.
   Never edit old events or recompute hashes to make them pass. Preserve old
   protocol bytes, timestamps, event IDs, sequences and provenance unchanged.
4. Provision new dedicated accounts / service / helper and a new format/runtime
   binding. Copy verified state with a recorded migration origin and hash.
   Import history as history; do not infer active identity from writable old
   session/run files, appended lifecycle events or copied role labels.
5. Import org/configuration sources, then render and validate under the new
   service's ownership. Preserve authored blacklist text / Instead / scopes and
   role / settings / driver sources. Do not hand-edit generated settings/manifests.
   Translate external paths into explicit project / data / credential handles with
   an owner-reviewed root grant. No automatic whole-home or whole-state grant.
6. Offline authenticated administrator import retains reports, mail, records,
   decisions, embeddings, ledgers and archives with original bytes/receipt links.
   Historical relationships remain marked legacy until explicitly attached.
   Imported decision text is not automatically authoritative guidance: verify
   original human/D6 provenance or require a human-approved exact-generation
   promotion. Other records remain labelled history/proposals; import cannot
   manufacture live ledger outcomes, tool coverage or approval authority.
   Move an old ConfigDir owner queue by copy + hash/read-back + receipt, retaining
   the original; the new queue is service state. Do not replay delivered messages.
7. For unfinished work, export/import the exact tree, base/diff and selected
   conversation records through confined data workers. Screen archive exports;
   exclude auth stores and unrelated histories. Keep a stable logical cwd/session
   mapping. If the pinned vendor cannot resume the imported history safely,
   create a new lane with an explicit continuation report; never silently resume
   “last” from a shared home.
8. Bootstrap new supervisor identity through the human ticket path; run the
   credential-free walkthrough, state / mail / archive read-back and isolation
   canaries before active work. Only then select/authenticate real profiles and
   run the authorized live gate. Keep the old installation frozen for rollback.

Remove the old `lanes.sandbox = off/laneboss-files` choice from active isolated
mode if the owner approves §11's prerequisite-mode choice; a missing backend
must never be presented as isolated. A separately labelled observation mode,
if the owner chooses it, has its own binding/status and no isolation acceptance.
Remove automatic Codex
state writable roots and the `allow_worktree_writes` broad exception. Translate
legitimate exceptions into concrete per-child grants, and report ambiguous ones
for review rather than broadening them. Existing sources are preserved in the
backup even when their legacy keys become ignored/deprecated.

Keep existing config names and the user's live session binding. The importer
uses a separate isolated process; do not clear a binding to pass migration.
Changing schema / API / protocol requires a versioned migration note and negotiation;
the old CLI must refuse the new active binding cleanly.

Rollback stops/quiesces the new installation, exports any newly created work
and keeps both histories, then reactivates the frozen old copy with its old
binary. Never point the old binary at new state or claim the old mode has new
isolation. A failed migration leaves the original intact and its evidence kept.

### Earlier protocol stores and 0.5.0 rollback

Keep forward verification / read / rebuild of structurally valid protocol-1.1.0
history, including original bytes/hashes and the 1.2.0 version-only transition
(`docs/architecture.md:1830`; protocol/brief context at `docs/architecture.md:5543`).
Test an actual old frozen store through the
importer and replay; do not re-screen immutable old records as newly authored
policy or “repair” their hashes to make a new rule pass.

Preserve the historical 0.5.0 compatibility/rollback matrix
(`docs/architecture.md:2780`; draft D:1071–1122): old config parsing does not
understand `prompt`, `stream`, `{session}` or `[turns]`; new session / prompt / mail
payloads, kinds and projection fields exceed its readers. The new service/life/
grant format adds further incompatibility. An old launcher must not write a new
active store. Rolling back means quiescing the new service and restoring the
matched old binary **and its frozen compatible config/state copy**, after keeping
new work/history separately. Relinking only the executable cannot downgrade
data safely, and cannot claim the new isolation or D6 approvals.

## 10. Verification and release acceptance

**Decision:** acceptance must observe real kernel failures and successful
controls on the exact release binary. A hook verdict, a rendered profile, a
mocked denial or a successful runner exit is insufficient.

This revision performs document/evidence review and starts no new runtime run.
The Linux feasibility results in §2 already ran elsewhere; the reported A30
Clef-flash smoke is scoped in Guidance. Neither completes the product acceptance
matrix below, whose remaining cells are future implementation/release runs.

### Measured evidence and remaining cells

| Cell | Current evidence | What remains |
| --- | --- | --- |
| Linux namespace/filesystem feasibility, restriction off | §2's box run `lb-spike-iso-bench` evidence, box run `lb-spike-iso-stock` evidence, box run `lb-spike-iso-bench2` evidence and box run `lb-spike-iso-stock2` evidence: **185/185** each; complete amd64/arm64 records show Ubuntu 24.04.5, AWS 7.0, bwrap 0.9.0 and ABI 8. | Production service/helper integration remains; these fixture checks do not implement UID/cgroup/identity controls. |
| Linux namespace/filesystem feasibility, restriction on | box run `lb-spike-iso-restricted` evidence / `fc3d770`: **11 passed, 2 failed**, diagnostic recognition/completion failure. Then box run `lb-spike-iso-restricted2` evidence / `b38c634`: **195/195**, bwrap-only profile enables unprivileged namespaces while restriction stays 1. | Preserve failure and repair evidence. Production root helper for UID/cgroup plus that unprivileged launch route is still unmeasured together. |
| Minimum kernel/ABI and startup | Complete supplied records are 7.0/ABI 8. Twenty warm `true` launches ran, but **durations were not harvested** into the evidence copy. | Linux 6.6/ABI 3 image/custom-kernel procurement is phase-1 work; startup p50/p95 and full 100-launch lane/runner/RSS/materialization cells remain unmeasured. |
| Real agent drivers and macOS | No Claude Code/Codex-inside-sandbox or native macOS run is established by these Linux fixture results. | Both real drivers' auth / session / tool paths and the native macOS cells below remain pending. |
| Clef-flash accuracy and Infisical | Two A30 command requests each include Noul and Choice, about 85 ms, P(yes) 0.95/0.01. The local snapshot is **8,192**, and R106 reports a configurable **16,384** deployment with silent truncation near its limit; R101 remains self-hosted only. | Approximately 302-item paired Jev corpus, shadow evidence, load percentiles and Infisical facts remain unverified. |

### Machines, matrix and retained evidence

Named required Linux cell: **Ubuntu 24.04 with its default AppArmor setting**,
with the observed restriction **1** and no host-wide switch change. Capture the
unprofiled bwrap refusal, administrator install / read-back / reload of the bwrap-only
profile, subsequent unprivileged success and unchanged sysctls, following §2's
measured path. Add a separate unprofiled namespace control that remains restricted;
the bwrap executable exception does not imply all host programs gained it.
Then exercise the production helper's separate UID / cgroup / egress provisioning
and real read / write / network / process canaries. Keep a second required
**Ubuntu 24.04 AWS restriction-off** cell: bwrap succeeds with no AppArmor setup,
and the same layout/Landlock controls pass. This does not remove the full
service's administrator provisioning. The **Linux 6.6/ABI-3 floor image or custom
kernel is a named phase-1 procurement item**, not an image asserted to exist.
Record its exact source/image/kernel hash and boot/capability proof, then repeat
the floor controls without newer Landlock features. Until then, that support
cell is pending, not covered by the measured AWS 7.0/ABI-8 runs.
Below-floor Debian 12/RHEL 9 stock kernels must produce the documented unsupported
result, never a fabricated sandbox pass. Retain the actual spot image/kernel/
AppArmor / profile / package identity and root-helper installation transcript.

Build and run Linux units/E2E only on authorized disposable spot test machines,
one machine per lane at a time. Exercise the source installer and supplied
release artifact through the real deployment / service / helper path. Include
Linux amd64 and arm64, a minimum-floor kernel and the selected current distro.
Keep the bootstrap's exact inputs/assertions rather than a parallel simulation;
its current checker contract is `docs/getting-started.md:744`.

Native Darwin rows run only on an explicitly authorized disposable/owner test
Mac and are marked Darwin-only; do not run the whole suite on a development Mac.
EC2 Mac is not a spot substitute and a paid dedicated host needs a separate
owner decision. Verify native macOS 14 and each advertised major version,
architecture, case-sensitive and case-insensitive APFS. If no Mac is available,
report those cells pending and keep native isolation unavailable. Linux evidence
does not satisfy them.

The runtime matrix is **Claude Code through Claudock and Codex**, including
start/resume/turn/stop and actual direct-tool/descendant-program access. Linux
release gates its Linux cells; native macOS cells close independently in phase
6 and do not block Linux under R35/R36. Declare each selected auth mode and the
exact pinned vendor versions. Credential-free stand-ins prove wiring only.

**R105 decides the live Linux acceptance credentials:** any authorized Claudock
profile with quota and the owner's Codex gcp setup may use the earlier ladder
method. Verify the disposable acceptance box, record selected login/profile
names privately, transfer test logins **once** by the existing acceptance-secret
flow, confirm the box copy before removing the Mac staging copy, then keep each
lane's delegated vendor slot private. No source checkout, test fixture, prompt,
event or broad shell inheritance receives credential values. Actual profile
headroom and a successful own-profile turn are controls; another profile's
credentials/history remain inaccessible.

After collecting screened evidence, destroy the credential-bearing box and
confirm termination/destruction with names-only receipts. A missing receipt or
uncertain destruction stays pending. This approved live acceptance path need
not wait for every production credential-broker mode; the Linux credential
worker/selected session mode in 4A must still function. No credentials are moved
or model calls started by this document revision.

For each phase retain source/input archive, exact binary / helper / vendor bytes
and hashes, OS / kernel / LSM / architecture / backend versions, grant/profile bytes,
names-only launch/identity facts, syscall results/exits, events, logs, manifests,
receipts and collection status. Keep raw sensitive evidence protected and gate
export on the privacy scan; never “fix” a failed scan by editing transcripts.
Copy evidence back at the end of each phase and verify its hashes before
collecting the machine.

### Prove a real OS boundary

Plant unpredictable harmless canary bytes outside the lane, with an observer
that can read them. Include a world-readable file to prove read confinement,
not merely that a secret happened to be mode 0600. Run the same syscall helper
outside confinement against the same disposable canary to prove it exists and
the operation would otherwise work. Inside, execute the actual operation with
the hook absent or forced to allow and vendor inner sandbox disabled. Capture
the real syscall return and errno, then independently read back bytes, inode/
directory state and any outputs from the observer. No canary operation targets
real human or production state.

| Boundary row | Required inside result | Positive control / mutation that must fail the check |
| --- | --- | --- |
| Service state: DB, journal, policy, future instance settings, receipts, mail, owner queue | Cannot open/read or modify direct state; public projection is a different object. State/grant hashes unchanged. | Authorized RPC works; exposing a canary state file or running as the state owner lets the canary operation succeed and fails the assertion. |
| Other lane, including sibling and old reused name | Cannot read its canary, alter work / temp / history or signal/drive its runner/socket. | Own lane equivalent succeeds; widening a mount/ACL or reusing a live UID must fail this row. |
| Outside all grants and human-home canary | Read / open / list / write / create / unlink / rename attempts fail at the OS. Linux hidden paths may give ENOENT; observer proves they exist. | Same helper on a granted copy works; broad home/root binding or Darwin read exception must be caught. |
| Read-only grant | Reads succeed; open-for-write, truncate, append, mmap write, unlink / rename / chmod / link tricks cannot alter the supplied object. | Same program with a separately authorized writable object succeeds; dropping read-only/permission enforcement fails. |
| Allowed work | Build / test / package install, scripts, Git including a push to a disposable test destination with an explicitly granted credential, shell substitutions, private temp/cache, a lane's own private tmux server, own-process kill/detach and permitted network actually complete. | A broad denial must break a control and fail. A private build tmux session is not substitution for Laneboss-managed agent sessions; if legacy pack matching over-blocks it, report/fix that explicit entry through D6, never add an implicit allowlist or call the failure harmless. No real remote push is performed by this design lane. |
| Service identity/RPC | Forged actor / env / level / instance, cross-config path, stale launch, PID reuse, cross-UID drift and passed connected descriptor cannot gain another principal. | Authentic child start / report / mail succeeds; bypassing the launch-membership or generation check must fail the row. |
| Process/run termination | Double fork, setsid/nohup, subreaper, pipe holder and long-running child remain confined/identified; stop/timeout leaves zero actual survivors. | A containment-removal mutation leaves a canary child alive and fails; process-read failure yields unknown/stopping, never success. |
| Network/IPC | Raw TCP / UDP / IPv6 / Unix / Mach attempts cannot reach management, another lane or metadata; no Docker / SSH-agent / host-tmux escape. | Public download, own loopback test and granted project/inference endpoint work; removed packet/profile rules fail. |
| Data/materialization | Traversal, symlink swap, hardlink, bind alias, nested mount, `.git` common dir/alternates, submodule/LFS and inherited-FD canaries reveal no ungranted object. | Internal safe link or independently copied repo works; a deliberately leaked FD/common Git admin path fails. |
| Confused-deputy worker | Report / file / grant / export / archive / judge / box APIs cannot open an arbitrary host path, execute repo hooks as service or smuggle a root command. | Authorized byte upload/import works; removing scope/worker isolation must fail the dedicated row. |
| Failure and restart | Unavailable sandbox / LSM / token API/credential source, killed helper/service, lost reply, partial archive, full disk and revoked parent do not launch unconfined or delete work. | Recovery by the original operation ID is idempotent; duplicate launch or clean-before-receipt mutation fails. |

The additional boundary/owner-contract rows are required, not optional unit
substitutes for the OS rows. Each must reach its assertion before a mutation
counts as killed. Run every DASH-* view row from §4 separately; one shared
dashboard-page load cannot pass all seven views.

| Row | Required denial and successful control | Mutation/failure that the row must detect |
| --- | --- | --- |
| GRANT-BOUND (R71/D4) | A child request wider in path, access, secret or delegation than its actual starter refuses before materialization/launch; a narrower request succeeds and the child's OS view is actually narrower. Repeat on resume/turn and an L5→L3 edge. | Skipping the central parent-subset check authorizes the wider request and fails the refusal / state / child-canary assertions. |
| CREDENTIAL-BOUND | Only the delegated profile works; other profiles/history, owner `~/.claude`, `~/.codex`, Keychain and broker administration remain inaccessible. Names-only env grants; R105 authorizes the actual Linux acceptance login flow, while native Keychain cells are phase 6. | Broad homes/registry mounts, wildcard lookup or a keyring fallback expose a canary and fail. Missing live login success is not a credential pass. |
| UBUNTU-DEFAULT | With observed restriction 1, unprofiled bwrap is refused; the administrator installs, reads back and reloads only its executable-specific profile, and unprivileged bwrap then works while the sysctls remain unchanged. Production helper provisioning and the layout/Landlock canaries also pass; vendor-inner-sandbox compatibility remains a separate cell. | Turning the restriction off, profiling every executable, requiring a root bwrap or mistaking the namespace exception for filesystem enforcement fails. An unprofiled namespace control must remain restricted. |
| UBUNTU-AWS | With observed restriction 0, unprivileged bwrap works without an AppArmor exception; the same work / grant / state / link / tree-hash and standalone/nested Landlock controls pass through the production path. | Inferring restriction 1 from the image label, demanding unnecessary namespace-profile installation or skipping the actual boundary controls fails. Separate account / cgroup / egress setup is still required. |
| CHILD-CODE | A real child-written test/Git hook tries to read/write a parent-only canary during parent review/testing and fails at the OS; a child-scoped build/test succeeds. | Running the candidate in the parent's wider workspace/sandbox exposes the canary and fails. |
| ROTATE-HISTORY | Claudock A→B after a limit/room decision resumes the same lane session/private history with only the new credential slot; a sibling's token/history stays inaccessible. Codex refresh lease has one owner, with successful next turn. | Shared `~/.claude` link, wrong session, concurrent refresh copies or loss of room rotation fails; a prerequisite failure is not a rotation pass. |
| HUMAN-IDENTITY | An unconfined process under the owner's UID without the operation-bound human proof cannot issue a ticket, grant root data or approve an org change; the actual verified human path works. | Trusting UID / terminal / session token alone or accepting a replayed/wrong-operation assertion fails. |
| ORG-APPROVAL (D6) | Exact approved L6 tool / script / config / template / other-resource change applies and records who / diff / time; L5 and unapproved / stale / rebased / replayed changes fail. Every lane's direct filesystem update fails too. | Omitting level, diff hash, fresh nonce, approver verification or base-generation check fails; include non-policy scripts/notes so scope is not narrowed. |
| TPL-SCOPE / SPAWN-LOWER | Correct role / task / template / grants are retained; L5→L3 start/adopt works; equal / higher / forged-level requests fail. | Wrong template generation, client-supplied authority, skipped adoption check or assumed adjacent-parent relation fails. |
| MSG-REL (D7) | Test the **owner-confirmed** peer rule (direct parent versus common L5/L6 root) and downward rule (sender subtree versus common-root lower lives). Include same-parent peers, L3s below sibling L4s, L5→L3 alongside L4→L3, and ancestor/direct-child controls; record provisional narrow outcomes as pending confirmation. Direct upward reports and granted L5/L6 human paths work; cross-root and L3/L4→human fail. | Wrong selected relation version, forged/stale starter, level-only access, omitted report/channel check or a hard-coded direct-parent result after a wider confirmation fails. Shared root alone is not automatically a failed test until the owner chooses its meaning. |
| HUMAN-SEND (D10) | Authenticated human dashboard mail reaches an L3, is delivered/returned correctly, and appears with `human` actor/sender and the same hash in agent history/raw views. The identical request without human authentication refuses. | A client-supplied human label, wrong target life, missing delivery record or hidden log entry fails. |
| GUIDE-TURN / BL-RESP | Per-turn authoritative history selection; unrelated decisions below relevance 0.50 yield no reminder. Ordinary work proceeds and scoped duties refuse correctly. Score 0.40/0.49 → allow, 0.50/0.60/0.84 → warn, 0.85 → refuse only on refuse-band entries under proposed defaults; repeat critical/noncritical cases to prove valid scores never use outage policy. Test actual timeout/cost/truncation, inheritance, injection/cache/recency and complete coverage below the actual configured context cap (historical 8,192/latest reported 16,384). | No turn selection, lane-proposal poisoning, irrelevant top-five filling, scored-as-unavailable/zero, missing-positive refusal, stale cache, silent suffix/chunk loss or binding-policy decay fails. Stand-ins do not prove semantic accuracy. |
| DRIVER-TWO / LB-FIRST | Production agent launches use Claudock/Codex with provider profiles; R103 cross-reviews and R107 selected hard-engineering jobs are explicit scoped exceptions with dedicated worktrees. Briefs contain the rule list; raw agent-session alternatives receive routes, while private tmux/build and ordinary network controls work after migrating the six tmux seeds. | Bare Claude/generic driver admitted, an unscoped/unapproved custom driver, missing routes or surviving unconditional raw-tmux pattern refusal fails. |

Additional review-derived authority/handoff rows run through the real service:

| Row | Denial, control and mutation |
| --- | --- |
| AUTH-RECORDS | Lane decision/store commit, ledger outcome write and raw event append refuse; an upward proposal stays non-authoritative and cannot appear in another lane's D1 context. Verified human/D6 decision commits and actual cloud-test worker ledger receipts work. Disabling the provenance/caller boundary or promoting a proposal must fail. |
| COVERAGE-TRUST | A lane fabricates hook callbacks/refusals/tool IDs and requests acceptance; the service rejects uncorrelated coverage against outside primary vendor/tool capture. Genuine correlated capture works. Missing vendor tool events remain an explicit gap; trusting lane UID or fake receipt bytes must fail the row. |
| LEASE-HANDOFF | Two distinct UID lives use an export in sequence through verified idmap/data projection; each can work without world-writable fallback. Simultaneous parent/sibling mounting, lingering writer FDs and planted links/special files/privilege bits refuse or fail scrub, while a sealed safe snapshot works in the child's scope. Skipping quiescence/scrub/UID mapping must fail. |
| JUDGE-ROUTE/BOUNDS | Inside hook reaches service socket; only the outside judge worker reaches the registered loopback/tunnel endpoint and writes protected egress/audit. Lane direct provider/admin access fails. Verify both the historical 8,192 and reported 16,384 configurations; full-token requests below the actual safe cap and complete chunks work, with no automatic deadline extension; unknown fit, cap/suffix overflow, missing chunks and malformed answers are unavailable. A local-hook adapter, silent truncation or arbitrary rules supplied by a client must fail. |
| ACCEPTANCE-CREDENTIALS | R105's chosen quota profile and Codex gcp login work on the verified disposable box in separate lane homes; another lane's slot is inaccessible. Names-only delivery and final box/login-destruction confirmations are retained. A credential value in retained outputs, stale staging copy, missing destruction or wrong-profile fallback fails. |
| ARGON-WORKTREE (R107) | A selected hard task uses the full Argon model and actual highest supported variant in its own isolated worktree with recorded scope/source, authorized box tests and independent Claude review. Shared worktree, arbitrary driver/model expansion, unsupported invented effort flag or self-acceptance fails. Mac work remains static-only except explicitly authorized Mac-only tests. |

Addendum-4 action rows run independently, even when they share fixture setup:

| Row | Actual successful control and required refusal/failure |
| --- | --- |
| SECRET-INJECT (D13) | Inject one delegated environment secret and one delegated file into a child and compare their bytes **in memory**, printing only names/verdicts. Another parent secret and an ungranted secret are absent; a wider request refuses before launch. Verify start events contain names only, never values, and task grants cannot select a vendor login. A missing-injection / broad-inheritance / subset-bypass mutation must fail. |
| DASH-STOP | The authenticated human stops a running lane through the dashboard; verify the actual processes stop and actor / source / operation / end records match CLI semantics. The same unauthenticated request refuses and leaves the run unchanged. |
| DASH-RESUME | The authenticated human resumes an eligible stopped life with the exact session/grants and actor `human`; the actual next run appears live. Unauthenticated, stale-life, cleaned or invalid-budget requests cannot launch it. |
| DASH-MERGED | A human marks an eligible reviewed lane merged, with truthful required checks/scan and lifecycle records. Unauthenticated requests or an acceptance bypass fail; no Git merge is fabricated. |
| DASH-ABANDONED | A human marks an eligible lane abandoned and sees that real transition/retention state. Unauthenticated or wrong-life requests fail and do not delete work. |
| WATCHDOG-LIMIT | Validated external usage/session limit → service watchdog selects another delegated Claudock profile with actual room → same session/private history continues. Verify from / to / reason / limit-text evidence, no task failure/retry increment and no budget reset. Agent cron / tool / profile-swap calls are absent. |
| WATCHDOG-NO-ROOM | Every eligible profile's checked headroom is exhausted → lane waits, records the actual no-room cause and notifies via permitted report/dashboard paths. It does not switch to Codex, buy capacity or spin; restored room permits one bounded continuation. |
| WATCHDOG-TAMPER | A fake limit in model/tool text, forged event/swap request, altered lane-local file or attempt to signal/configure the watchdog cannot trigger/suppress a swap. A real limit afterward still triggers one; an authorized stop cancels pending continuation without allowing a stale watchdog restart. |

Accept EACCES / EPERM / EROFS or a demonstrated hidden-path ENOENT as appropriate to
the operation, not a text match on stderr. For Darwin capture syscall results
and Seatbelt diagnostics where available; do not require a tracing facility
that SIP disables and then skip the boundary. Preserve the direct syscall
result and independent read-back instead. Failed harness setup is not a killed
mutation. Every control must reach the named operation.

### Convert the adversarial and private write-shape corpus

The existing public additions are explicitly hook-input-only
(`e2e-rows/adversarial-additions.json:3`), with nested / env / ANSI-C / eval and outside
write pairs (`e2e-rows/adversarial-additions.json:6`,
`e2e-rows/adversarial-additions.json:40`,
`e2e-rows/adversarial-additions.json:92`). Preserve their IDs and exact original
bytes in the migration manifest. Obtain the private suite's complete write-shape
row inventory during implementation; it was not supplied to this design lane.
Release cannot claim “all rows converted” without that manifest and a mapping
for every row, including a reason for any policy-only row.

Execute each write-shape in a planted disposable workspace, once against an
ungranted/readonly canary and once against its writable control. Cover redirects
and clobbers, append, tee/dd, every copier option shape, sed/perl in-place,
tar extraction/traversal, executing/destructive find, xargs, Git overrides,
patch/file tools, variable / ANSI-C / alias / eval / nested-shell forms, opaque scripts,
renamed binaries and descendants. Expected: **a forbidden operation fails at the
OS regardless of what the hook decides**. A hook refusal alone means the OS
row did not run; run its equivalent direct program in the isolated probe.

Do not blindly retain obsolete expectations. Private `/tmp` output is now an
ordinary allowed control; the old outside-worktree hook refusal for that shape
is not the new contract. An authorized service operation can mutate state through
RPC while direct SQLite writes fail. A Git push policy row remains a blacklist
policy test against a disposable local destination; do not push a real remote
or interpret every historical MUST_REFUSE as an OS access boundary.

Keep one minimal assertion/control and a guarding mutation per distinct
boundary. Variations in spellings can be table inputs to that executed check;
do not reintroduce large duplicate suites or skip the E2E in favor of units.

### Ladder smoke and final gate

Retain R57's mixed-runner intent as refined by R58–R60: **ten instances**,
1 L6 + 2 L5 + 3 L4 + 4 L3. The harness starts only L6; each parent starts its
children through the public inside CLI, waits for authentic end events,
reviews / marks / archives / cleans them and reports upward. Use the real service and
isolation backend, not a parallel harness sandbox.

Use a recorded random seed to assign the L3 mix, with both Claude Code and
Codex guaranteed (for example shuffle two of each). Under R60 the L6 / L5 / L4
supervisors remain Claude Code for the primary release gate. Pure-Claude,
mixed and pure-Codex-adapter behavior also have focused cells; do not silently
reinterpret R60 as authorization to change the primary ladder to all Codex.
The redesigned Codex-supervisor capability has a separate real L4 / L5 / L6
delegation / turn / event-wait gate before it is advertised, and can later support
a fully Codex ladder after an owner scope decision.

Every lane finds a planted file in its own data and reports its path plus an
unpredictable word token. The seed determines structure, never the answer
token. Use causal ping/pong on turn-capable links: send event, delivered turn,
then matching child response; no early PONG counts. Supervisors carry all
descendant answers upward. Reports go level by level, with no credential or
management state grants to supervisors.

Assert actual starter/life links, correct request actors on manual turn/resume,
mail senders separately, parent-visible child ends, sibling privacy, correct
answers/tokens, no source-tree changes, no unexpected refusals/suspicions,
complete transcripts/telemetry, truthful budget / exit / survivor data and cleanup
by the parent with archive receipts. Exercise simultaneous sibling starts and
a second credentialed turn, addressing the ladder summary's suspected broker
race without asserting its cause before the canary. Reject an adapter whose
executable/self-helper path has disappeared; use named immutable vendor binaries,
not an unlinked executable projection.

Before paid runs, red controls must reject a wrong token/path, another lane's
path, a missing ancestor answer, skipped report level, early PONG, hidden child
end, first-mail-sender actor and missing transcript. The same assertions then
consume the real run's plan / events / files; no hard-coded pass or expected answer
inside a product adapter.

Require two complete primary ladder passes **at the same time**, as L6 requested,
on identical release source / binary / backend artifacts with the seeded plans
recorded. Use two independently bound configurations, stores, UID leases, sockets
and workspaces on the same one authorized spot machine; never switch a live
session's binding to serve the other run. Use available authorized profile room
and budget for both runs, with the same seeded runner plan and independently
unpredictable planted tokens. If capacity prevents concurrent execution, report
the gate incomplete rather than substitute two sequential runs. This supersedes
the first draft's sequential-run wording. A diagnostic all-Claude probe does not
replace the mixed gate. Archive/copy back/read back evidence and verify machine
termination. Any failed required cell stops acceptance; missing Mac/live-auth
evidence remains a named unsupported/pending capability, never a passed cell.

## 11. Delivery phases, risks and owner decisions

R102 authorizes the supervising implementation track to build now toward the
36-hour **Linux** target, using recorded recommended defaults for reversible
unanswered implementation choices. It does not turn pending owner readings into
confirmed words, waive D6's per-change human approval, authorize unrelated paid
fallbacks or make an unpassed release gate succeed. This document lane still
edits only this file and launches no implementation/reviewer sessions.

### Confirmed owner decisions

| Decision | Implementation consequence |
| --- | --- |
| **R101 — CLEF-HOST = A** | Evaluate Clef **only on the existing self-hosted Clef-flash on the authorized pair of 24 GB A30s**, currently one GPU at short context. **No Cloudflare account/token and no hosted Clef evaluation arm.** Use the local deployment and paired Jev corpus with the actual verified configurable cap (historical 8,192; R106 reports 16,384); moving to the 48 GB-class executor-model host needs the owner's word. Default promotion still needs the measured bars/shadow evidence. |
| **R105 — live acceptance credentials** | The owner decided “可以照做 任何有quota的profile都能用”: use any authorized Claudock profile with quota and the owner's Codex gcp setup. Follow the earlier ladder method: verify the disposable acceptance box, record selected names privately, write the test logins once through the existing acceptance-secret flow, confirm the box's copy before removing the Mac staging copy, then destroy the box/logins and retain confirmation after collection. No credential values in logs, Git, prompts or fixtures. This closes Fable's credential decision; acceptance need not wait for an unbuilt production broker. |
| **R89/R102 — parallel 36-hour Linux build** | About **2 h contract freeze**, then roughly **20 parallel Codex authoring lanes**, with all available authorized Claudock/Codex headroom and no artificial profile cap. Continuous disposable-box verification; reserve roughly the last 10 h for integration, two concurrent live ladders, fixes and release checks. The 36 h is the owner's target, not a substitute for those checks. |
| **R103 — paired gating review** | Every gating read gets a Claude review plus an opencode `google-vertex/gemini-4-argon` cross review. Retain both reports and reconcile findings; disputed owner meanings remain explicit below. R103 is the read-only exception in §3; R107 separately permits selected hard engineering tasks, each with its own worktree. |
| **R104 — maximum effort** | Every implementation and review uses maximum reasoning effort: Codex/Claude effort `max`, the actual highest supported opencode variant, verifying version/flag evidence. R107 reports `google-vertex/gemini-4-argon#high` as that build's highest variant; do not invent a `max` flag. Record the selected model and effort with the lane/review inputs. |
| **R106 — adjustable context** | The owner corrected 8k as a setting. The later operator report records a tuned **16,384-token** A30 deployment and smoke; near-full input was silently truncated and took **2.4–3.0 s**. Retain both evidence generations, derive the actual cap with a safety margin, and preserve the command deadline rather than call that result a complete-input/two-second pass. |
| **R107 — selected hard Argon tasks** | opencode `google-vertex/gemini-4-argon` may author selected harder implementation tasks, **each in its own Git worktree**, with independent Claude review. Record its maximum supported effort (`#high` in the reported build) and keep platform-test/credential/grant limits. This later engineering exception is distinct from R103's mandatory read-only cross-review. |
| **R35/R36 — Linux first** | Phases **1–5 have zero test-Mac dependency**. All Darwin identity, Keychain, packet-rule and native credential proofs belong to phase 6, which can proceed separately when authorized hardware exists. Native Mac remains unavailable until its own evidence passes; Linux VM is the explicit fallback. |
| **Earlier confirmed product choices** | One Go binary (R88), human dashboard controls (R94), native encrypted secret-store default (R95), and service-watchdog profile swap (R96/R97) stay decided. No new account/payment choice is inferred from CLI availability. |

For R105, the implementation/acceptance operator uses the already authorized
secret flow, not an environment dump or a copy into source. Private per-lane
vendor homes and delegated-profile checks still apply on that box. Collect
names-only delivery/cleanup receipts, verify the retained evidence is credential
screened, terminate the box and confirm destruction; an uncertain cleanup is
pending, not success. Production credential workers are still required in 4A,
but the approved acceptance method does not depend on all broker modes.

### Match the build outline and remove later-worker dependencies

The owner's five-step outline remains service → Linux sandbox/grants/routing →
layered judgment/guidance → dashboard → ladder/tutorial/macOS. The packages
below put each confined worker **before its consumer's integration gate**.

| L6's stated order | Dependency-correct work package |
| --- | --- |
| 1. Service + identity + stores | Phase 2 core RPC/identity, tickets, durable events/mail/lifecycle, native secret store and D6 staging/approval records. D6 application/rendering closes only after phase 3's worker exists. |
| 2. Linux sandbox + spawn/grants/routing | Phase 3 helper, **confined-worker framework and data/Git worker**, materialization, resource rendering and boundary proofs; phase 4A adds the **Linux credential worker** and actual drivers. |
| 3. Layered config + judge + guidance | Phase 4B builds the **outside judge worker**, its socket delegation and self-hosted Clef/TypeSafe adapters before any D1/D2 production integration. |
| 4. Dashboard and remaining CLI | Phase 5 completes the remaining command groups, archive/cloud-test/channel workers, protected decision/store paths, dashboard and migration using the earlier workers. All 24 groups must be reconciled before Linux acceptance. |
| 5. Ladder + tutorial + macOS | Phase 7 Linux acceptance depends on phases 1–5, **not phase 6**. Phase 6 owns every Mac-specific spike/mode and certification. Phase 8 Windows/WSL remains after Linux/macOS. |

Phase 1 freezes the versioned RPC/grant/event/judge/worker interfaces in about
two hours so independent authors can proceed. Remaining Linux feasibility and
minimum-kernel procurement can run alongside them, but a consumer cannot call a
stand-in “production complete”. Phase 2 may stage/authenticate a D6 transaction;
it returns a visible dependency-unavailable result for rendering/application
until phase 3's confined worker is present. Core mail/report byte storage does
not require phase 5's external channel delivery worker.

The following **63–98 working days are single-engineer-equivalent scope only**
for the full Linux/native-Mac work, including checks, packaging and independent
fixes. They are not elapsed dates or a three-author schedule. Reallocation moves
worker work earlier and all Mac work to 6; completed spikes are credited, not
repeated for ceremony. Add about 20% scope contingency: **76–118 equivalent
working days**. Neither total is divided mechanically by twenty to promise
throughput.

| Work package | Single-engineer-equivalent days | Deliverable and exit condition |
| --- | --- | --- |
| 1. Linux contracts and remaining feasibility | 3–5 | About 2 h serial contract freeze; credit the measured off/on bwrap/AppArmor and A30 smoke. Procure/name/hash a bootable **Linux 6.6/ABI-3** floor image or custom kernel, prove remaining restricted-amd64/production capability cells, inventory private rows and verify the Linux human-confirmation path. No Mac prerequisite. |
| 2. Core service/state/identity RPC | 10–15 | Identity/tickets, authenticated core state/events/mail/lifecycle, native store, durable launch/outbox recovery and D6 staging/approval protocol. No arbitrary store/event/ledger mutation API. Resource application waits for 3's worker; later CLI groups are not falsely called ported here. |
| 3. Linux helper, worker framework and data/Git | 13–19 | UID allocation/cgroup delegation/helper packaging and security review; unprivileged bwrap with the measured profile path, seccomp and egress plumbing; confined-worker framework plus data/Git/materialization and D6 renderer/validator. Prove the previously unmeasured helper+bwrap combination and export lease/idmap controls. |
| 4. Linux drivers/credentials (4A), judge/guidance (4B) | 12–18 | **4A:** Linux credential worker, selected Linux Claudock/Codex modes, private history/refresh ownership, outside capture, watchdog and lifecycle tests. **4B:** outside judge worker, lane-socket delegation, local Clef-flash/TypeSafe contract, context bounds, layered config, cache/threshold/audit/outage behavior and per-turn guidance. All Mac modes move to 6. |
| 5. Remaining CLI groups and migration | 10–16 | Finish the 24-group inventory: archive / box / decision-store / report-channel APIs and workers, dashboard, resource views, gateway/sheet integrations, importer, old-store/0.5 compatibility, rollback and verified archival. Use the framework/data/credential/judge workers already built; no deferred prerequisite worker. |
| 6. Native macOS, entirely separate from Linux gate | 9–15 | All Darwin peer-generation/PID-reuse, Keychain/auth/profile and listener/packet spikes; LaunchDaemon/helper, UID leases, Seatbelt/IPC, orphan supervision and native driver/credential matrix. Uses an explicitly authorized test Mac; missing hardware leaves only native capability pending. |
| 7. Linux acceptance, corpus and teaching docs | 6–10 | After 1–5, actual OS controls/private write-shape corpus, paired judge evaluation, Linux guide/bootstrap tutorial, two concurrent live mixed ladders with R105 logins, cleanup/read-back/privacy and independent paired gating reviews. Native Mac cells close separately after 6. |
| **Full initial Linux/macOS scope** | **63–98** | **76–118 with 20% contingency**; single-engineer equivalent, not elapsed time. Linux first; phase 8 excluded. |
| 8. Windows/WSL roadmap | Estimate after WSL spike | After Linux/macOS, prove WSL2 kernel/LSM/userns/systemd/peer/interop, Linux versus `/mnt/c` grants and both drivers; native Windows later. |

### Parallel 36-hour Linux plan (R89/R102)

Use all actually available authorized profile headroom; roughly twenty Codex
authoring lanes is the launch plan, not a ceiling; R107 permits selected hard
Argon engineering tasks in separate worktrees too. Assign independent contracts,
files and reviewers, and integrate verified outputs continuously. Maximum effort
and paired gating reviews apply throughout. Builds/units/E2E stay on disposable
Linux boxes; the orchestration must preserve one configuration per live session
and each lane's authorized machine limit. This design lane spawns none.

| Target window from implementation start | Work and evidence |
| --- | --- |
| **Hours 0–2** | Freeze core RPC/life/grant/event/worker/judge contracts and test responsibilities; name the remaining kernel-floor procurement cell. Preserve the failed and successful spike inputs. |
| **Hours 2–12** | Roughly 20 parallel Codex authors plus available Claudock profiles cover core service, helper/framework/data, Linux credentials, judge/policy, CLI groups, UI, migration, docs and adversarial rows. Verify real merged dependencies continuously on boxes; contract fixtures are not acceptance evidence. |
| **Hours 12–26** | Integrate all command groups, actual driver sessions/watchdog, decision/coverage authority, archive/rollback, dashboard and teaching paths. Run focused OS controls and paired reviews while completing the fixed local Clef/Jev corpus. Surface resource/critical-path slippage immediately. |
| **Hours 26–36** | Final integration and fixes, two concurrent live ladders on the exact candidate, complete CLI/tutorial/OS/privacy/cleanup evidence, Claude plus Gemini gating reads, then the authorized release decision only if its checks pass. |

This replaces the earlier three-stream and 35–51-working-day Linux elapsed
schedule. R102's 36-hour target does not certify a result in advance. If the
minimum-floor image, live login, required capture, corpus or another required
Linux row is missing/failing, report the concrete remaining gate and deadline
risk; never relabel it passed. The two-week Clef shadow window is for **default
promotion**; it cannot finish inside 36 hours, so the Linux build can retain the
approved incumbent default while offering the evaluated local alternative.
Mac work may proceed in its separate phase 6 without blocking Linux; no paid
Mac is procured by this document.

| Risk | Effect | Recommendation |
| --- | --- | --- |
| Reusing a shared inference host | Stopping a wrong service or retaining an untracked model process affects other users. | The authorized supervising operator verifies actual ownership/process identity first, stops only the approved service by verified identity, retains private rollback/collection evidence and leaves other users untouched. No host operation is performed by this documentation lane. |
| Service rewrite expands the trusted code | A file / URL / command RPC could undo filesystem isolation. | Typed operations only; confined data / judge / channel workers; independent review of every capability that crosses UIDs. |
| Darwin deprecated APIs, peer generation and process supervision | Native macOS may miss its target or fail an OS-version upgrade. | Prove these first; keep Linux primary and a VM fallback. No permissive native fallback. |
| Vendor CLI / auth / refresh / session changes | Runs start but cannot authenticate, resume or preserve hooks/records. | Pin actual binaries and supported modes; real two-turn/concurrent-profile proofs; version adapters and diagnose unsupported modes. |
| Git/common data, alias races, live writable exports | Granted data becomes a route to ungranted files or cross-lane modification. | Independent copies by default; no host admin dirs, external hardlinks or shared mutable caches; mount only broker-managed exports after alias/race controls. |
| Installation needs administrator actions | More setup than the old user-local binary. | One explicit reviewed install step; leave CLI install lightweight and reusable. Do not hide privilege in arbitrary sudo commands or a Docker socket. |
| Broad policy breaks ordinary coding | Repeats the hook's over-block cycle. | Ordinary-work controls beside each security boundary; improve data/runtime grants instead of adding command exceptions. |
| Missing private inventory or live/Mac test access | An incomplete matrix could be called complete. | Gate each advertised capability on its actual evidence; retain row manifests and pending cells. |
| Repository copy and archival cost | Startup, disk usage and cleanup latency increase. | Measure the explicit scope, use safe APFS/reflink copies where supported, then optimize immutable objects; preserve receipt-before-removal ordering. |

### Review differences retained for the owner

| Point | Both review views and remaining decision |
| --- | --- |
| Peer “same root” | The Fable-reviewed draft used the direct-parent reading; Gemini identifies same L5/L6-root cases that the example does not settle. **Open:** same direct parent or common L5/L6 subtree root? Keep both in D7/MSG-REL; recommend the narrow provisional default, awaiting the owner's 對. |
| Downward “same tree” | Fable requires the sender-subtree narrowing to be labelled a reading; the wider root interpretation remains possible. **Open:** own starter descendants only, or any lower-level agent sharing the chosen root? The labels/tests must follow the answer. |
| Hook deletion authority | The Fable-reviewed text retained an R47-confirmation gate without a new objection; Gemini explicitly reads R64–R70 as authorizing deletion after OS acceptance. **The OS/service move is authorized. Open:** does applying the exact legacy deletion map need a separate R47 confirmation? Retain both readings without turning silence into approval or deleting code on either interpretation. |
| Phase/Mac risk timing | Fable considered the previous early-Mac/dependency handling feasible; Gemini found later-worker dependencies and a Mac prerequisite on Linux. R35/R36 and addendum 6 settle **Linux first, all Mac proofs in phase 6** and the worker order above. **Open only:** when authorized hardware exists, how early should independent phase-6 risk probes run in parallel? No answer may reintroduce a Mac dependency into 1–5. |
| Old elapsed estimate | Fable's three-stream suggestion and Gemini's R89/R102 objection are both recorded. The later **owner decision settles the build plan at 36 h with uncapped parallelism**; only actual critical-path feasibility remains to measure, not a choice to restore the old schedule. |

### Questions for the owner and L6

R101–R107, Linux-first, dashboard control and the native-store default above
are decided, not questions. R102 permits recorded recommended reversible
implementation defaults below; it does not supply a literal 對 for a pending
interpretation or substitute for exact-change D6 approval.

| Open decision | Recommendation/status |
| --- | --- |
| One administrator install/per-lane UID leases, and missing isolation prerequisites? | Use the narrow helper with service/runner unprivileged; refuse an isolated launch when prerequisites fail. A separately bound, visibly unprotected observation mode remains an explicit product choice, never an isolation pass. |
| Native Mac test hardware and live-mount parity? | Phase 6 uses a designated existing test Mac when authorized; R35 cancelled paid EC2 Mac. Keep native copy-only until separate mount/ACL proof; Linux VM fallback. No Mac blocks Linux acceptance. |
| Unsupported vendor credential fallback? | R105 decides the live acceptance route. Production starts with supported Claudock/Codex Linux modes and serial refresh/login fallback; a new paid API/billing mode still needs the owner's payment choice. |
| Default live writable cross-repo sharing? | Independent copies by default. Only an explicit Linux single-writer ID-mapped/confined projection with quiescent scrubbed handoff; no simultaneous parent/sibling mount. |
| Codex supervisors and primary ladder composition? | Gate Codex supervisors through the service, while keeping R60's mixed-worker/Claude-supervisor primary ladder until changed; add focused Codex-supervisor evidence. |
| Legacy already-running sessions and R24/R44 `start --role` behavior? | **Proposed change awaiting confirmation:** preserve briefing/history, then explicit import/relaunch into service confinement rather than register a live host agent as isolated. Do not call this already approved by R24. |
| Hostile multi-tenant/multi-host scope? | Defer Kubernetes/distributed tenancy; use a VM for a separate-kernel requirement and retain a backend contract. |
| Exact hook-code deletion under R47? | Preserve the two authority readings in the review table above. OS/service protection is authorized and required; exact deletion follows passing replacement rows plus resolution of this disputed confirmation scope. |
| Judge outage policy? | Recommend closed only for explicitly critical entries, otherwise open with notice/record; no silently seeded secret/network bans. Valid scored probabilities use (e), never the outage route. |
| Does “time averaged” mean recency decay rather than reminder throttling (D1/R73)? | **proposed reading, awaiting the owner's 對**: judge applicable history every turn, relevance cutoff then time-weighted ranking; current binding policy never decays. |
| Does judge membership fully replace pattern matching (D2/R74)? | **proposed reading, awaiting the owner's 對**. R76 confirms blacklist-only responsibility splitting, not this replacement. Preserve compatibility/history; fix the six tmux seed over-blocks explicitly. |
| Does peer “same root” mean direct parent or common L5/L6 root (D7/R79)? | **proposed reading, awaiting the owner's 對**: recommend direct-parent siblings provisionally; retain the wider alternative and let MSG-REL test the selected rule. |
| Does downward “same tree” mean sender descendants only (D7/R81)? | **proposed reading, awaiting the owner's 對**: recommend authentic sender subtree; retain the wider common-root alternative. Upward reports still use the direct report line. |
| Human proof/device and R45 scalar inheritance? | Hardware-backed operation-bound confirmation or independent unreachable-to-agents channel; prove the Linux path without a test Mac. Keep documented org fallback/deny union until N+1 scalar semantics are clarified. |
| Promote Clef-flash over the incumbent default? | R101 fixes **self-hosted A30-only evaluation**. First pass the approximately 302-item paired Jev bars under the actual verified configurable bounds (8,192 snapshot; R106 reports 16,384), then two weeks of shadow evidence and an approved policy change; smoke latency is not accuracy or a p95. |
| R43: initial secret handles, delivery/rotation/revocation? | Service-only named env/private-file injection bounded by parent grants; separate task and runner-login grants. R95 already fixes the default store; R105 covers the acceptance-box login method. |
| R34: raw-log/transcript/archive retention? | Recommend daily verified archival, seven recent raw-log days locally, archive-backed lookup and immutable event/input/decision/approval indexes. Select destination/long-term retention; no purge before verified read-back and usable references, no credential archival. |

The implementation track records defaults and deviations with its contracts;
release approval comes from the executed §10 evidence and reconciled independent
reads. This document neither launches that track nor declares its gates passed.
