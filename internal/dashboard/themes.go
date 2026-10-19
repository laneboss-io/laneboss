package dashboard

// Every meaningful text/series/focus colour uses this shared theme palette.
const themeCSS = `
:root,:root[data-theme=light]{color-scheme:light;--bg:#f3f6f3;--surface:#ffffff;--ink:#173325;--muted:#466454;--line:#cddace;--control:#658171;--accent:#17613f;--warn:#6b4d12;--bad:#963d32;--tint:#e3eee7;--late:#f6e8e3;--series1:#17613f;--series2:#9d3d36;--series3:#705300;--series4:#405e99;--series5:#6e4075;--series6:#355e66;--heat1:#496556;--heat2:#2d7450;--heat3:#17613f}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]){color-scheme:dark;--bg:#101815;--surface:#19241e;--ink:#e6eee8;--muted:#a7b9ae;--line:#3d5145;--control:#83958b;--accent:#a2daba;--warn:#ecc58f;--bad:#f0ada5;--tint:#243c30;--late:#3d2d27;--series1:#91d4ae;--series2:#edaca7;--series3:#e1bf89;--series4:#aacafa;--series5:#ccaed6;--series6:#a4cacc;--heat1:#91a89a;--heat2:#a1c1ac;--heat3:#a2daba}}
:root[data-theme=dark]{color-scheme:dark;--bg:#101815;--surface:#19241e;--ink:#e6eee8;--muted:#a7b9ae;--line:#3d5145;--control:#83958b;--accent:#a2daba;--warn:#ecc58f;--bad:#f0ada5;--tint:#243c30;--late:#3d2d27;--series1:#91d4ae;--series2:#edaca7;--series3:#e1bf89;--series4:#aacafa;--series5:#ccaed6;--series6:#a4cacc;--heat1:#91a89a;--heat2:#a1c1ac;--heat3:#a2daba}
.panel,.panel.full,.graph-node{content-visibility:visible;contain-intrinsic-size:none}
button,input,select,textarea,.tool-chip{border-color:var(--control)}
input::placeholder,textarea::placeholder{color:var(--muted);opacity:1}
.graph-human{display:flex;justify-content:space-between;gap:16px;border-bottom:1px solid var(--control);padding:12px 0;color:var(--ink)}.graph-human strong{font-weight:600}.graph-parent{grid-column:1/-1;min-width:0;border-left:1px solid var(--control);padding-left:12px}.graph-parent-heading{font-size:11px;color:var(--muted);margin:0 0 8px;overflow-wrap:anywhere}.graph-parent-cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(195px,1fr));gap:10px}.node-parent{font-size:10px;line-height:1.5;color:var(--muted);margin-top:9px;overflow-wrap:anywhere}#drawer-lifecycle{max-height:300px}#drawer-lifecycle table{font-size:11px}#drawer-lifecycle td,#drawer-lifecycle th{padding:9px 8px}#drawer-supervisor,#drawer-level-source{font-size:11px;overflow-wrap:anywhere}
button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible,a:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:3px}
.graph-node[data-state=running]{border-color:var(--accent)}
.graph-level[data-level=unrecorded]{grid-template-columns:1fr}.graph-level[data-level=unrecorded]:before{display:none}.graph-level[data-level=unrecorded] .graph-level-tag{text-align:left;margin:0;font-size:12px;line-height:1.6;font-family:inherit}.graph-level[data-level=unrecorded] .graph-level-tag span{display:block}.graph-agent{min-width:0}.graph-agent>.graph-node{width:100%}.graph-agent.has-lanes{grid-column:1/-1}.graph-agent.has-lanes>.graph-node{width:min(260px,100%)}.graph-agent>.graph-level{margin-left:18px;border-left:1px solid var(--control);padding-left:16px}.preferences{display:flex;gap:10px;align-items:center}.preferences label{display:flex;align-items:center;gap:5px}.preferences select{margin:0}.graph-starter{color:var(--ink)}
@keyframes live-pulse{0%,100%{box-shadow:0 0 0 0 var(--accent);opacity:1}50%{box-shadow:0 0 0 2px var(--accent);opacity:1}}
#source-records pre{padding:18px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;color:var(--ink)}
@media(max-width:700px){.watch-actions{flex-wrap:wrap;align-self:stretch}.preferences{flex-wrap:wrap}}
@media print{.panel,.graph-node{content-visibility:visible!important}.scroll,.scroll.large,.graph-root,.thinking-stream,.drawer-records{max-height:none;overflow:visible}}
`
