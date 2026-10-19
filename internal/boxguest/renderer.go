package boxguest

import (
	"strconv"
	"strings"

	"laneboss.io/laneboss/internal/boxcore"
)

const guardEnd = "LB_BOX_GUARD_END"

// Renderer renders the on-box scripts. The zero value works.
type Renderer struct{}

// New returns the renderer as the boxcore interface.
func New() boxcore.GuestRenderer {
	return Renderer{}
}

// Render builds the guest scripts for a spec. It is pure and deterministic.
func (Renderer) Render(spec boxcore.GuestSpec) boxcore.Guest {
	spec = defaults(spec)
	var b strings.Builder
	b.WriteString("#!/bin/bash\nset -u\n")
	b.WriteString("mkdir -p -- " + quote(spec.OutDir) + " || exit 1\n")
	b.WriteString("chmod 1777 -- " + quote(spec.OutDir) + " || exit 1\n")
	b.WriteString("if ! shutdown -h " + quote("+"+strconv.Itoa(spec.HardMin)) +
		" " + quote(spec.Tag+" hard cap") + "; then\n")
	b.WriteString("    logger -t " + quote(spec.Tag) +
		" 'hard cap scheduling failed'\nfi\n")
	b.WriteString("if ! cat > '/usr/local/bin/lb-box-guard' <<'" +
		guardEnd + "'\n")
	b.WriteString(GuardScript(spec))
	b.WriteString(guardEnd + "\nthen\n    exit 1\nfi\n")
	b.WriteString("chmod 755 '/usr/local/bin/lb-box-guard' || exit 1\n")
	b.WriteString(`if command -v systemctl > /dev/null 2>&1 &&
    [ -d '/run/systemd/system' ]; then
`)
	b.WriteString("    cat > " + quote("/etc/systemd/system/"+
		spec.Tag+"-guard.service") + " <<'LB_BOX_SERVICE_END'\n")
	b.WriteString(`[Unit]
Description=Spot box idle guard
[Service]
Type=oneshot
ExecStart=/usr/local/bin/lb-box-guard
LB_BOX_SERVICE_END
    if [ "$?" -ne 0 ]; then exit 1; fi
`)
	b.WriteString("    cat > " + quote("/etc/systemd/system/"+
		spec.Tag+"-guard.timer") + " <<'LB_BOX_TIMER_END'\n")
	b.WriteString(`[Unit]
Description=Spot box guard timer
[Timer]
OnBootSec=60
OnUnitActiveSec=60
AccuracySec=1s
[Install]
WantedBy=timers.target
LB_BOX_TIMER_END
    if [ "$?" -ne 0 ]; then exit 1; fi
    systemctl daemon-reload || exit 1
`)
	b.WriteString("    systemctl enable --now " +
		quote(spec.Tag+"-guard.timer") + " || exit 1\nelse\n")
	b.WriteString("    cat > " + quote("/etc/cron.d/"+spec.Tag+"-guard") +
		" <<'LB_BOX_CRON_END'\n")
	b.WriteString(`* * * * * root /usr/local/bin/lb-box-guard
LB_BOX_CRON_END
    if [ "$?" -ne 0 ]; then exit 1; fi
`)
	b.WriteString("    chmod 644 " + quote("/etc/cron.d/"+
		spec.Tag+"-guard") + " || exit 1\nfi\n")
	b.WriteString("logger -t " + quote(spec.Tag) + " " +
		quote("guard installed: idle "+strconv.Itoa(spec.IdleMin)+
			" min, hard "+strconv.Itoa(spec.HardMin)+" min, sync "+
			strconv.Itoa(spec.SyncSeconds)+" s") + "\n")
	guest := boxcore.Guest{Startup: b.String()}
	if spec.Provider == "gcp" {
		guest.Shutdown = `#!/bin/bash
set -u
if [ ! -f '/usr/local/bin/lb-box-guard' ]; then
    exit 0
fi
exec timeout 25 '/usr/local/bin/lb-box-guard' 'final'
`
	}
	return guest
}

func defaults(spec boxcore.GuestSpec) boxcore.GuestSpec {
	if spec.Tag == "" {
		spec.Tag = "lb-box"
	}
	spec.Tag = reduce(spec.Tag)
	spec.RunID = reduce(spec.RunID)
	if spec.SyncSeconds <= 0 {
		spec.SyncSeconds = 60
	}
	if spec.IdleMin <= 0 {
		spec.IdleMin = 30
	}
	if spec.HardMin <= 0 {
		spec.HardMin = 360
	}
	if spec.OutDir == "" {
		spec.OutDir = "/var/lib/lb-box/out"
	}
	if len(spec.DoneFiles) == 0 {
		spec.DoneFiles = []string{"/var/tmp/lb-done"}
	}
	if len(spec.BusyFiles) == 0 {
		spec.BusyFiles = []string{"/var/tmp/lb-busy"}
	}
	return spec
}

func reduce(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' ||
			r >= '0' && r <= '9' || strings.ContainsRune("._-", r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func quote(value string) string {
	value = strings.ReplaceAll(value, "'", "'\\''")
	// Split a delimiter supplied as data without changing its shell value.
	value = strings.ReplaceAll(value, guardEnd, "LB_BOX_''GUARD_END")
	return "'" + value + "'"
}

func assignment(b *strings.Builder, name, value string) {
	b.WriteString(name + "=" + quote(value) + "\n")
}

func array(b *strings.Builder, name string, values []string) {
	b.WriteString(name + "=(")
	for i, value := range values {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(quote(value))
	}
	b.WriteString(")\n")
}
