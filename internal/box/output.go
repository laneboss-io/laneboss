package box

import (
	"encoding/json"
	"fmt"
	"io"

	"laneboss.io/laneboss/internal/boxcore"
)

type boxJSON struct {
	Provider      string            `json:"provider"`
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Type          string            `json:"type"`
	Zone          string            `json:"zone"`
	Region        string            `json:"region"`
	Image         string            `json:"image"`
	Address       string            `json:"address"`
	SpotRequestID string            `json:"spot_request_id"`
	LaunchTimeUTC string            `json:"launch_time_utc"`
	QuoteUSDHour  float64           `json:"quote_usd_hour"`
	Project       string            `json:"project"`
	Labels        map[string]string `json:"labels"`
}

func boxObject(b boxcore.Box) boxJSON {
	return boxJSON{
		Provider: b.Provider, ID: b.ID, Name: b.Name, Type: b.Type,
		Zone: b.Zone, Region: b.Region, Image: b.Image, Address: b.Address,
		SpotRequestID: b.SpotRequestID, LaunchTimeUTC: b.LaunchTimeUTC,
		QuoteUSDHour: b.QuoteUSDHour, Project: b.Project, Labels: b.Labels,
	}
}

type candidateJSON struct {
	Type         string  `json:"type"`
	Zone         string  `json:"zone"`
	Region       string  `json:"region"`
	Arch         string  `json:"arch"`
	PriceUSDHour float64 `json:"price_usd_hour"`
}

type dryJSON struct {
	Allowed bool   `json:"allowed"`
	Code    string `json:"code"`
	Detail  string `json:"detail"`
}

type launchJSON struct {
	Box       boxJSON       `json:"box"`
	Candidate candidateJSON `json:"candidate"`
	Dry       *dryJSON      `json:"dry"`
	ExitCode  int           `json:"exit_code"`
}

func printLaunch(w io.Writer, a arguments, r boxcore.LaunchResult) error {
	if a.format == "json" {
		c := r.Candidate
		v := launchJSON{
			Box: boxObject(r.Box), ExitCode: r.ExitCode,
			Candidate: candidateJSON{c.Type, c.Zone, c.Region, c.Arch, c.PriceUSDHour},
		}
		if r.Dry != nil {
			v.Dry = &dryJSON{r.Dry.Allowed, r.Dry.Code, r.Dry.Detail}
		}
		return json.NewEncoder(w).Encode(v)
	}
	if a.dry {
		if r.Dry != nil && r.Dry.Allowed {
			_, err := fmt.Fprintln(w, "dryrun: allowed")
			return err
		}
		code := "unexpected"
		if r.Dry != nil && r.Dry.Code != "" {
			code = r.Dry.Code
		}
		_, err := fmt.Fprintf(w, "dryrun: denied %s\n", code)
		return err
	}
	if r.Box.ID == "" {
		return nil
	}
	c := r.Candidate
	if c.Type == "" {
		c.Type = r.Box.Type
	}
	if c.Zone == "" {
		c.Zone = r.Box.Zone
	}
	if c.PriceUSDHour == 0 {
		c.PriceUSDHour = r.Box.QuoteUSDHour
	}
	address := r.Box.Address
	if a.provider == "gcp" || r.Box.Provider == "gcp" || address == "" {
		address = r.Box.Name
		if address == "" {
			address = r.Box.ID
		}
	}
	_, err := fmt.Fprintf(w, "spot: %s %s $%.6f/h\niid=%s\nip=%s\n",
		c.Type, c.Zone, c.PriceUSDHour, r.Box.ID, address)
	return err
}

type runJSON struct {
	RunID         string   `json:"run_id,omitempty"`
	IID           string   `json:"iid,omitempty"`
	SuiteExit     *int     `json:"suite_exit,omitempty"`
	Verdict       string   `json:"verdict,omitempty"`
	Harvest       string   `json:"harvest,omitempty"`
	Files         *int     `json:"files,omitempty"`
	Bytes         *int64   `json:"bytes,omitempty"`
	Manifest      string   `json:"manifest,omitempty"`
	Terminated    *bool    `json:"terminated,omitempty"`
	BilledSeconds *int     `json:"billed_seconds,omitempty"`
	CostUSD       *float64 `json:"cost_usd,omitempty"`
	ExitCode      int      `json:"exit_code"`
	ExitName      string   `json:"exit_name"`
}

func printRun(w io.Writer, format string, r boxcore.RunResult) error {
	v := runJSON{
		RunID: r.RunID, IID: r.Box.ID, Verdict: r.Verdict,
		ExitCode: r.ExitCode, ExitName: boxcore.ExitName(r.ExitCode),
	}
	if r.SuiteExit >= 0 {
		v.SuiteExit = &r.SuiteExit
	}
	if r.OutDir != "" {
		v.Harvest, v.Files, v.Bytes, v.Manifest = r.OutDir, &r.Files, &r.Bytes, r.ManifestSHA256
	}
	if r.Box.ID != "" || r.Terminated || r.BilledSeconds != 0 || r.CostUSD != 0 {
		v.Terminated, v.BilledSeconds, v.CostUSD = &r.Terminated, &r.BilledSeconds, &r.CostUSD
	}
	if format == "json" {
		return json.NewEncoder(w).Encode(v)
	}
	var writeErr error
	line := func(format string, args ...any) {
		if writeErr == nil {
			_, writeErr = fmt.Fprintf(w, format+"\n", args...)
		}
	}
	if v.RunID != "" {
		line("run_id=%s", v.RunID)
	}
	if v.IID != "" {
		line("iid=%s", v.IID)
	}
	if v.SuiteExit != nil {
		line("suite exit %d", *v.SuiteExit)
	}
	if v.Verdict != "" {
		line("verdict=%s", v.Verdict)
	}
	if v.Harvest != "" {
		line("harvest=%s files=%d bytes=%d manifest=%s", v.Harvest, *v.Files, *v.Bytes, v.Manifest)
	}
	if v.Terminated != nil {
		line("terminated=%t billed_seconds=%d cost_usd=%.4f", *v.Terminated, *v.BilledSeconds, *v.CostUSD)
	}
	line("exit=%d (%s)", v.ExitCode, v.ExitName)
	return writeErr
}

type endJSON struct {
	InstanceID    string `json:"instance_id"`
	State         string `json:"state"`
	Basis         string `json:"basis"`
	TerminatedUTC string `json:"terminated_utc"`
	BilledSeconds int    `json:"billed_seconds"`
	Pending       bool   `json:"pending"`
	ExitCode      int    `json:"exit_code"`
}

func printEnd(w, stderr io.Writer, a arguments, r boxcore.EndResult) error {
	if r.Pending {
		if _, err := fmt.Fprintf(stderr, "%s is still %s after %ds; END_PENDING recorded\n",
			a.instance, r.State, a.bound); err != nil {
			return err
		}
	}
	if a.format == "json" {
		return json.NewEncoder(w).Encode(endJSON{
			InstanceID: a.instance, State: r.State, Basis: r.Basis,
			TerminatedUTC: r.TerminatedUTC, BilledSeconds: r.BilledSeconds,
			Pending: r.Pending, ExitCode: r.ExitCode,
		})
	}
	if !r.Pending && r.ExitCode == boxcore.ExitOK {
		_, err := fmt.Fprintf(w, "terminated %s (%s)\n", a.instance, r.Basis)
		return err
	}
	return nil
}

type listedJSON struct {
	ID     string `json:"id"`
	State  string `json:"state"`
	AgeMin int    `json:"age_min"`
	Ledger string `json:"ledger"`
	Orphan bool   `json:"orphan"`
	Type   string `json:"type"`
	Zone   string `json:"zone"`
}

func listedObjects(rows []boxcore.Listed, events []map[string]any) []listedJSON {
	objects := make([]listedJSON, 0, len(rows))
	for _, row := range rows {
		ledger := "none"
		if row.LedgerEnded {
			ledger = "ended"
		} else if lastLaunch(events, row.Box.ID) != nil {
			ledger = "open"
		}
		objects = append(objects, listedJSON{
			ID: row.Box.ID, State: row.State.Name, AgeMin: row.AgeMin,
			Ledger: ledger, Orphan: row.Orphan, Type: row.Box.Type, Zone: row.Box.Zone,
		})
	}
	return objects
}

func printList(w io.Writer, format string, rows []boxcore.Listed, events []map[string]any) error {
	objects := listedObjects(rows, events)
	if format == "json" {
		return json.NewEncoder(w).Encode(objects)
	}
	for _, row := range objects {
		orphan := "no"
		if row.Orphan {
			orphan = "yes"
		}
		if _, err := fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
			row.ID, row.State, row.AgeMin, row.Ledger, orphan, row.Type, row.Zone); err != nil {
			return err
		}
	}
	return nil
}

func printSweep(w io.Writer, format string, r boxcore.SweepResult) error {
	if format == "json" {
		return json.NewEncoder(w).Encode(struct {
			Examined int          `json:"examined"`
			Orphans  []listedJSON `json:"orphans"`
			Deleted  []string     `json:"deleted"`
			Refused  []string     `json:"refused"`
		}{r.Examined, listedObjects(r.Orphans, nil), r.Deleted, r.Refused})
	}
	if _, err := fmt.Fprintf(w, "examined=%d orphans=%d deleted=%d refused=%d\n",
		r.Examined, len(r.Orphans), len(r.Deleted), len(r.Refused)); err != nil {
		return err
	}
	for _, id := range r.Deleted {
		if _, err := fmt.Fprintf(w, "deleted %s\n", id); err != nil {
			return err
		}
	}
	for _, refusal := range r.Refused {
		if _, err := fmt.Fprintf(w, "refused %s\n", refusal); err != nil {
			return err
		}
	}
	return nil
}
