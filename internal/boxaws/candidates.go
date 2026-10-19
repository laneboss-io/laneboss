package boxaws

import (
	"context"
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/boxcore"
)

type spotRow struct {
	InstanceType     string
	AvailabilityZone string
	SpotPrice        string
	Timestamp        string
}

// Candidates returns the latest prices in deterministic cheapest-first order.
func (p *provider) Candidates(ctx context.Context, req boxcore.Request) ([]boxcore.Candidate, error) {
	if err := p.profile(); err != nil {
		return nil, err
	}
	args := []string{"ec2", "describe-spot-price-history", "--product-descriptions", "Linux/UNIX",
		"--start-time", p.o.Now().UTC().Format(time.RFC3339), "--instance-types"}
	explicit := req.Type != "" && req.Zone != ""
	var types []string
	if explicit {
		types = []string{req.Type}
		args = append(args, req.Type, "--availability-zone", req.Zone)
	} else {
		var err error
		types, err = p.types(req)
		if err != nil {
			return nil, err
		}
		args = append(args, types...)
	}
	result, err := p.aws(ctx, "describe-spot-price-history", args...)
	if err != nil {
		return nil, err
	}
	var response struct{ SpotPriceHistory []spotRow }
	if err := json.Unmarshal(result.Stdout, &response); err != nil {
		return nil, priceError("invalid price response", err)
	}
	if explicit {
		price := 0.0
		if len(response.SpotPriceHistory) != 0 {
			price, err = spotPrice(response.SpotPriceHistory[0].SpotPrice)
			if err != nil {
				return nil, err
			}
		}
		return []boxcore.Candidate{{Type: req.Type, Zone: req.Zone, Region: p.cfg.Region,
			Arch: typeArch(req.Type), PriceUSDHour: price}}, nil
	}
	requested := make(map[string]bool, len(types))
	for _, name := range types {
		requested[name] = true
	}
	type quote struct {
		candidate boxcore.Candidate
		at        time.Time
	}
	type pair struct{ name, zone string }
	latest := make(map[pair]quote)
	for _, row := range response.SpotPriceHistory {
		if !requested[row.InstanceType] {
			continue
		}
		if row.AvailabilityZone == "" {
			return nil, priceError("price row has no zone", nil)
		}
		at, err := time.Parse(time.RFC3339, row.Timestamp)
		if err != nil {
			return nil, priceError("invalid price timestamp", err)
		}
		price, err := spotPrice(row.SpotPrice)
		if err != nil {
			return nil, err
		}
		key := pair{row.InstanceType, row.AvailabilityZone}
		old, present := latest[key]
		if !present || at.After(old.at) || at.Equal(old.at) && price < old.candidate.PriceUSDHour {
			latest[key] = quote{candidate: boxcore.Candidate{
				Type: row.InstanceType, Zone: row.AvailabilityZone, Region: p.cfg.Region,
				Arch: typeArch(row.InstanceType), PriceUSDHour: price,
			}, at: at}
		}
	}
	if len(latest) == 0 {
		return nil, boxcore.NewError(boxcore.KindCapacity, "candidates", "", "no spot prices", nil)
	}
	candidates := make([]boxcore.Candidate, 0, len(latest))
	for _, q := range latest {
		candidates = append(candidates, q.candidate)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.PriceUSDHour != b.PriceUSDHour {
			return a.PriceUSDHour < b.PriceUSDHour
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.Zone < b.Zone
	})
	limit := p.cfg.MaxCandidates
	if limit == 0 {
		limit = 3
	}
	if limit < 0 {
		return nil, priceError("invalid candidate limit", nil)
	}
	return candidates[:min(limit, len(candidates))], nil
}

func (p *provider) types(req boxcore.Request) ([]string, error) {
	sizes := map[int]string{2: "large", 4: "xlarge", 8: "2xlarge", 16: "4xlarge",
		32: "8xlarge", 48: "12xlarge", 64: "16xlarge"}
	size, ok := sizes[req.VCPU]
	if !ok {
		return nil, priceError("unsupported vCPU count", nil)
	}
	families := req.Families
	if len(families) == 0 {
		switch req.Arch {
		case "x86":
			families = p.cfg.FamiliesX86
		case "arm64":
			families = p.cfg.FamiliesArm
		case "any":
			families = append(append([]string{}, p.cfg.FamiliesX86...), p.cfg.FamiliesArm...)
		default:
			return nil, priceError("unknown architecture", nil)
		}
	}
	var types []string
	seen := make(map[string]bool)
	for _, family := range families {
		if !boxcore.PlainName(family) || strings.Contains(family, ".") {
			return nil, priceError("invalid instance family", nil)
		}
		memory := 0
		switch family[0] {
		case 'c':
			memory = 2 * req.VCPU
		case 'm':
			memory = 4 * req.VCPU
		case 'r':
			memory = 8 * req.VCPU
		}
		if req.MemGiB > 0 && memory < req.MemGiB || seen[family] {
			continue
		}
		seen[family] = true
		types = append(types, family+"."+size)
	}
	if len(types) == 0 {
		return nil, priceError("no families meet the memory minimum", nil)
	}
	return types, nil
}

func typeArch(name string) string {
	family, _, _ := strings.Cut(name, ".")
	if strings.HasSuffix(family, "g") {
		return "arm64"
	}
	return "x86"
}

func spotPrice(text string) (float64, error) {
	price, err := strconv.ParseFloat(text, 64)
	if err != nil || price < 0 || math.IsNaN(price) || math.IsInf(price, 0) {
		return 0, priceError("invalid spot price", err)
	}
	return price, nil
}

func priceError(detail string, err error) *boxcore.Error {
	return boxcore.NewError(boxcore.KindOther, "candidates", "", detail, err)
}
