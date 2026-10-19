package boxgcp

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"laneboss.io/laneboss/internal/boxcore"
)

func shapeArch(arch string) string {
	if arch == "" {
		return "x86"
	}
	return arch
}

// Candidates selects shapes and zones in stable price order.
func (p *provider) Candidates(ctx context.Context, req boxcore.Request) ([]boxcore.Candidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, localError("candidates", "selection interrupted", err)
	}
	if req.Zone != "" {
		known := false
		for _, zone := range p.cfg.Zones {
			if zone == req.Zone {
				known = true
				break
			}
		}
		if !known {
			return nil, localError("candidates", "zone is not configured", nil)
		}
	}
	if req.Type != "" && req.Zone != "" {
		arch := shapeArch(req.Arch)
		if arch == "any" {
			arch = "x86"
		}
		c := boxcore.Candidate{Type: req.Type, Zone: req.Zone, Region: p.cfg.Region, Arch: arch}
		for _, shape := range p.cfg.Shapes {
			if shape.Type == req.Type {
				c.Arch = shapeArch(shape.Arch)
				c.PriceUSDHour = shape.PriceUSDHour
				break
			}
		}
		return []boxcore.Candidate{c}, nil
	}
	var candidates []boxcore.Candidate
	for _, shape := range p.cfg.Shapes {
		arch := shapeArch(shape.Arch)
		if shape.VCPU != req.VCPU || req.MemGiB > 0 && shape.MemGiB < req.MemGiB {
			continue
		}
		if arch != "x86" && arch != "arm64" || req.Arch != "any" && arch != shapeArch(req.Arch) {
			continue
		}
		if req.Type != "" && req.Type != shape.Type {
			continue
		}
		if len(req.Families) > 0 {
			matches := false
			for _, family := range req.Families {
				if strings.HasPrefix(shape.Type, family+"-") {
					matches = true
					break
				}
			}
			if !matches {
				continue
			}
		}
		for _, zone := range p.cfg.Zones {
			if req.Zone != "" && req.Zone != zone {
				continue
			}
			candidates = append(candidates, boxcore.Candidate{
				Type: shape.Type, Zone: zone, Region: p.cfg.Region,
				Arch: arch, PriceUSDHour: shape.PriceUSDHour,
			})
		}
	}
	// The input loops already encode the shape and zone tie breakers.
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].PriceUSDHour < candidates[j].PriceUSDHour
	})
	if len(candidates) == 0 {
		return nil, boxcore.NewError(boxcore.KindCapacity, "candidates", "",
			fmt.Sprintf("no candidate for %d vCPU", req.VCPU), nil)
	}
	return candidates, nil
}
