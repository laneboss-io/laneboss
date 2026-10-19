package boxcore

import (
	"errors"
	"math"
)

// MinHardMin is the shortest run allowed when a cost cap reduces the duration.
const MinHardMin = 10

// ErrPriceUnknown means no positive finite hourly price is available.
var ErrPriceUnknown = errors.New("price unknown or not positive")

// ErrCapTooLow means the cost cap cannot cover the minimum run.
var ErrCapTooLow = errors.New("cost cap too low for the minimum run")

// HourlyUSD adds the disk's hourly cost, counting a negative disk term as zero.
func HourlyUSD(priceHour float64, rootGB int, diskUSDGBMonth float64) float64 {
	disk := float64(rootGB) * diskUSDGBMonth / 730
	if disk < 0 {
		disk = 0
	}
	return priceHour + disk
}

// WorstCaseUSD prices a box that lives for the full hard limit.
func WorstCaseUSD(hourly float64, hardMin int) float64 {
	return hourly * float64(hardMin) / 60
}

// FitHardMin reduces the requested duration to fit a positive finite cost cap.
func FitHardMin(hourly float64, hardMin int, capUSD float64) (int, error) {
	if math.IsNaN(hourly) || math.IsInf(hourly, 0) || hourly <= 0 {
		return 0, ErrPriceUnknown
	}
	if math.IsNaN(capUSD) || math.IsInf(capUSD, 0) || capUSD <= 0 {
		return 0, ErrCapTooLow
	}
	if WorstCaseUSD(hourly, hardMin) <= capUSD {
		return hardMin, nil
	}
	m := int(math.Floor(capUSD / hourly * 60))
	if m < MinHardMin {
		return 0, ErrCapTooLow
	}
	return min(m, hardMin), nil
}
