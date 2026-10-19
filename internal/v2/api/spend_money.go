package api

import (
	"math/big"
	"regexp"
)

var usdDecimal = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]{1,3})?$`)

// USDMicros uses exact decimal arithmetic. Costs round up; available balances
// round down. A binary float can never buy another turn at the floor.
func USDMicros(decimal string, roundUp bool) (int64, error) {
	bad := func() (int64, error) {
		return 0, &Error{Code: CodeIntegrity, Owner: "lb-v2-spend", Message: "USD amount is missing, negative or outside its bound"}
	}
	if len(decimal) > 64 || !usdDecimal.MatchString(decimal) {
		return bad()
	}
	r, ok := new(big.Rat).SetString(decimal)
	if !ok || r.Sign() < 0 {
		return bad()
	}
	r.Mul(r, big.NewRat(1000000, 1))
	q, remainder := new(big.Int), new(big.Int)
	q.QuoRem(r.Num(), r.Denom(), remainder)
	if roundUp && remainder.Sign() != 0 {
		q.Add(q, big.NewInt(1))
	}
	if !q.IsInt64() || q.Int64() > 1<<53-1 {
		return bad()
	}
	return q.Int64(), nil
}
