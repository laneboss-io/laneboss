// Package guardtime defines the shared judge budget and the runner's margin.
package guardtime

import "time"

const Timeout = 30 * time.Second
const Cleanup = 3 * time.Second
const HookSeconds = 60
