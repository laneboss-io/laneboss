package judgecase

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestJudgeProducer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", "-B", "test_producer.py", "-v")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("judge producer regression: %v\n%s", err, output)
	}
}
