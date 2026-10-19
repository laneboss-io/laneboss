package assembly

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/wire"
)

// All fields are protected administrator enrollment, never RPC input. The
// tokenizer program must run the serving formatter/tokenizer on stdin's exact
// complete System One bytes and emit one TokenFit JSON object on stdout.
type JudgeWorkerInstallation struct {
	TokenizerPath             string     `json:"tokenizer_path"`
	TokenizerArgs             []string   `json:"tokenizer_args,omitempty"`
	TokenizerExecutableSHA256 api.Digest `json:"tokenizer_executable_sha256"`
	PriceFile                 string     `json:"price_file"`
	PriceSHA256               api.Digest `json:"price_sha256"`
	CredentialFile            string     `json:"credential_file,omitempty"`
	SafetyTokens              int        `json:"safety_tokens"`
	ReserveMicros             int64      `json:"reserve_micros"`
}

type judgePrice struct {
	Schema                 string `json:"schema"`
	Provider               string `json:"provider"`
	Model                  string `json:"model"`
	InputMicrosPerMillion  int64  `json:"input_micros_per_million"`
	OutputMicrosPerMillion int64  `json:"output_micros_per_million"`
}

func judgeWorkerPrerequisite(message string) error {
	return &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-judge", Message: message,
		Instead: "Have the administrator enroll the approved formatter/tokenizer, price, reservation and protected credential material; no inference was authorized by an enrollment label."}
}

type judgeOutput struct{ bytes.Buffer }

func (b *judgeOutput) Write(data []byte) (int, error) {
	if b.Len()+len(data) > 16384 {
		return 0, io.ErrShortBuffer
	}
	return b.Buffer.Write(data)
}

func installedJudgeOptions(enrollment JudgeInstallation) (wire.Options, error) {
	var options wire.Options
	w := enrollment.Worker
	if w == nil {
		return options, judgeWorkerPrerequisite("installed judge worker enrollment is absent")
	}
	if err := validateJudgeWorker(enrollment); err != nil {
		return options, err
	}
	priceBytes, err := readProtected(w.PriceFile, 16384)
	if err != nil {
		return options, err
	}
	if wire.Digest(priceBytes) != w.PriceSHA256 {
		return options, judgeWorkerPrerequisite("installed judge price bytes changed")
	}
	var price judgePrice
	if err := api.DecodeObject(priceBytes, &price); err != nil {
		return options, err
	}
	if price.Schema != "laneboss.judge-price.v1" || price.Provider != enrollment.Config.Provider || price.Model != enrollment.Config.Model ||
		price.InputMicrosPerMillion < 0 || price.InputMicrosPerMillion > 1<<53-1 || price.OutputMicrosPerMillion < 0 || price.OutputMicrosPerMillion > 1<<53-1 {
		return options, judgeWorkerPrerequisite("installed judge price is not for the selected deployment")
	}
	if enrollment.CredentialHandle != "" {
		material, err := readJudgeCredential(w.CredentialFile)
		if err != nil {
			return options, err
		}
		options.Credential = api.SecretMaterial{Bytes: material}
	} else if w.CredentialFile != "" {
		return options, judgeWorkerPrerequisite("judge credential file has no enrolled handle")
	}
	options.SafetyTokens, options.ReserveMicros = w.SafetyTokens, w.ReserveMicros
	options.Cost = func(input, output int64) (int64, error) {
		if input < 0 || output < 0 {
			return 0, judgeWorkerPrerequisite("negative measured judge usage")
		}
		amount := new(big.Int).Mul(big.NewInt(input), big.NewInt(price.InputMicrosPerMillion))
		amount.Add(amount, new(big.Int).Mul(big.NewInt(output), big.NewInt(price.OutputMicrosPerMillion)))
		amount.Add(amount, big.NewInt(999999))
		amount.Div(amount, big.NewInt(1000000))
		if !amount.IsInt64() || amount.Int64() > 1<<53-1 {
			return 0, judgeWorkerPrerequisite("measured judge cost overflow")
		}
		return amount.Int64(), nil
	}
	options.Fit = func(ctx context.Context, body []byte) (api.TokenFit, error) {
		data, err := readProtected(w.TokenizerPath, 256<<20)
		if err != nil {
			return api.TokenFit{}, err
		}
		info, err := os.Lstat(w.TokenizerPath)
		if err != nil || info.Mode().Perm()&0111 == 0 || wire.Digest(data) != w.TokenizerExecutableSHA256 {
			return api.TokenFit{}, judgeWorkerPrerequisite("installed serving tokenizer executable changed")
		}
		command := exec.CommandContext(ctx, w.TokenizerPath, w.TokenizerArgs...)
		command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
		command.Stdin = bytes.NewReader(body)
		command.Stderr = io.Discard
		command.WaitDelay = 100 * time.Millisecond
		var stdout judgeOutput
		command.Stdout = &stdout
		if err := command.Run(); err != nil {
			return api.TokenFit{}, judgeWorkerPrerequisite("installed serving tokenizer failed")
		}
		var fit api.TokenFit
		decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&fit) != nil {
			return api.TokenFit{}, judgeWorkerPrerequisite("installed tokenizer emitted an invalid fit proof")
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF || !fit.Proved || fit.InputBytes != len(body) || fit.InputTokens < 1 ||
			fit.ContextTokens != enrollment.Config.ContextTokens || fit.TokenizerSHA256 != enrollment.Config.TokenizerSHA256 {
			return api.TokenFit{}, judgeWorkerPrerequisite("installed tokenizer proof differs from complete bytes or deployment")
		}
		return fit, nil
	}
	return options, nil
}

func privateJudgeCredential(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm()&^os.FileMode(0640) != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && stat.Nlink == 1 && (info.Mode().Perm()&0040 == 0 || stat.Gid == uint32(os.Getegid()))
}

func readJudgeCredential(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !privateJudgeCredential(before) {
		return nil, judgeWorkerPrerequisite("judge credential requires private root ownership and the dedicated service group")
	}
	data, err := readProtected(path, 8192)
	if err != nil {
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil || !privateJudgeCredential(after) || !os.SameFile(before, after) || before.Mode() != after.Mode() {
		return nil, judgeWorkerPrerequisite("protected judge credential identity changed during read")
	}
	return data, nil
}

func validateJudgeWorker(enrollment JudgeInstallation) error {
	w := enrollment.Worker
	if w == nil {
		return nil
	}
	if w.SafetyTokens < 1 || w.SafetyTokens >= enrollment.Config.ContextTokens || w.ReserveMicros < 1 || w.ReserveMicros > 1<<53-1 || !isDigest(w.TokenizerExecutableSHA256) || !isDigest(w.PriceSHA256) || len(w.TokenizerArgs) > 32 {
		return judgeWorkerPrerequisite("installed judge worker bounds or pins are invalid")
	}
	for _, value := range []string{w.TokenizerPath, w.PriceFile} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value || value == "/" {
			return judgeWorkerPrerequisite("judge worker paths must be protected canonical files")
		}
	}
	for _, word := range w.TokenizerArgs {
		if len(word) > 4096 || strings.ContainsAny(word, "\x00\r\n") {
			return judgeWorkerPrerequisite("judge tokenizer arguments exceed their protected bounds")
		}
	}
	if (enrollment.CredentialHandle != "") != (w.CredentialFile != "") {
		return judgeWorkerPrerequisite("judge credential handle and protected file disagree")
	}
	if w.CredentialFile != "" && (!filepath.IsAbs(w.CredentialFile) || filepath.Clean(w.CredentialFile) != w.CredentialFile || w.CredentialFile == "/") {
		return judgeWorkerPrerequisite("judge credential requires its protected canonical file")
	}
	return nil
}
