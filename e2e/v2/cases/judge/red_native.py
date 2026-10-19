"""Reached native judge controls, only on the authorized disposable Linux box."""

import argparse
import hashlib
import json
import shutil
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "linux" or not args.source.is_absolute() or not args.evidence.is_absolute():
        raise RuntimeError("native controls require absolute disposable Linux paths")
    source = args.source.resolve(strict=True)
    evidence = args.evidence
    evidence.mkdir(mode=0o700)
    rows = []
    go = shutil.which("go")
    if go is None:
        raise RuntimeError("native controls require the installed Go toolchain")

    def run(name, package, pattern, root=False):
        command = [go, "test", "-count=1", "-v", "-run", pattern]
        if root:
            command = ["sudo", *command, "-tags", "laneboss_root_canary"]
        command.append(package)
        result = subprocess.run(command, cwd=source, capture_output=True, timeout=600, check=False)
        (evidence / (name + ".stdout")).write_bytes(result.stdout)
        (evidence / (name + ".stderr")).write_bytes(result.stderr)
        (evidence / (name + ".exit")).write_text(str(result.returncode) + "\n")
        return result

    controls = [
        ("base-cli", "internal/v2/cli/internal_judge.go", None, None,
         "./e2e/v2/cases/judge", "^TestNativeCLIArguments$", "native CLI lost its fixed binding/lease handoff", False),
        ("base-producer", "scripts/v2-serve/case_judge.py", None, None,
         "./e2e/v2/cases/judge", "^TestJudgeProducer$", "installed judge producer is absent", False),
        ("native-dispatch", "internal/v2/judge/internal.go",
         b"func RunNativeJob(ctx context.Context, j NativeJob) (api.WorkerResultReceipt, error) {",
         b"func RunNativeJob(ctx context.Context, j NativeJob) (api.WorkerResultReceipt, error) {\nif ctx.Err() == nil { return api.WorkerResultReceipt{}, api.NotImplemented(\"lb-v2-judge\", \"internal.judge.job-lease\") }\n",
         "./e2e/v2/cases/judge", "^TestNativeWorkerExchange$", "native job omitted actual provider, fit or retained result", False),
        ("native-gate", "internal/v2/admin/judge_gate_linux.go",
         b"func (m *leaseManager) startJudgeGate(ctx context.Context, parent leaseRecord, w judgeNative) (ownedGate, error) {",
         b"func (m *leaseManager) startJudgeGate(ctx context.Context, parent leaseRecord, w judgeNative) (ownedGate, error) {\nif ctx.Err() == nil { return nil, failure(api.CodeNotImplemented, \"native judge gate is absent\") }\n",
         "./internal/v2/admin", "^TestJudgeGateNative$", "judge native gate unavailable", True),
        ("native-relay", "internal/v2/admin/judge_relay_linux.go",
         b"io.Copy(peer, io.LimitReader(provider, (1<<20)+65536))",
         b"io.Copy(peer, io.LimitReader(provider, 1))",
         "./internal/v2/admin", "^TestJudgeGateNative$", "judge provider relay lost exact worker bytes", True),
        ("native-recovery", "internal/v2/store/judge_recovery.go",
         b"func (s *Service) RecoverJudgeExecution(ctx context.Context, scope api.Scope, e api.JudgeExecution) (api.JudgeAudit, error) {",
         b"func (s *Service) RecoverJudgeExecution(ctx context.Context, scope api.Scope, e api.JudgeExecution) (api.JudgeAudit, error) {\nif ctx.Err() == nil { return api.JudgeAudit{}, api.NotImplemented(\"lb-v2-judge\", \"original measured recovery\") }\n",
         "./internal/v2/store", "^TestJudgeMeasuredRecovery$", "judge restart lost the original measured audit", False),
    ]
    for name, relative, anchor, replacement, package, pattern, assertion, root in controls:
        target = source / relative
        original = target.read_bytes()
        original_mode = target.stat().st_mode & 0o777
        if anchor is None:
            if name == "base-producer":
                # Measured base 1d2c9c6b has no producer. Its absence and
                # exact CLI bytes are recorded in the case handoff.
                changed = None
            else:
                changed = Path(__file__).with_name("base-cli.go.in").read_bytes()
        else:
            if original.count(anchor) != 1:
                raise RuntimeError("native control anchor is absent or ambiguous: " + name)
            changed = original.replace(anchor, replacement, 1)
        (evidence / (name + ".before")).write_bytes(original)
        if changed is not None:
            (evidence / (name + ".red")).write_bytes(changed)
        try:
            if changed is None:
                target.unlink()
            else:
                target.write_bytes(changed)
            result = run(name, package, pattern, root)
            combined = result.stdout + result.stderr
            if result.returncode != 1 or b"--- FAIL:" not in combined or assertion.encode() not in combined:
                raise RuntimeError("native control did not reach its named assertion: " + name)
            failure = next(line.decode("utf-8", errors="replace").strip()
                for line in combined.splitlines() if assertion.encode() in line)
            rows.append({"id": name, "reached": True, "exit": result.returncode,
                "failure": failure, "before_sha256": hashlib.sha256(original).hexdigest(),
                "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()})
        finally:
            target.write_bytes(original)
            target.chmod(original_mode)
            if target.read_bytes() != original:
                raise RuntimeError("native control did not restore exact candidate bytes")
        restored = run(name + "-green", package, pattern, root)
        if restored.returncode != 0:
            raise RuntimeError("restored native candidate failed: " + name)
        print(json.dumps({"red": rows[-1], "restored_exit": restored.returncode}), flush=True)
    (evidence / "result.json").write_text(json.dumps({"controls": rows}, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
