"""Run on the disposable Linux box; retain scanner inputs and observed exits."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def exempt_cases():
    # Approved positives contain only the three eligible rules. Key headers
    # and denylist matches have separate negative fixtures under the gate contract.
    line = ("note café: " + "z" * 64 + " "
            + ".".join(["203", "0", "113", "7"]) + " review" + "@"
            + "example.invalid").encode("utf-8")
    comment = b"# Synthetic fixture; approval: self-test only.\n"

    def approval(text, path="sample.txt"):
        return comment + path.encode("utf-8") + b"\t" + hashlib.sha256(text).hexdigest()[:32].encode() + b"\n"

    entry = approval(line)[len(comment):]
    approved = comment + entry
    rules = ["long-secret-like-token", "email-address", "non-loopback-ipv4"]
    denied = line + b" fixture-marker"
    key_header = line + b" -----BEGIN " + b"PRIVATE KEY-----"
    cases = {
        "exempt-line": {"exit": 0, "helper": ("1", entry)},
        "exempt-moved": {"exit": 0, "content": b"safe\n" + line + b"\n",
                         "helper": ("2", entry)},
        "exempt-copy": {"exit": 1, "content": line + b"\n" + line + b"\n",
                        "location": "sample.txt:2"},
        "exempt-literal": {"exit": 1, "content": line + b"\ncopy: " + line + b"\n",
                           "location": "sample.txt:2"},
        "exempt-other-file": {"exit": 1, "other": line + b"\n", "location": "other.txt:1"},
        "exempt-edited": {"exit": 1, "content": b"N" + line[1:] + b"\n"},
        "exempt-empty": {"exit": 1, "entries": b""},
        "exempt-header": {"exit": 1, "entries": comment},
        "exempt-missing": {"exit": 1, "entries": None},
        "exempt-env-empty": {"exit": 1, "entries": None, "env_empty": True},
        "exempt-no-lf": {"exit": 0, "content": line, "helper": ("1", entry)},
        "exempt-crlf": {"exit": 0, "content": line + b"\r\n",
                        "entries": approval(line + b"\r")},
        "exempt-cr-edit": {"exit": 1, "content": line + b"\r\n"},
        "exempt-raw": {"exit": 0, "content": line + b"\xff\n",
                       "entries": approval(line + b"\xff")},
        "exempt-multiline": {"exit": 1, "content": denied + b"\nnext\n",
                             "entries": approval(denied),
                             "rules": ["denylist-line-2"]},
        "exempt-stage-grant": {"exit": 1, "entries": comment, "tree_entries": comment,
                               "work_entries": approved},
        "exempt-stage-revoke": {"exit": 0, "tree_entries": approved, "work_entries": comment},
        "exempt-stage-edit": {"exit": 0, "work_content": b"N" + line[1:] + b"\n",
                              "work_exit": 1},
        "exempt-work-bad": {"exit": 0, "tree_entries": approved,
                            "work_entries": comment + b"bad entry\n"},
        "exempt-index-bad": {"exit": 0, "tree_entries": comment + b"bad entry\n",
                             "work_entries": approved},
        "exempt-tree-only": {"exit": 1, "entries": None, "tree_entries": approved},
        "exempt-tree-other": {"exit": 1, "entries": approval(line, "other.txt"),
                              "tree_entries": approved, "other": line + b"\n",
                              "forbid": ["SCAN FAIL other.txt:"]},
        "exempt-tree-hit": {"exit": 1, "entries": None,
                            "tree_entries": b"# " + b"z" * 64 + b"\n" + approved,
                            "location": "scripts/scan-exempt.txt:1",
                            "rules": ["long-secret-like-token"]},
        "exempt-denylist": {"exit": 1, "content": denied + b"\n",
                            "entries": approval(denied), "rules": ["denylist-line-1"],
                            "forbid": rules},
        "exempt-key-header": {"exit": 1, "content": key_header + b"\n",
                              "entries": approval(key_header), "rules": ["private-key-header"],
                              "forbid": rules},
        "exempt-file-missing": {"exit": 2, "missing": True},
        "exempt-unreadable": {"exit": 2, "list_directory": True},
    }
    malformed = {
        "bad-entry": comment + b"bad entry\n",
        "bad-hash": comment + b"sample.txt\t" + b"g" * 32 + b"\n",
        "short-hash": comment + entry[:-2] + b"\n",
        "extra-field": comment + entry.rstrip(b"\n") + b"\textra\n",
        "parent-path": comment + b"../" + entry,
        "absolute-path": comment + b"/" + entry,
        "no-comment": entry,
        "bad-utf8": b"\xff\n",
        "duplicate-entry": approved + approved,
    }
    for name, content in malformed.items():
        cases["exempt-" + name] = {"exit": 2, "entries": content}
    for fixture in cases.values():
        fixture.setdefault("content", line + b"\n")
        fixture.setdefault("entries", approved)
        fixture.setdefault("rules", rules)
        fixture.setdefault("location", "sample.txt:1")
    return cases


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--scanner", type=Path, default=Path(__file__).resolve().with_name("scan.sh"))
    parser.add_argument("--case", action="append", dest="cases")
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=True, mode=0o700)
    root = Path(tempfile.mkdtemp(prefix="lb-v2-integrate-scan-", dir=args.evidence)).resolve()
    scanner = args.scanner.resolve(strict=True)
    own = "laneboss.io/laneboss/" + "internal/v2/isolation/mac/fixture"
    long_literal = "z" * 64
    address = ".".join(["203", "0", "113", "7"])
    extra = exempt_cases()
    helper = Path(__file__).resolve().with_name("scan-exempt-line.sh")
    denylist = root / "fixture-deny.txt"
    denylist.write_text("fixture-marker\nfixture-marker\\nnext\n", encoding="utf-8")
    rows = [
        ("single", ".go", f'package sample\nimport "{own}"\n', None),
        ("alias", ".go", f'package sample\nimport (\n peer "{own}"\n)\n', None),
        ("single-alias", ".go", f'package sample\nimport peer "{own}"\n', None),
        ("dot", ".go", f'package sample\nimport (\n . "{own}"\n)\n', None),
        ("literal", ".go", f'package sample\nvar value = "{long_literal}"\n',
         "long-secret-like-token"),
        ("path-literal", ".go", f'package sample\nvar value = "{own}"\n',
         "long-secret-like-token"),
        ("raw-lookalike", ".go", f'package sample\nvar value = `\nimport (\n"{own}"\n)\n`\n',
         "long-secret-like-token"),
        ("comment-lookalike", ".go", f'package sample\n/*\nimport (\n"{own}"\n)\n*/\n',
         "long-secret-like-token"),
        ("trailing-comment", ".go", f'package sample\nimport "{own}" // note\n',
         "long-secret-like-token"),
        ("other-file", ".txt", f'import "{own}"\n', "long-secret-like-token"),
        ("foreign-module", ".go", 'package sample\nimport "other.invalid/' + long_literal + '"\n',
         "long-secret-like-token"),
        ("alias-token", ".go", f'package sample\nimport {long_literal} "{own}"\n',
         "long-secret-like-token"),
        ("import-other-rule", ".go", 'package sample\nimport "laneboss.io/laneboss/' +
         address + '/native"\n', "non-loopback-ipv4"),
        ("other-rule", ".go", f'package sample\nimport "{own}"\nvar contact = "' +
         "review" + "@" + 'example.invalid"\n', "email-address"),
        ("nonexistent-own-path", ".go", 'package sample\nimport "laneboss.io/laneboss/' +
         "a" * 64 + '"\n', "long-secret-like-token"),
        ("import-block-escape", ".go", f'package sample\nimport (\n); var value = (\n"{own}"\n)\n',
         "long-secret-like-token"),
        ("wrong-module", ".go", f'package sample\nimport "{own}"\n',
         "long-secret-like-token"),
        ("untracked-own-path", ".go", f'package sample\nimport "{own}"\n',
         "long-secret-like-token"),
        ("staged-content", ".go", f'package sample\nimport "{own}"\n', None),
    ]
    rows += [(name, ".txt", fixture["content"], None) for name, fixture in extra.items()]
    if args.cases:
        selected = set(args.cases)
        if selected - {row[0] for row in rows}:
            parser.error("unknown scanner case")
        rows = [row for row in rows if row[0] in selected]
    results = []
    for name, extension, content, failure_rule in rows:
        fixture = extra.get(name)
        directory = root / name
        directory.mkdir(mode=0o700)
        module = "other.invalid/sample" if name == "wrong-module" else "laneboss.io/laneboss"
        (directory / "go.mod").write_text("module " + module + "\n", encoding="utf-8")
        package = directory / "internal/v2/isolation/mac/fixture"
        package.mkdir(parents=True)
        (package / "package.go").write_text("package fixture\n", encoding="utf-8")
        sample = directory / ("sample" + extension)
        sample.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
        scan_env = dict(os.environ)
        scan_env.pop("LANEBOSS_SCAN_EXEMPT", None)
        scan_env.pop("LANEBOSS_SCAN_DENYLIST", None)
        if fixture is not None:
            # Only the gate list outside this disposable repository is trusted.
            approvals = root / (name + "-list.txt")
            if fixture["entries"] is not None:
                scan_env["LANEBOSS_SCAN_EXEMPT"] = str(approvals)
                if fixture.get("list_directory"):
                    approvals.mkdir()
                elif not fixture.get("missing"):
                    approvals.write_bytes(fixture["entries"])
            elif fixture.get("env_empty"):
                scan_env["LANEBOSS_SCAN_EXEMPT"] = ""
            scan_env["LANEBOSS_SCAN_DENYLIST"] = str(denylist)
            scripts = directory / "scripts"
            scripts.mkdir()
            if "tree_entries" in fixture:
                (scripts / "scan-exempt.txt").write_bytes(fixture["tree_entries"])
            if "other" in fixture:
                (directory / "other.txt").write_bytes(fixture["other"])
            if "helper" in fixture:
                helper_copy = scripts / helper.name
                helper_copy.write_bytes(helper.read_bytes())
                number, expected = fixture["helper"]
                call = subprocess.run(["sh", str(helper_copy), sample.name, number],
                                      capture_output=True, timeout=30, check=False)
                (root / f"{name}-helper.stdout").write_bytes(call.stdout)
                (root / f"{name}-helper.stderr").write_bytes(call.stderr)
                passed = call.returncode == 0 and call.stdout == expected and not call.stderr
                results.append({"id": name, "mode": "helper", "exit": call.returncode,
                                "passed": passed})
                print(("PASS " if passed else "FAIL ") + name + "/helper")
                if not passed:
                    raise RuntimeError("exemption helper output did not match the exact bytes")
        # Real disposable Git/index fixtures, only on the test box. The product
        # checkout/index is never staged or otherwise changed by this workload.
        setup = [["git", "init", "--quiet", str(directory)],
                 ["git", "-C", str(directory), "add", "--", "go.mod", sample.name]]
        if name != "untracked-own-path":
            setup.append(["git", "-C", str(directory), "add", "--", "internal"])
        if fixture is not None:
            setup.append(["git", "-C", str(directory), "add", "--all"])
        for index, command in enumerate(setup):
            prepared = subprocess.run(command, capture_output=True, timeout=30, check=False)
            (root / f"{name}-setup-{index}.stdout").write_bytes(prepared.stdout)
            (root / f"{name}-setup-{index}.stderr").write_bytes(prepared.stderr)
            if prepared.returncode != 0:
                raise RuntimeError("scanner Git fixture setup failed")
        # Deliberately disagree with index bytes. Only staged scanning should
        # retain the import exception; normal scanning must report the token.
        if name == "staged-content":
            (directory / "go.mod").write_text("module other.invalid/sample\n", encoding="utf-8")
            (package / "package.go").unlink()
        if fixture is not None:
            if "work_entries" in fixture:
                (directory / "scripts/scan-exempt.txt").write_bytes(fixture["work_entries"])
            if "work_content" in fixture:
                sample.write_bytes(fixture["work_content"])
        for staged in [False, True]:
            mode = "staged" if staged else "working"
            rule = "long-secret-like-token" if name == "staged-content" and not staged else failure_rule
            command = ["sh", str(scanner)] + (["--staged"] if staged else []) + [str(directory)]
            call = subprocess.run(command, capture_output=True, timeout=30, check=False, env=scan_env)
            (root / f"{name}-{mode}.stdout").write_bytes(call.stdout)
            (root / f"{name}-{mode}.stderr").write_bytes(call.stderr)
            output = call.stdout.decode("utf-8", "replace")
            if fixture is not None:
                expected = fixture["exit"] if staged else fixture.get("work_exit", fixture["exit"])
                passed = call.returncode == expected
                if expected == 0:
                    passed = passed and "SCAN PASS:" in output and "SCAN FAIL" not in output
                elif expected == 1:
                    passed = passed and "SCAN PASS:" not in output and all(
                        "SCAN FAIL " + fixture["location"] + " " + item in output
                        for item in fixture["rules"])
                else:
                    stderr = call.stderr.decode("utf-8", "replace")
                    passed = passed and "SCAN PASS:" not in output and "SCAN ERROR:" in stderr
                    passed = passed and "LANEBOSS_SCAN_EXEMPT" in stderr
                passed = passed and all(item not in output for item in fixture.get("forbid", []))
            elif rule is None:
                passed = call.returncode == 0 and "SCAN PASS:" in output
            else:
                passed = call.returncode == 1 and rule in output and "SCAN FAIL" in output
            results.append({"id": name, "mode": mode, "exit": call.returncode, "passed": passed})
            print(("PASS " if passed else "FAIL ") + name + "/" + mode + " exit=" + str(call.returncode))
    (root / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    return 0 if all(row["passed"] for row in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
