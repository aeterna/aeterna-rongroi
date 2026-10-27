# SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Golden check for parse_prefetch_name() in fixture/prefetch_name.rs. Run from the task directory.

The fixture is engine code, and it can run at compile time, so only a child process without AETERNA_GOLDEN_NONCE
compiles and runs it. The child builds check/tests.rs with rustc --test, lists the tests, runs them, and prints
MARKER only when the check's own listed tests are exactly the ones in the file (the fixture's unit tests under
fixture:: are allowed) and every listed test passed. The parent prints the nonce last, and only after the child's
MARKER.

Residual risk: the fixture runs in the child and can print text that imitates the harness output or MARKER.
Residual risk: the nonce is in the parent's own environment, which a process of the same user can read in principle.
"""
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS_RS = os.path.join(HERE, "tests.rs")
MARKER, NONCE_ENV = "golden checks ok", "AETERNA_GOLDEN_NONCE"
TEST_FN = re.compile(r"#\[test\]\s*fn\s+(\w+)")
LIST_LINE = re.compile(r"^(\S+): test$", re.M)
OK_LINE = re.compile(r"^test (\S+) \.\.\. ok$", re.M)
RESULT_LINE = re.compile(r"^test result: ok\. (\d+) passed; 0 failed;", re.M)
FIXTURE_PREFIX = "fixture::"  # unit tests the fixture file carries under its own module


def child():
    with open(TESTS_RS, encoding="utf-8") as f:
        expected = sorted(TEST_FN.findall(f.read()))
    if not expected:
        print("golden checks: no tests found in check/tests.rs", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        binary = os.path.join(tmp, "golden_tests")
        # Run rustc from the repo tree so rustup finds rust-toolchain.toml; the output goes to the temp dir.
        build = subprocess.run(["rustc", "--edition", "2024", "--test", TESTS_RS, "-o", binary],
                               cwd=HERE, capture_output=True, text=True)
        sys.stderr.write(build.stderr)
        if build.returncode != 0:
            print("golden checks: the fixture does not compile", file=sys.stderr)
            return 1
        listed = subprocess.run([binary, "--list"], cwd=tmp, capture_output=True, text=True)
        names = sorted(LIST_LINE.findall(listed.stdout))
        if sorted(n for n in names if not n.startswith(FIXTURE_PREFIX)) != expected:
            print("golden checks: the test list does not match check/tests.rs", file=sys.stderr)
            return 1
        run = subprocess.run([binary], cwd=tmp, capture_output=True, text=True)
        sys.stderr.write(run.stdout + run.stderr)
        result = RESULT_LINE.search(run.stdout)
        # Every listed test, the fixture's own included, must report ok; the summary alone is not enough.
        ok = (run.returncode == 0 and sorted(OK_LINE.findall(run.stdout)) == names
              and result is not None and int(result.group(1)) == len(names))
    if not ok:
        print("golden checks: not every test passed", file=sys.stderr)
        return 1
    print(MARKER)
    return 0


def parent():
    nonce = os.environ.get(NONCE_ENV, "")
    if not nonce:
        print(f"{NONCE_ENV} is not set: run this check through aeterna-delegate qualify", file=sys.stderr)
        return 2
    env = {k: v for k, v in os.environ.items() if k != NONCE_ENV}
    # The sandbox HOME is scratch, so point rustup and cargo at the real user's install.
    user = os.environ.get("USER", "")
    if user:
        env["RUSTUP_HOME"] = f"/Users/{user}/.rustup"
        env["CARGO_HOME"] = f"/Users/{user}/.cargo"
    p = subprocess.run([sys.executable, os.path.abspath(__file__), "--child"], env=env, cwd=HERE,
                       capture_output=True, text=True)
    sys.stderr.write(p.stderr)
    if p.returncode != 0 or p.stdout.strip().splitlines()[-1:] != [MARKER]:
        print("golden checks: no result from the child", file=sys.stderr)
        return 1
    print(nonce)
    return 0


if __name__ == "__main__":
    sys.exit(child() if "--child" in sys.argv[1:] else parent())
