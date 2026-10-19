# SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Golden check for redact_user_path() in fixture/redact_user_path.rs. Run from the task directory.

The fixture is engine code, and it can run at compile time, so only a child process without AETERNA_GOLDEN_NONCE
compiles and runs it. The child builds check/tests.rs with rustc --test, lists the tests, runs them, and prints
MARKER only when the listed tests are exactly the ones in the file and all of them passed. The parent prints the
nonce last, and only after the child's MARKER.

Residual risk: the fixture runs in the child and can print text that imitates the harness output or MARKER.
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
        if sorted(LIST_LINE.findall(listed.stdout)) != expected:
            print("golden checks: the test list does not match check/tests.rs", file=sys.stderr)
            return 1
        run = subprocess.run([binary], cwd=tmp, capture_output=True, text=True)
        sys.stderr.write(run.stdout + run.stderr)
        result = RESULT_LINE.search(run.stdout)
        ok = (run.returncode == 0 and sorted(OK_LINE.findall(run.stdout)) == expected
              and result is not None and int(result.group(1)) == len(expected))
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
