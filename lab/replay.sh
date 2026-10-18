#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.
#
# Boots the maintainer's Windows 11 Arm lab VM from a throwaway copy-on-write overlay, optionally runs one
# scenario's setup.ps1, scans with rongroi.exe, powers off, deletes the overlay and checks the scan with
# `cargo xtask lab-check`. Design: docs/adr/0076-lab-replay.md. macOS host only (qemu-system-aarch64 with
# HVF, qemu-img, hdiutil).
#
# Usage:
#   lab/replay.sh control              one scan of a fresh overlay with no setup (ADR 0076 §1 control scan)
#   lab/replay.sh <scenario-dir>       e.g. lab/scenarios/posture/script-block-logging-off
#                                      (must contain setup.ps1 and expect.yaml)
#   lab/replay.sh -h                   this text
#
# Environment:
#   RONGROI_LAB          (required) lab folder holding win.qcow2 (installed system disk, never written here),
#                        efivars.fd, share.img (FAT32 raw disk labelled LAB) and cli.exe (the build to run).
#   RONGROI_LAB_TIMEOUT  seconds to wait for the VM to power off (default 1800).
#   RONGROI_LAB_CONTROL  optional path to the control scan.json, passed to lab-check as --control.
#   QEMU_SHARE           qemu data dir holding edk2-aarch64-code.fd (default /opt/homebrew/share/qemu).
#
# Exit status: 0 success (control: prints the scan path); 1 refused or bad usage; 2 timeout (VM killed);
# 3 no scan.json from the VM; otherwise the status of lab-check.

set -euo pipefail

# Shared with the maintainer's other lab script on purpose, so the two never run at once.
RUNDIR=/tmp/rr-dmalab
PIDFILE="$RUNDIR/qemu.pid"
SHARE_MNT="$RUNDIR/share"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
SCENARIOS_ROOT="$REPO_ROOT/lab/scenarios"
QEMU_SHARE="${QEMU_SHARE:-/opt/homebrew/share/qemu}"
TIMEOUT="${RONGROI_LAB_TIMEOUT:-1800}"

# State shared with the EXIT trap. Defined before anything can exit, so set -u is safe.
IS_CONTROL=0
NAME=""
SCEN_DIR=""
RESTART=0
RUN_ID=""
WORK=""
RESULTS=""
QEMU_PID=""
SHARE_MOUNTED=0

die() {
  local code=$1
  shift
  echo "replay: $*" >&2
  exit "$code"
}

# Prints the usage comment block at the top of this file (range-matched, so edits above it cannot break it).
usage() {
  sed -n '/^# Usage:/,/^$/p' "$0" | sed 's/^# \{0,1\}//'
}

# QEMU option strings split on commas; a literal comma in a path must be doubled.
qesc() {
  printf '%s' "${1//,/,,}"
}

parse_args() {
  if [[ $# -ne 1 ]]; then
    usage >&2
    exit 1
  fi
  case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
    control)
      IS_CONTROL=1
      NAME=control
      ;;
    *)
      [[ -d "$1" ]] || die 1 "no such scenario directory: $1"
      SCEN_DIR="$(cd -- "$1" && pwd)"
      [[ -f "$SCEN_DIR/setup.ps1" && -f "$SCEN_DIR/expect.yaml" ]] ||
        die 1 "$1 must contain setup.ps1 and expect.yaml"
      # Name used in RUN_ID and the ledger hint: the path below lab/scenarios when there is one.
      if [[ "$SCEN_DIR" == "$SCENARIOS_ROOT"/* ]]; then
        NAME="${SCEN_DIR#"$SCENARIOS_ROOT"/}"
      else
        NAME="$(basename -- "$SCEN_DIR")"
      fi
      # ADR 0076 §1: a scenario may ask for one restart between setup and scan (Windows reads some
      # settings only at boot). The control scan never restarts.
      if grep -Eq '^restart:[[:space:]]*true[[:space:]]*$' "$SCEN_DIR/expect.yaml"; then
        RESTART=1
      fi
      ;;
  esac
}

check_host() {
  [[ "$(uname -s)" == Darwin ]] || die 1 "macOS host only"
  local tool
  for tool in qemu-system-aarch64 qemu-img hdiutil; do
    command -v "$tool" >/dev/null || die 1 "$tool not found in PATH"
  done
  [[ -f "$QEMU_SHARE/edk2-aarch64-code.fd" ]] ||
    die 1 "no UEFI firmware at $QEMU_SHARE/edk2-aarch64-code.fd (set QEMU_SHARE)"
}

# Refuse rather than create anything: the lab folder may be on a drive that is unplugged, and a missing
# folder must not be recreated in its place.
check_lab() {
  [[ -n "${RONGROI_LAB:-}" ]] || die 1 "RONGROI_LAB is not set"
  [[ -d "$RONGROI_LAB" ]] || die 1 "lab folder not found: $RONGROI_LAB (drive unplugged?)"
  local f
  for f in win.qcow2 efivars.fd share.img cli.exe; do
    [[ -f "$RONGROI_LAB/$f" ]] || die 1 "missing $f in $RONGROI_LAB (drive unplugged?)"
  done
  [[ "$TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die 1 "RONGROI_LAB_TIMEOUT must be a positive number of seconds"
}

# ADR 0076 §1 / Behaviour 1: one lab VM at a time. A pidfile whose process is gone is stale and ignored.
check_not_running() {
  local pid
  pid="$(cat -- "$PIDFILE" 2>/dev/null || true)"
  if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
    die 1 "another lab VM is running (pid $pid, $PIDFILE); refusing to start"
  fi
  rm -f -- "$PIDFILE"
}

# Runs on every exit, including timeouts, refusals and signals. Only the two overlay files are deleted,
# by exact path: WORK is checked first so an unset WORK can never turn these into "/disk.qcow2".
cleanup() {
  local rc=$?
  if [[ -n "$QEMU_PID" ]] && kill -0 "$QEMU_PID" 2>/dev/null; then
    kill "$QEMU_PID" 2>/dev/null || true
  fi
  if (( SHARE_MOUNTED )); then
    unmount_share || true
  fi
  if [[ -n "$WORK" ]]; then
    rm -f -- "$WORK/disk.qcow2" "$WORK/efivars.fd"
  fi
  exit "$rc"
}

new_run() {
  RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-${NAME//\//-}"
  WORK="$RONGROI_LAB/replay/$RUN_ID"
  RESULTS="$WORK/results"
  mkdir -p -- "$RUNDIR" "$WORK"
  # Install the trap only once WORK is set, so cleanup never acts on an empty path.
  trap cleanup EXIT
  # INT and TERM must go through exit so the EXIT trap still runs.
  trap 'exit 130' INT TERM
  echo "replay: run $RUN_ID"
}

# Overlay: the installed disk is the read-only backing file; every write lands in disk.qcow2, which is
# deleted on exit. efivars.fd is copied because UEFI writes variables at every boot.
make_overlay() {
  qemu-img create -q -f qcow2 -b "$RONGROI_LAB/win.qcow2" -F qcow2 "$WORK/disk.qcow2"
  cp -- "$RONGROI_LAB/efivars.fd" "$WORK/efivars.fd"
}

mount_share() {
  mkdir -p -- "$SHARE_MNT"
  hdiutil attach -imagekey diskimage-class=CRawDiskImage -nobrowse -mountpoint "$SHARE_MNT" \
    "$RONGROI_LAB/share.img" >/dev/null
  SHARE_MOUNTED=1
}

# The share must be detached before boot (the VM gets the image directly) and after the run. The -force
# fallback covers a busy volume; it is not the first choice.
unmount_share() {
  hdiutil detach "$SHARE_MNT" -quiet || hdiutil detach "$SHARE_MNT" -force -quiet
  SHARE_MOUNTED=0
}

# run.ps1 is written here with the scenario's restart flag filled in. The heredoc is quoted so PowerShell
# variables are not expanded by bash; the one placeholder is replaced by sed.
write_run_ps1() {
  sed "s/__RESTART__/$RESTART/" >"$SHARE_MNT/run.ps1" <<'PS1'
param([string]$Root)
$out = Join-Path $Root 'out'; New-Item -ItemType Directory -Force -Path $out | Out-Null
Start-Transcript -Path (Join-Path $out 'transcript.txt') -Append -Force
Start-Sleep 60
$setup = Join-Path $Root 'setup.ps1'; $done = Join-Path $Root 'setup.done'
if ((Test-Path $setup) -and -not (Test-Path $done)) {
  & $setup *> (Join-Path $out 'setup.txt'); Set-Content -Path $done -Value (Get-Date).ToUniversalTime().ToString('o')
  if (__RESTART__ -eq 1) { Stop-Transcript; shutdown /r /f /t 10; exit }
}
& (Join-Path $Root 'rongroi.exe') scan --json 1> (Join-Path $out 'scan.json') 2> (Join-Path $out 'scan-stderr.txt')
Remove-Item (Join-Path $Root 'run.ps1')
Stop-Transcript
shutdown /s /f /t 10
PS1
}

# Clears what an earlier run left on the share, then stages this run's files. The share is the only way
# in and out of the VM, so nothing from a previous run may be left where this run could pick it up.
prepare_share() {
  mount_share
  if [[ -d "$SHARE_MNT/out" ]]; then
    find "$SHARE_MNT/out" -type f -delete
  fi
  rm -f -- "$SHARE_MNT/run.ps1" "$SHARE_MNT/setup.ps1" "$SHARE_MNT/setup.done"
  cp -f -- "$RONGROI_LAB/cli.exe" "$SHARE_MNT/rongroi.exe"
  if (( ! IS_CONTROL )); then
    cp -- "$SCEN_DIR/setup.ps1" "$SHARE_MNT/setup.ps1"
  fi
  write_run_ps1
  unmount_share
}

# No network device at all (-nic none): the VM cannot fetch anything during a run.
boot_vm() {
  local args=(
    -M virt -accel hvf -cpu host -smp 4 -m 4096
    -drive "if=pflash,format=raw,unit=0,file=$(qesc "$QEMU_SHARE")/edk2-aarch64-code.fd,readonly=on"
    -drive "if=pflash,format=raw,unit=1,file=$(qesc "$WORK")/efivars.fd"
    -device ramfb -device qemu-xhci,id=xhci -device usb-kbd -device usb-tablet
    -drive "if=none,id=sys,file=$(qesc "$WORK")/disk.qcow2,format=qcow2" -device nvme,drive=sys,serial=lab0
    -drive "if=none,id=share,file=$(qesc "$RONGROI_LAB")/share.img,format=raw"
    -device usb-storage,drive=share,removable=on
    -device pcie-root-port,id=rp1,chassis=1,slot=1
    -nic none -vnc 127.0.0.1:5 -display none
    -daemonize -pidfile "$PIDFILE"
  )
  rm -f -- "$PIDFILE"
  local start
  start="$(date +%s)"
  qemu-system-aarch64 "${args[@]}"
  wait_for_pidfile
  QEMU_PID="$(cat -- "$PIDFILE")"
  wait_for_power_off "$start"
}

# With -daemonize the pidfile is written by the child; poll briefly rather than assume the order.
wait_for_pidfile() {
  local i
  for ((i = 0; i < 30; i++)); do
    if [[ -s "$PIDFILE" ]] && [[ "$(cat -- "$PIDFILE")" =~ ^[0-9]+$ ]]; then
      return 0
    fi
    sleep 1
  done
  die 1 "qemu did not write $PIDFILE"
}

# ADR 0076 "What is unverified" asks for the replay time, so the elapsed time is always printed.
# The clock starts at boot, not at logon, because the VM's own 60 s wait is part of the cost.
wait_for_power_off() {
  local start=$1
  local elapsed
  while kill -0 "$QEMU_PID" 2>/dev/null; do
    elapsed=$(( $(date +%s) - start ))
    if (( elapsed >= TIMEOUT )); then
      kill "$QEMU_PID" 2>/dev/null || true
      echo "VM off after ${elapsed}s"
      die 2 "timed out after ${TIMEOUT}s; VM killed"
    fi
    sleep 5
  done
  elapsed=$(( $(date +%s) - start ))
  echo "VM off after ${elapsed}s"
}

# The raw scan stays under WORK, outside the repository (ADR 0076 §4).
fetch_results() {
  mount_share
  mkdir -p -- "$RESULTS"
  if [[ -d "$SHARE_MNT/out" ]]; then
    cp -R -- "$SHARE_MNT/out/." "$RESULTS/"
  fi
  unmount_share
  [[ -s "$RESULTS/scan.json" ]] ||
    die 3 "no scan: $RESULTS/scan.json is missing or empty (see $RESULTS/transcript.txt)"
}

run_check() {
  if (( IS_CONTROL )); then
    echo "control scan: $RESULTS/scan.json"
    exit 0
  fi
  cd -- "$REPO_ROOT"
  local cmd=(cargo xtask lab-check --expect "$SCEN_DIR/expect.yaml" --scan "$RESULTS/scan.json")
  if [[ -n "${RONGROI_LAB_CONTROL:-}" ]]; then
    cmd+=(--control "$RONGROI_LAB_CONTROL")
  fi
  local status=0
  "${cmd[@]}" || status=$?
  echo "replay: to print ledger rows, run: cargo xtask lab-check --expect \"$SCEN_DIR/expect.yaml\"" \
    "--scan \"$RESULTS/scan.json\" --evidence \"lab/scenarios/$NAME (run $RUN_ID)\" --date $(date -u +%Y-%m-%d)"
  exit "$status"
}

main() {
  parse_args "$@"
  check_host
  check_lab
  check_not_running
  new_run
  make_overlay
  prepare_share
  boot_vm
  fetch_results
  run_check
}

main "$@"
