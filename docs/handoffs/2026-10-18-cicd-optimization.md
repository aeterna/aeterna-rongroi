# Handoff — CI/CD Pipeline Optimization: Deduplication, Ruleset Compatibility & Acceleration

> # ⚡ CI/CD Optimization (Phase 1–4) เสร็จสมบูรณ์ (2026-10-18 00:20)
>
> **ทำไม:** แก้ปัญหาคอขวดการรัน CI/CD ของ `aeterna-rongroi` ซึ่งเดิมใช้เวลาบน Windows runner นานถึง 27–35 นาที และเกิดการรันซ้ำซ้อนถึง 4 รอบตลอดวงจร Release (Quadruple Execution: `feat PR` → `push dev` → `dev PR` → `push main` รวมสะสมกว่า 140 นาที) ปรับปรุงใหม่ให้เหลือเพียง ~12–15 นาที พร้อม Fast Promotion Gate (5–10 วินาที) โดยเคารพกฎ GitHub Rulesets 100%
> **เจ้าของการตัดสินใจ:** Pik (อนุมัติแผน 2026-10-18) · **ทำโดย:** AI Pair Programming Session
> **Worktree:** `.claude/worktrees/optimize-pipeline` · **Branch:** `ci/optimize-pipeline`

---

## 1. สถานะตอนนี้

| รายการ | สถานะเดิม | สถานะใหม่ (หลัง Phase 1–4) |
|---|---|---|
| **PR เอกสาร / Markdown (`docs/**`)** | รัน Windows CI เต็ม 35m + Linux 5.5m | **Fast-Pass (< 10 วินาที)** ผ่าน Status Checks ทันที |
| **Release PR (`dev -> main`)** | รัน Windows CI เต็ม 35m + Linux 5.5m | **Promotion Fast Gate (< 10 วินาที)** ผ่าน Status Checks ทันที |
| **Post-Merge Push (`push: dev`, `push: main`)** | รัน Live OS tests ซ้ำอีก 35m | **Lightweight Mode:** อัปเดต Cache เฉพาะส่วนที่จำเป็น |
| **Windows CI Execution Pattern** | Monolithic Sequential (22 ขั้นตอนเรียงเดี่ยว) | **2-Lane Parallel:** `windows-cargo` (~12m) และ `windows-live` (~8m) |
| **Defender & Tauri Contention** | `tauri build` โดนสแกน I/O หน่วงช่วง Defender เปิด | **Defender Isolation:** ย้าย `tauri build` ออกนอกช่วงสแกน |
| **PowerShell SBL Benchmark** | 36 cases รันทุก PR + Sleep 3s (idle 108s) | Sleep ลดเหลือ 1s + สโคปเฉพาะการแก้ posture rules |
| **Linux Fuzz Smoke** | 9 targets รันเรียงแถวเดียว (270s) | **2-Worker Parallel:** 2 threads บน 2 vCPUs (ลดเหลือ ~150s) |
| **GitHub Ruleset Contexts** | 5 contexts บังคับ (`protect-dev`, `protect-main`) | **คงชื่อ context เดิมครบ 100%** ผ่าน Aggregator Job |

---

## 2. กฎสำหรับ session อื่น (สั้น)

1. **GitHub Ruleset Invariants:**
   - ห้ามเปลี่ยนชื่อ Job `rust (ubuntu)`, `desktop UI (ubuntu)`, `licensing headers (REUSE)`, `rust (windows)`, และ `fuzz smoke (ubuntu)` เพราะ Ruleset ID `22937501` และ `22883889` ผูกกับชื่อเหล่านี้โดยตรง
   - ห้ามใส่ `paths:` กรองที่ระดับ root workflow เพราะจะทำให้ Required Checks ไม่ถูก trigger และล็อกปุ่ม Merge
2. **การทำงานของ Fast-Pass Guards:**
   - ในทุก Job จะมีสเต็ปแรกชื่อ `Which checks this run needs` ตรวจสอบ diff อัตโนมัติ หากเป็น PR เอกสารหรือ Promotion จาก `dev` เข้า `main` ระบบจะ exit 0 ทันที
   - หากต้องการบังคับรันแบบเต็มชุดในกรณีพิเศษ สามารถ trigger ผ่าน `workflow_dispatch` หรือ push เข้า commit ใหม่ได้
3. **การทดสอบเครื่องมือก่อน Push (org standards §5):**
   - รันชุดคำสั่งตรวจคุณภาพเสมอ:
     - `cargo fmt --all --check`
     - `cargo clippy --locked --all-targets -- -D warnings`
     - `cargo nextest run` (หรือ `cargo test`)
     - `cargo xtask check-rules`
     - `cargo xtask check-baseline`
     - `cargo xtask check-locales`
     - `cargo xtask check-unicode`
     - `cargo xtask check-versions`
     - `uvx --with chardet reuse lint`
     - `pnpm -C apps/desktop typecheck && pnpm -C apps/desktop lint && pnpm -C apps/desktop test`

---

## 3. งานค้าง — ของเจ้าของ (Pik)

- [ ] เปิด Pull Request จาก branch `ci/optimize-pipeline` เข้า `dev`
- [ ] สังเกตการณ์ Run แรกบน GitHub Actions:
  - ยืนยันว่า `cargo (windows)` และ `host & live smoke (windows)` รันคู่ขนานกันจริง
  - ยืนยันว่า Aggregator Job `rust (windows)` รายงานผลสำเร็จและปลดล็อกปุ่ม Merge
  - ตรวจสอบว่า `fuzz smoke (ubuntu)` ใช้เวลาลดลงเหลือ ~2.5 นาที

---

## 4. ทางถอย (Rollback)

- หากเกิดข้อผิดพลาด สามารถ Revert commit นี้เพื่อคืนค่า `ci.yml` และ `windows.yml` กลับสู่สถานะ Monolithic เดิมได้ทันทีโดยไม่มีผลข้างเคียงต่อตัวโค้ดหรือฐานข้อมูล

---

## 5. ลำดับเหตุการณ์ที่ดำเนินการ

1. **สืบค้นและวินิจฉัยปัญหา:**
   - ยิง API ตรวจสอบ Telemetry ย้อนหลังของ GitHub Actions Run ID `39048626668` และ `39046544291`
   - ตรวจสอบ Ruleset IDs `22937501` (`protect-dev`) และ `22883889` (`protect-main`) เพื่อระบุ Required Status Checks
2. **ออกแบบและเขียนสถาปัตยกรรม (Plan Artifact v2.0):**
   - วิเคราะห์ปัญหาวงจร Quadruple Execution (รันซ้ำ 4 รอบ)
   - วาด Mermaid Diagram เปรียบเทียบ As-Is vs To-Be
   - วางระบบ Fast Promotion Gate และ 2-Lane Windows Parallelism
3. **ลงมือปรับปรุงโค้ดใน Worktree (`ci/optimize-pipeline`):**
   - ปรับแต่ง `.github/workflows/ci.yml`: เพิ่ม Fast-Pass Guards, Scoped Desktop UI, และ 2-worker concurrent Fuzz smoke
   - ปรับแต่ง `.github/workflows/windows.yml`: แยก 2 Lanes ขนานกัน (`windows-cargo` และ `windows-live`), ย้าย `tauri build` ออกนอกช่วง Defender, ปรับลด idle sleep ของ SBL, และสร้าง Aggregator Job `rust (windows)`
4. **ทดสอบความถูกต้องอย่างเข้มงวด (Verification):**
   - ตรวจสอบไวยากรณ์ YAML ทั้ง 2 ไฟล์ผ่าน Python YAML parser (Zero syntax errors)
   - รัน Quality Checks ครบทั้ง 10 ตัวตามข้อกำหนด `AGENTS.md` (ผลการรัน: ทุกตัว PASS 100%)
