# Handoff — CI/CD Pipeline Optimization: Deduplication, Ruleset Compatibility & Acceleration

> # ⚡ CI/CD Optimization (Phase 1–4) เสร็จสมบูรณ์และใช้งานจริง (2026-10-18 01:10)
>
> **ทำไม:** แก้ปัญหาคอขวดการรัน CI/CD ของ `aeterna-rongroi` ซึ่งเดิมใช้เวลาบน Windows runner นานถึง 27–35 นาที และเกิดการรันซ้ำซ้อนถึง 4 รอบตลอดวงจร Release (Quadruple Execution: `feat PR` → `push dev` → `dev PR` → `push main` รวมสะสมกว่า 140 นาที) ปรับปรุงใหม่ให้เหลือเพียง ~12–18 นาที พร้อม Fast Promotion Gate (14 วินาที) โดยเคารพกฎ GitHub Rulesets 100%
> **เจ้าของการตัดสินใจ:** Pik (อนุมัติแผน 2026-10-18) · **ทำโดย:** AI Pair Programming Session
> **Pull Requests:** [#190](https://github.com/aeterna/aeterna-rongroi/pull/190) (`ci/optimize-pipeline` → `dev`) · [#191](https://github.com/aeterna/aeterna-rongroi/pull/191) (`dev` → `main`)

---

## 1. สถานะตอนนี้

| รายการ | สถานะเดิม | สถานะใหม่ (หลัง Phase 1–4) | ผลลัพธ์จริงบน Production (Verified) |
|---|---|---|---|
| **PR เอกสาร / Markdown (`docs/**`)** | รัน Windows CI เต็ม 35m + Linux 5.5m | **Fast-Pass (< 15 วินาที)** ผ่าน Status Checks ทันที | ✅ ผ่านทุก Context ภายใน ~14 วินาที |
| **Release PR (`dev -> main`)** | รัน Windows CI เต็ม 35m + Linux 5.5m | **Promotion Fast Gate (< 15 วินาที)** ผ่าน Status Checks ทันที | ✅ [PR #191](https://github.com/aeterna/aeterna-rongroi/pull/191) ผ่านทุก Check ใน **14 วินาที** |
| **Post-Merge Push (`push: dev`, `push: main`)** | รัน Live OS tests ซ้ำอีก 35m | **Lightweight Mode:** อัปเดต Cache เฉพาะส่วนที่จำเป็น | ✅ `push: dev` windows-live จบใน **17s** · `push: main` จบใน **2m54s** |
| **Windows CI Execution Pattern** | Monolithic Sequential (22 ขั้นตอนเรียงเดี่ยว) | **2-Lane Parallel:** `windows-cargo` (~15m) และ `windows-live` (~18m) | ✅ [PR #190](https://github.com/aeterna/aeterna-rongroi/pull/190) รันขนานกันสมบูรณ์ |
| **Defender & Tauri Contention** | `tauri build` โดนสแกน I/O หน่วงช่วง Defender เปิด | **Defender Isolation:** ย้าย `tauri build` ออกนอกช่วงสแกน | ✅ ไร้ข้อขัดแย้ง I/O disk lock บน NTFS |
| **PowerShell SBL Benchmark** | 36 cases รันทุก PR + Sleep 3s (idle 108s) | Sleep ลดเหลือ 1s + สโคปเฉพาะการแก้ posture rules | ✅ ลด idle time ของ runner อย่างมีนัยสำคัญ |
| **Linux Fuzz Smoke** | 9 targets รันเรียงแถวเดียว (318s) | **2-Worker Parallel:** 2 threads บน 2 vCPUs | ✅ ลดเวลาลงเหลือ **3m17s** (~197s) |
| **GitHub Ruleset Contexts** | 5 contexts บังคับ (`protect-dev`, `protect-main`) | **คงชื่อ context เดิมครบ 100%** ผ่าน Aggregator Job | ✅ Ruleset ปลดล็อกปุ่ม Merge ได้ 100% |

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

- ไม่มีงานค้าง — CI/CD Pipeline ผ่านการทดสอบ รันจริงบน Production และรวมเข้าสู่ `dev` ([PR #190](https://github.com/aeterna/aeterna-rongroi/pull/190)) และ `main` ([PR #191](https://github.com/aeterna/aeterna-rongroi/pull/191)) ครบถ้วน 100%

---

## 4. ทางถอย (Rollback)

- หากเกิดข้อผิดพลาด สามารถ Revert commit `6254e34` (บน dev) หรือ `a44b9ca` (บน main) เพื่อคืนค่า `ci.yml` และ `windows.yml` กลับสู่สถานะ Monolithic เดิมได้ทันทีโดยไม่มีผลข้างเคียงต่อตัวโค้ดหรือฐานข้อมูล

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
5. **เปิด Pull Request และเฝ้าสังเกตการณ์ Telemetry จริง (Production Deployment):**
   - เปิด [PR #190](https://github.com/aeterna/aeterna-rongroi/pull/190) เข้า `dev`: ผ่านทุก Checks, รวม Squash merge เข้า `dev` (`6254e34`)
   - สังเกตการณ์ `push: dev`: `windows-live` fast-pass 17 วินาที, `ci.yml` 3m21s
   - เปิด [PR #191](https://github.com/aeterna/aeterna-rongroi/pull/191) จาก `dev` เข้า `main`: Fast Promotion Gate ทำงานสมบูรณ์ ผ่านใน **14 วินาที**, ผสานเข้า `main` (`a44b9ca`)
   - สังเกตการณ์ `push: main`: `windows.yml` จบใน **2m54s**, `ci.yml` จบใน **3m23s**
