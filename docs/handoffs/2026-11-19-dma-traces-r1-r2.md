<!--
SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Handoff — DMA traces: releases 0.16.0 (R1) and 0.17.0 (R2)

> **สถานะ:** ออกทั้งสอง release แล้วเมื่อ 2026-11-19 · rule ใหม่ทุกตัวเป็น `experimental`
> **ADR:** [0095](../adr/0095-pci-positions-windows-started.md) (PCI) · [0096](../adr/0096-usb-display-bluetooth-devices.md) (USB, จอ, Bluetooth, ช่วงก่อนตรวจ)
> **Release:** [`v2026.11.19-0.16.0`](https://github.com/aeterna/aeterna-rongroi/releases/tag/v2026.11.19-0.16.0) · [`v2026.11.19-0.17.0`](https://github.com/aeterna/aeterna-rongroi/releases/tag/v2026.11.19-0.17.0) · `release.json` = 0.17.0
> **เจ้าของการตัดสินใจ:** Pik · **ทำโดย:** Claude Code - Claude Opus 5.5 (Orchestrator) กับ engineer run ผ่าน `aeterna-delegate`

## 1. สิ่งที่ออกไปแล้ว

| Release | PR | เนื้อหา |
|---|---|---|
| 0.16.0 | #296, #297, #298, #299, #300 | ข้อมูล PCI จาก bus (class, link speed/width, จำนวนลูก) · bug check 0xE6 · `pci_start_history` และ rule `not-every-start` |
| 0.17.0 | #301, #302, #304, #305, #306 | `usb_device`, `display_device`, `bluetooth_device` (เฉพาะ full scan) · rule absent ของ USB และจอ · ตัวนับอุปกรณ์ที่ถูกถอดและการเริ่ม Windows ในช่วงก่อนตรวจ |

ตรวจแล้ว:

- **CI:** ผ่านทุก PR และทุก run บน dev/main
- **Hash:** ตรงกับ `SHA256SUMS`
- **Build ทางการบน PC ของ Pik:** ขึ้น official build
- **Full scan บนเครื่องจริง:** อ่าน USB 22 แถว จอ 2 จอ และ Bluetooth 11 แถว ไม่มีเลข hex 12 ตัวในชื่อ
- **Lab VM:** ผลตาม ADR 0096 หัวข้อ "Lab VM check" เวลาถอด USB เหมือน PCI คือ
  - ถอดตอนเปิดเครื่อง: มีเวลาถอด
  - shutdown เต็มแล้วถอด: ไม่มีเวลาถอด
  - Fast Startup แล้วถอด: มีเวลาถอด เป็นเวลาตอนที่ Windows กลับมาทำงาน

### Pilot (2026-11-20)

0.17.0 คือตัว pilot ไม่ต้อง release ใหม่ เพราะ README แสดงจาก `dev` และเว็บ deploy เองเมื่อ `site/` บน `dev` เปลี่ยน

- **#308:** README ทั้งสองภาษาขึ้น 85 rules จาก 27 collectors และมีแถว Hardware & Devices กับแถวช่วงก่อนสแกน
  - เว็บมีแถว "ฮาร์ดแวร์และอุปกรณ์" ในตาราง "ตรวจอะไรบ้าง"
  - ประโยคเรื่อง DMA บอกว่าแสดงได้แค่ร่องรอยที่ฮาร์ดแวร์ทิ้งไว้ ไม่ใช่ตัวโปร
- **#309:** กล่อง source ใน diagram สถาปัตยกรรมเปลี่ยนเป็น "Devices · PCI · USB / HID · displays · Bluetooth"
- **Feedback จาก pilot:** รับผ่าน GitHub issue template ได้แก่ false positive, false negative, bug และขอ rule ใหม่

## 2. ยังไม่ได้ทำ

- **วัดเครื่องจริงให้ครบ 3 เครื่อง:** ต้องทำก่อนเลื่อน rule ใหม่จาก `experimental` ตอนนี้วัดแล้วเครื่องเดียวคือ PC ของ Pik
  - เครื่องทีมงานอีก 2 เครื่องรอคนรัน `staff-pci-channel-check.ps1`
- **การ์ด PCIe แยก:** ยังไม่เคยเพิ่มหรือย้ายบนเครื่องจริง (ADR 0095 "Not covered")
- **จอที่มีรหัสรุ่นจริง:** ยังไม่ได้ทดสอบการเพิ่มและถอด เพราะ VM มีแค่ `DISPLAY\DEFAULT_MONITOR` ต้องทดสอบบนเครื่องจริง
- **Bluetooth LE (`BTHLEDEVICE`):** ยังไม่อ่าน จนกว่าจะมีเครื่องให้วัด
- **การนำเข้าบันทึกและ Connect:** collector ใหม่ทั้งสามยังไม่อยู่ใน `DEVICE_COLLECTORS` และ Connect จนกว่าจะมี consent สำหรับการ upload (ADR 0096 ข้อ 4)

## 3. สิ่งที่ session ถัดไปควรรู้

1. **Engine เขียนโค้ดบน win ตอนนี้ไปลง agy/gemini และไม่ compile ก่อนส่ง patch:** R2 ต้องส่ง run แก้ตามอีก 9 รอบ
   - หลัง apply ทุกครั้ง ให้รันด่านเต็มเอง ได้แก่ fmt, clippy (รวม test target), test ทั้ง workspace, xtask ทุกตัว และ `cargo xtask readme-diagram`
   - CI เคยล้มเพราะไม่ได้ generate ตัวสุดท้ายนี้
2. **บน win ไม่มี pnpm:** ให้รัน desktop test บน Mac ด้วย `pnpm --pm-on-fail=ignore` เพราะ version ที่ pin ไว้ไม่ตรงกับ pnpm บน Mac
3. **Repo นี้เป็น public:** `aeterna-delegate` จะปฏิเสธ run ถ้า HEAD ยังไม่ได้ push ขึ้น origin ต้อง push branch ก่อน dispatch ทุกครั้ง
4. **`fleet dispatch exec` ยอมแค่ fast-forward:** ก่อน dispatch ให้ `fleet sync fetch` แล้ว merge แบบ ff เข้า branch บน Mac ก่อน
   - หลัง `fleet sync push` เข้า worktree ที่ checkout branch นั้นอยู่ ref จะขยับแต่ index ไม่ขยับตาม ต้อง `git checkout HEAD -- <files>` เอง
5. **ลบ exec worktree บน win:** ใช้ repo แบบ bare `git --git-dir=/home/heavy/fleet/aeterna-rongroi.git worktree remove <path>`
6. **Lab VM:** สคริปต์อยู่ที่ `.claude/probes/r2-vm-2026-11-19/lab-r2.sh` ซึ่งอยู่นอก git
   - ใช้ overlay disk บน WD1TB
   - QEMU `usb-serial` ต้องใส่ `always-plugged=on` ถึงจะต่อเข้า Windows
   - ใน zsh ตัวแปรใน `for` loop ที่ไม่ใส่ quote จะไม่แยกคำ

## 4. ของที่ยังค้าง

- **Branch `integ/dma-r1`, `lane/dma-r1/l1` และ `lane/dma-r1/l3` บน Mac:** เป็น branch local ของ R1 ที่ไม่มี PR
  - เนื้อหาอยู่ใน #296 (`391332c99`) แล้ว แต่ squash ทำให้ `git cherry` บอกว่าไม่ตรง
  - hook §4.1 ไม่ให้ลบแบบบังคับ จึงต้องให้ Pik ลบเอง
- **Ref `feat/r2-devices` ใน mirror ของ fleet บน win** (`~/fleet/aeterna-rongroi.git`): squash-merge แล้วใน #302 ลบแบบบังคับไม่ได้ด้วยเหตุผลเดียวกัน
- **Overlay ของ lab VM ที่ `/Volumes/WD1TB/aeterna-vm.noindex/rongroi-dma-lab/r2/`:** โฟลเดอร์ lab ทั้งหมดรอ Pik ตัดสินว่าจะลบเมื่อไร
- **แผนงานและตารางสถานะ:** artifact `RmsnkSCEWfJNucMcfjvQe3`
