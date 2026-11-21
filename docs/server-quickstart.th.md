# ใช้ Rongroi บนเซิร์ฟเวอร์ของคุณ: เริ่มต้นใช้งาน

สำหรับเจ้าของเซิร์ฟเวอร์ที่อยากให้ผู้เล่นส่งผลตรวจเครื่องให้ทีมงานผ่าน **Rongroi Connect** Rongroi แสดงหลักฐานให้ทีมงานอ่าน
ไม่เคยบอกว่าเครื่องไหน "สะอาด" และไม่เตะหรือแบนใคร (ADR 0002)

English: [server-quickstart.md](server-quickstart.md) · การออกแบบ: [ADR 0097](adr/0097-easy-adoption-relay-and-rr2.md)

## เลือกทางที่รายงานจะมาถึงคุณ

| | ตรง (direct) | Rongroi Relay |
|---|---|---|
| ต้องมีเครื่องหรือ container เพิ่ม | ไม่ต้อง | container เล็กหนึ่งตัวที่คุณรันเอง (HTTPS) |
| พอร์ตเกมต้องรับ HTTP ธรรมดาจากผู้เล่น | ใช่ | ไม่ |
| ใช้หลัง Cfx proxy ได้ | ไม่ได้ | ได้ |
| ขนาดรายงาน | แบ่งส่งทีละ 4 KiB (เพดานของ Enhanced) | ส่งครั้งเดียว ไม่เกิน 2 MiB |
| รหัสจับคู่ | `rr1.` | `rr2.` (ต้องใช้ Connect 0.2 ขึ้นไป) |

AETERNA ไม่ได้รัน relay ให้ relay เป็นของคุณเหมือนเซิร์ฟเวอร์เกม

## FiveM แบบตรง (ประมาณ 10 นาที)

1. คัดลอก `nakara_rongroi` จาก [release ของ nakara-oss](https://github.com/aeterna/nakara-oss/releases?q=nakara_rongroi)
   ล่าสุดไปไว้ใน `resources/` ใช้ชื่อโฟลเดอร์ `nakara_rongroi` ตามเดิม
2. ใน `server.cfg`:
   ```
   ensure nakara_rongroi
   add_ace group.admin nakara_rongroi.staff allow
   set rongroi_public_origin "http://<IP หรือชื่อสาธารณะ>:<พอร์ตเกม>"
   ```
   ใช้ `set` ห้ามใช้ `setr`
3. เปิดเซิร์ฟเวอร์แล้วพิมพ์ `rongroi doctor` ใน console ทุกบรรทัดจะบอก `ok` หรือ `FAIL` พร้อมเหตุผล
4. ในเกม ทีมงานพิมพ์ `/rongroi` เปิดเคสให้ผู้เล่น ผู้เล่นจะเห็นรหัสไปวางใน Connect

## FiveM แบบใช้ Rongroi Relay

1. รัน relay: [nakara-oss `relay/`](https://github.com/aeterna/nakara-oss/tree/dev/relay) มี Dockerfile ไฟล์ Compose ที่มี Caddy
   ทำ HTTPS ให้ และคำสั่ง `node main.js keygen <server-id>` ที่พิมพ์บรรทัดสำหรับขั้นที่ 2 ให้
2. ใน `server.cfg` ใช้แทน `rongroi_public_origin`:
   ```
   ensure nakara_rongroi
   add_ace group.admin nakara_rongroi.staff allow
   set rongroi_relay_url "https://relay.example.org"
   set rongroi_relay_id "my-server"
   set rongroi_relay_key "<จาก keygen>"
   ```
3. `rongroi doctor` ตรวจว่า relay ตอบ และ key เป็นของ `my-server`

resource ใดก็ได้บนเซิร์ฟเวอร์อ่าน convar ที่ตั้งด้วย `set` ได้ ให้รันเฉพาะ resource ที่ไว้ใจ

## ไม่ใช่ FiveM

รัน relay แล้วบนเซิร์ฟเวอร์ของคุณใช้
[`@aeterna_game/rongroi-envelope`](https://github.com/aeterna/nakara-oss/tree/dev/sdk/rongroi-envelope) เปิดรายงานที่ดึงมาจาก relay
โปรโตคอลอยู่ใน ADR 0097 §3 test vectors อยู่ใน SDK แสดงสิ่งที่ได้รับให้ทีมงานเป็นหลักฐาน อย่าแปลงเป็นผ่านหรือไม่ผ่าน

## อัปเดต Kit

แทนโฟลเดอร์ได้ **แต่เก็บ `cache/rongroi-reports/` ไว้** บน FXServer Enhanced รายงานที่บันทึกไว้อยู่ในนั้น ถ้าแทนไปแล้ว
Kit จะบอกตอนเริ่ม (`stored reports missing: expected <n>, found <m>`) และทีมงานจะเห็นแถบแจ้ง รายงานกู้คืนจากเซิร์ฟเวอร์ไม่ได้

## รุ่นที่ใช้ด้วยกันได้

| Server Kit `nakara_rongroi` | Rongroi Connect | Relay | รหัส | Envelope |
|---|---|---|---|---|
| 0.1.x | 0.1.x ขึ้นไป | — | `rr1.` | v1 |
| 0.2.x แบบตรง | 0.1.x ขึ้นไป | — | `rr1.` | v1 |
| 0.2.x แบบ relay | **0.2.x ขึ้นไป** | 0.1.x | `rr2.` | v2 |

Connect ตรวจรายงานเองทุกครั้งก่อนส่ง ตัวสแกน (`rongroi-scan`) ที่มากับ Connect ออกตามรุ่นของ Connect
