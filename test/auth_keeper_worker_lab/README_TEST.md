# M WOIF AUTH KEEPER WORKER LAB V1

LAB นี้ใช้ Web/DB จริง แต่แยกโค้ด Runtime และ Session Cache ออกจาก Worker หลัก

## สิ่งที่ไม่ถูกแก้

- `start_worker.bat`
- `main.py`
- `mwoif/`
- `mwoif_worker/`
- `state/sender-session-cache/`
- Web/PHP
- Database schema/data

LAB ใช้ cache แยกที่:

`state/auth-keeper-worker-lab/sender-session-cache/`

และใช้ process lock เดียวกับ Worker หลัก ดังนั้นถ้า `start_worker.bat` ยังทำงานอยู่ LAB จะไม่ยอมเริ่ม

## วิธีทดสอบรอบแรก

1. ปิด `start_worker.bat` ตัวหลักด้วย `Ctrl+C` และรอให้ Worker ปิดสมบูรณ์
2. แตก ZIP นี้ทับ root ของ `vps_next`
3. รัน `RUN_AUTH_KEEPER_WORKER_LAB_V1.bat`
4. ต้องเห็น `LAB AUTH KEEPER READY` และ `WORKER SERVICE READY`
5. เข้า Web Admin > `pump-accounts`
6. กด `ทดสอบ Login หลายไอดี`
7. เลือก `ไอดีใช้งานทั้งหมด` และ `100 ไอดี`
8. รอให้ Web ทดสอบครบ 100
9. Console LAB ต้องทยอยเห็น `LAB AUTH CAPTURE PASS sga_id=... source=ADMIN_BULK_LOGIN`
10. ดู `LAB AUTH KEEPER STATUS cached=100 ...`
11. ปล่อยไว้จนเลย 27-30 นาที
12. ก่อน token หมด LAB จะเห็น `LAB AUTH REFRESH PASS ... newRemaining≈1800 fullLogin=false`
13. เมื่อผ่าน 30 นาทีแล้ว สั่งปั้มใจ 100 จาก Web จริง
14. ตรวจ log งาน Heart

ผลที่ต้องการ:

- `P10.1 SESSION CACHE HYDRATE hits=100/100`
- `LAB HEART AUTH SOURCE cache=100 fresh=0 freshFailed=0 total=100`
- ไม่มี Full Login ของ HEART_SENDER ชุดนั้น

Receiver ของลูกค้าอาจยังมี `P1 DEVPLAY login start` ได้ตามปกติ เพราะการทดสอบนี้วัด Sender 100 ไอดี

## ถ้า Refresh ล้ม

LAB ไม่มี Full Login fallback ใน Auth Keeper:

- Network/Timeout/5xx/429 -> `RETRY`
- Refresh credential ใช้ไม่ได้แบบ non-retryable -> `LOGIN_REQUIRED`
- จะไม่ Login Email/Password อัตโนมัติเพื่อกลบผลการทดสอบ

## กลับไป Worker หลัก

1. `Ctrl+C` ปิด LAB
2. รอ `P9 WORKER DRAIN COMPLETE`
3. รัน `start_worker.bat` ตัวเดิม

Worker หลักจะกลับไปใช้ `state/sender-session-cache/` ของเดิม และไม่ได้ใช้ LAB cache
