# ⛓️ Wallet Scanner V3.1

نسخه ۳.۱ — باگ‌فیکس مستقل: RPC batched، keccak اصلاح‌شده، لوله موازی producer/deriver/worker.

اسکنر آفلاین ولت‌های BIP39 (عبارت ۱۲ کلمه‌ای) با بررسی هم‌زمان موجودی
**ETH + USDT + USDC** روی شبکه اصلی اتریوم از طریق چند اندپوینت RPC.

## قابلیت‌ها (میراث از V2 + تثبیت در V3)
- ➕ موجودی USDT و USDC (ERC-20 `balanceOf` روی قراردادهای اصلی mainnet)
- ⚡ ۴ worker موازی بررسی موجودی + صف pending
- 🔁 Failover روی ۵ اندپوینت RPC + backoff ۳۰ ثانیه برای نودهای مرده
- 🎚 آستانه جداگانه: حداقل ETH و حداقل USDT/USDC
- 📄 ثبت خودکار ولت‌های دارای موجودی در `funded_wallets.txt` (با ۱۲ کلمه)
- 🖥 پنل وب: نمایش ETH+USDT+USDC هر hit، دکمه ⬇ دانلود فایل، شمارنده «در انتظار بررسی»، هشدار خطای اتصال به سرور
- ▶/⏹/↺ شروع / توقف / پاک‌سازی + زمان تست (ثانیه)

## راه‌اندازی
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt   # coincurve + pycryptodome
python app.py                     # → http://localhost:8000
```

## ساختار
```
app.py        # سرور HTTP (stdlib only)
core/         # bip39, hd, wallet_model, balance (RPC failover), scanner (workers)
web/          # index.html, app.js, style.css
```

## تفاوت با V2
این مخزن یک پروژه **مستقل** است تا نسخه ۳ روی GitHub به‌صورت جداگانه منتشر شود؛
کد پایه یکسان است و توسعه آینده V3.1 فقط در این مخزن انجام می‌شود.
