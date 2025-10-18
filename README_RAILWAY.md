# 🚀 Deployment Guide for Railway

## Deploy Steps
1. Buka [https://railway.app/dashboard](https://railway.app/dashboard)
2. Klik **New Project → Deploy from ZIP**
3. Upload file ZIP ini (`python_web_railway.zip`)
4. Railway akan otomatis install dependencies dan menjalankan app.

## Environment Variables
Tambahkan variable berikut di tab **Variables**:
```
ACCESS_TOKEN=token123
SECRET_CONTENT=rahasia_besar
ADMIN_TOKEN=admin123
```
Jika menggunakan PostgreSQL bawaan Railway, `DATABASE_URL` akan otomatis tersedia.

## Local Run
```
pip install -r requirements.txt
python combined_app.py
```
