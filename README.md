# Datacenter Inventory

Flask + MariaDB ile basit datacenter inventory ve rack yerlesim uygulamasi.

## Moduller

- Datacenter: country, building, name, codename, FQDN, birden fazla rack ve IP range
- Servers
- Firewalls
- Switchs
- Other Parts
- Analytics dashboard
- Rack animasyon/gorunum sayfasi: U bazinda cihaz yerlesimi, cihaza tiklayinca settings ekrani

## Kurulum

1. Sanal ortam olusturun ve paketleri yukleyin:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

2. MariaDB'yi baslatin:

```powershell
docker compose up -d
```

3. `.env.example` dosyasini `.env` olarak kopyalayin.

```powershell
Copy-Item .env.example .env
```

4. Tablolari olusturun:

```powershell
flask --app app init-db
```

5. Uygulamayi calistirin:

```powershell
flask --app app run
```

Uygulama varsayilan olarak `http://127.0.0.1:5000` adresinde acilir.

## Notlar

- Rackler datacenter formunda satir satir girilir ve varsayilan `48U` olarak kaydedilir.
- Rack size secenekleri `1U, 2U, 3U, 4U, 6U, 8U`.
- Ayni rack icinde U cakismasi uygulama tarafinda engellenir.
- `DATABASE_URL` tanimli degilse uygulama hizli deneme icin `sqlite:///inventory.db` kullanir.
