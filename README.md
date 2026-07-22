# SubScope - High-Performance Asset Recon Suite 🚀

An advanced, high-performance asset discovery, subdomain harvesting, port scanning, subdomain takeover verification, and WHOIS/RDAP query suite.

![SubScope](sc.png)

## License
Licensed under the [MIT License](LICENSE).

---

## English Version

### Key Features
1. **Deep Subdomain Harvesting**:
   - Collects subdomains passively from `crt.sh`, `AlienVault OTX`, `RapidDNS`, and `HackerTarget`.
   - Wildcard detection to filter out false positives.
   - Permutation scanning to discover hidden assets.
2. **Subdomain Takeover Checker**:
   - Analyzes CNAME and body signatures for AWS S3, GitHub Pages, Heroku, Shopify, Zendesk, Squarespace, etc.
3. **Async Port Scanner**:
   - High-concurrency port scanning powered by `asyncio` with rate limiting.
   - Deconstructs TLS/SSL certificates and extracts service banners.
4. **WHOIS & RDAP Query**:
   - Queries registrar records via RDAP JSON or WHOIS fallback.
5. **Diff Mode**:
   - Compare two scan result JSON outputs to view added, removed, or changed assets.
6. **Premium Dashboard Reports**:
   - Exports results to interactive HTML dashboards, CSV, and JSON.

### Installation
Verify dependencies and install requirements:
```bash
pip install -r requirements.txt
```

### Usage Examples
- **Perform Full Reconnaissance**:
  ```bash
  python subscope.py run -d target.com -o output_result --permutations
  ```
- **Harvest Subdomains only**:
  ```bash
  python subscope.py enum -d target.com
  ```
- **Scan Ports only**:
  ```bash
  python subscope.py ports -d target.com --ports 22,80,443,8080 --rate 150
  ```
- **WHOIS Query**:
  ```bash
  python subscope.py whois -d target.com
  ```
- **Compare Scans**:
  ```bash
  python subscope.py diff old_scan.json new_scan.json
  ```

---

## النسخة العربية (Arabic Version)

### الميزات الرئيسية
1. **جمع نطاقات فرعية عميق**:
   - الاستخراج من مصادر متعددة غير نشطة: `crt.sh`, `AlienVault OTX`, `RapidDNS`, `HackerTarget`.
   - فحص الـ Wildcards الذكي وتخمين الـ Permutations.
2. **فحص ثغرات Takeover**:
   - التحقق التلقائي لخدمات الطرف الثالث الشهيرة.
3. **فحص منافذ متزامن فائق السرعة**:
   - يعتمد على `asyncio` بالكامل مع سحب شهادات الـ TLS والـ Banners.
4. **سجلات WHOIS / RDAP**:
   - يدعم استعلامات RDAP الهيكلية المتطورة.
5. **أداة مقارنة النتائج (Diff Mode)**:
   - تتبع الاختلافات بين عمليتي فحص مختلفتين بسهولة.
6. **تقارير احترافية**:
   - إنتاج لوحة تحكم HTML متميزة إلى جانب تقارير CSV و JSON.

### التثبيت
للتحقق من المتطلبات وتثبيتها:
```bash
pip install -r requirements.txt
```

### أمثلة التشغيل
- **تشغيل فحص شامل**:
  ```bash
  python subscope.py run -d target.com -o output_result --permutations
  ```
- **جمع النطاقات الفرعية**:
  ```bash
  python subscope.py enum -d target.com
  ```

---

*Developer: goudawolfdev | D33P-X (Gouda Nasralla)*
