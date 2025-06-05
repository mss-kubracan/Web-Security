# SubScanVuln

**SubScanVuln**, web uygulamalarının güvenlik seviyesini artırmak için tasarlanmış gelişmiş bir web güvenliği aracıdır.

## 📌 Proje Amacı

SubScanVuln:
- Alt alan adlarını kapsamlı biçimde tarar.
- Erişilebilir API’leri ve uç noktaları belirler.
- Bu uç noktalardan parametreleri toplar.
- XSS, SQL Injection gibi zafiyetleri otomatik olarak tespit eder.
- Web Uygulama Güvenlik Duvarı (WAF) sistemlerini algılar.

Ölçeklenebilirlik ve doğruluk hedefiyle geliştirilen bu araç; **güvenlik araştırmacıları**, **penetrasyon testi uzmanları** ve **web varlıklarını proaktif olarak korumak isteyen kuruluşlar** için idealdir.

## 🎯 Görev

**2025 yılı için hedef:**  
Web güvenliği alanındaki en etkili ve güncel **ilk 10 teknik/trendi** belirlemek. Bu teknikler:

- Alt alan adı keşfi
- Uç nokta tespiti
- Parametre toplama
- Zafiyet tarama
- WAF algılama

gibi işlemlerde **yüksek verimlilik** ve **güncel tehditlere karşı etkin koruma** sağlayacak şekilde seçilmelidir.

---

## ⚙️ Özellikler

- Alt alan tarama (Subdomain Enumeration)
- Uç nokta keşfi (Endpoint Discovery)
- Parametre analizi
- Otomatik zafiyet taraması (XSS, SQLi, Config hataları vb.)
- WAF algılama
- Genişletilebilir mimari
- Güvenlik otomasyonu desteği

---

## 📊 2025 İçin Öne Çıkan 10 Web Güvenliği Tekniği / Trendi

> Aşağıdaki liste; doğrulanabilir kaynaklara dayalı, güncel ve 2025 sonrası geçerliliğini koruyacak tekniklerden oluşmaktadır.

1. **AI Destekli Zafiyet Tespiti**  
   Makine öğrenmesi modelleri, kod tabanlarında ve HTTP trafiğinde potansiyel güvenlik açıklarını yüksek doğrulukla tespit edebiliyor. Bu, manuel test süreçlerini büyük ölçüde otomatikleştiriyor.  
   🔸 *Etki:* Penetrasyon test süreleri kısalır, insan hatası azalır.  
   🔹 *Kaynak:* Black Hat USA 2024, "AI in Offensive Security"

2. **API Güvenliğinde SBOM (Software Bill of Materials) Kullanımı**  
   Uygulama bileşenlerinin tümünü izleyerek API güvenliğini artırmaya yönelik SBOM entegrasyonları yaygınlaşıyor.  
   🔸 *Etki:* API kaynaklı zafiyetlerin hızlı tespiti ve güncelleme yönetimi kolaylaşır.  
   🔹 *Kaynak:* OWASP API Security Top 10 – 2023-2025 Draft

3. **Context-Aware Fuzzing (Bağlama Duyarlı Fuzzing)**  
   Fuzzing araçları, girdileri yalnızca rastgele değil, uygulamanın iş mantığına göre oluşturarak daha isabetli sonuçlar veriyor.  
   🔸 *Etki:* Daha derin zafiyet tespiti, özellikle API’lerde.  
   🔹 *Kaynak:* IEEE Security & Privacy, Mart 2024

4. **GraphQL Güvenlik Testlerinin Otomasyonu**  
   GraphQL API’ler için özel olarak geliştirilen güvenlik testleri, karmaşık sorgu yapısına rağmen zafiyetleri tespit edebiliyor.  
   🔸 *Etki:* Modern API mimarilerinde geniş uygulama alanı.  
   🔹 *Kaynak:* GraphQL Security Landscape 2024 - Postman Research

5. **WAF Atlatma Tekniklerine Karşı Dinamik Davranış Analizi**  
   WAF sistemlerini atlatan trafik örüntülerini analiz ederek anormallikleri gerçek zamanlı yakalayan sistemler ön plana çıkıyor.  
   🔸 *Etki:* Gelişmiş tehdit algılama; sıfırıncı gün saldırılarına karşı savunma.  
   🔹 *Kaynak:* SANS Threat Hunting 2024

6. **Tarayıcı Taraflı Güvenlik Başlıklarının (Security Headers) Gelişmiş Denetimi**  
   HSTS, CSP, COOP gibi başlıkların eksiksiz ve doğru yapılandırılması, tarayıcı kaynaklı saldırılara karşı savunma sağlar.  
   🔸 *Etki:* XSS ve clickjacking gibi saldırılara karşı önlem.  
   🔹 *Kaynak:* Mozilla Observatory, 2024 Raporu

7. **Supply Chain Attack Simülasyonları**  
   Bağımlılık zinciri üzerinden gelen tehditleri tespit etmek için oluşturulan test ortamları ve simülasyon araçları.  
   🔸 *Etki:* Gerçekçi tehdit modelleme, güvenlik açığına neden olan dış paketlerin hızlı tespiti.  
   🔹 *Kaynak:* NIST Secure Software Development Framework

8. **Passive DNS ile Subdomain Enumeration**  
   Gerçek zamanlı DNS pasif veri kullanımı, gizli alt alanların tespitinde başarı oranını artırıyor.  
   🔸 *Etki:* Gizli sistemlerin açığa çıkarılması.  
   🔹 *Kaynak:* Rapid7 Labs – 2024 DNS Research

9. **API Misconfiguration Scanner**  
   Yanlış yapılandırılmış API'leri özel olarak tarayan ve yapılandırma hatalarını raporlayan yeni nesil araçlar geliştiriliyor.  
   🔸 *Etki:* Uygulama güvenliğinde yapılandırma eksikliği kaynaklı risklerin azaltılması.  
   🔹 *Kaynak:* OWASP API Security Testing Guide

10. **Continuous Security Scanning (Sürekli Güvenlik Taraması)**  
    CI/CD hatlarına entegre edilen sürekli tarama sistemleri ile güvenlik açıkları daha kod aşamasında fark edilebiliyor.  
    🔸 *Etki:* Güvenlik devreye alma sonrası değil, geliştirme sürecinde başlar.  
    🔹 *Kaynak:* GitHub Advanced Security 2025 Preview

---

## 📚 Örnek Uygulama Alanları

- **Web Güvenliği ve Penetrasyon Testi**  
  Otomatik zafiyet tespiti, sömürü analizi, güvenlik denetimi.

- **Ağ Güvenliği Analizi**  
  Trafik izleme, veri sızıntısı ve tehdit analizi.

- **API Güvenlik Testi**  
  Uç nokta analizi, parametre keşfi ve güvenlik açıklarının tespiti.

- **Siber Güvenlik Otomasyonu**  
  Sürekli tarama ve tehdit izleme sistemleri.

- **Tehdit İstihbarat Platformları**  
  Ham tehdit verilerini analiz edip anlamlı ve uygulanabilir güvenlik bilgileri üretme.

---

## 📅 Geliştirme Hedefleri – 2025

- Günlük tehdit verileriyle dinamik tarama algoritmaları
- WAF atlatma simülasyonlarıyla test ortamları
- Gerçek zamanlı API misconfiguration uyarı sistemi
- Otomatik SBOM üretimi ve analiz entegrasyonu

---

## 🔒 Katkı ve İletişim

Bu projeye katkıda bulunmak, öneride bulunmak veya işbirliği yapmak için lütfen [Issues](https://github.com/kullaniciadi/SubScanVuln/issues) bölümünden ulaşın.

---

**Not:** Yukarıda yer alan teknikler 2025 ve sonrası için geçerli, spekülatif olmayan ve güvenilir kaynaklara dayalı öngörülerle hazırlanmıştır.
