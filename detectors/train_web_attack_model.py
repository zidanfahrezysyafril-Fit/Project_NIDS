# ============================================================
# train_web_attack_model.py
# Melatih model XGBoost untuk deteksi SQLi & XSS
# Dataset: web_attack_combined.csv (35,687 baris)
# Output : data/web_attack_model.pkl
# ============================================================

import os
import sys
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score, classification_report,
    f1_score, confusion_matrix
)
from xgboost import XGBClassifier

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # naik ke root project
DATA_DIR = os.path.join(BASE_DIR, 'data')
DATASET_PATH = os.path.join(DATA_DIR, 'web_attack_combined.csv')
MODEL_OUTPUT  = os.path.join(DATA_DIR, 'web_attack_model.pkl')

print("=" * 60)
print("  NIDS - Web Attack Model Training")
print("  Kelompok 10 - AI for Security")
print("  Dataset : web_attack_combined.csv")
print("  Algoritma: XGBoost + TF-IDF (Character N-Gram)")
print("=" * 60)
print()

# ─────────────────────────────────────────────────────────────
# 1. LOAD DATASET
# ─────────────────────────────────────────────────────────────
print("[1/5] Memuat dataset...")
df = pd.read_csv(DATASET_PATH, encoding='utf-8')
df = df.dropna(subset=['payload', 'attack_type'])
df['payload'] = df['payload'].astype(str)

print("  Total baris    :", len(df))
print("  Distribusi kelas:")
for cls, cnt in df['attack_type'].value_counts().items():
    pct = cnt / len(df) * 100
    print(f"    {cls:<20} : {cnt:>6,} baris ({pct:.1f}%)")
print()

# ─────────────────────────────────────────────────────────────
# 2. FEATURE EXTRACTION — TF-IDF Character N-Gram (1-4 gram)
#    Teknik terbaik untuk mendeteksi pola karakter seperti
#    ' OR 1=1 (SQLi) atau <script> (XSS) tanpa memerlukan
#    tokenisasi berbasis kata (word tokenization)
# ─────────────────────────────────────────────────────────────
print("[2/5] Ekstraksi fitur TF-IDF Character N-Gram (1,4)...")
vectorizer = TfidfVectorizer(
    analyzer='char_wb',    # Character-level n-gram (termasuk boundary whitespace)
    ngram_range=(1, 4),    # Unigram hingga 4-gram karakter
    max_features=20000,    # Top 20.000 fitur paling informatif
    sublinear_tf=True,     # Gunakan log(tf) + 1 untuk mengurangi dominasi payload panjang
    min_df=2,              # Abaikan n-gram yang muncul kurang dari 2 kali
    strip_accents='unicode',
    lowercase=True
)

X = vectorizer.fit_transform(df['payload'])
print("  Matriks fitur  :", X.shape[0], "sampel x", X.shape[1], "fitur TF-IDF")

# Label encoding
le = LabelEncoder()
y = le.fit_transform(df['attack_type'])
print("  Kelas terlatih :", list(le.classes_))
print()

# ─────────────────────────────────────────────────────────────
# 3. SPLIT TRAIN/TEST (80/20 Stratified)
# ─────────────────────────────────────────────────────────────
print("[3/5] Pembagian data latih/uji (80% / 20% stratified)...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print("  Data latih :", X_train.shape[0], "sampel")
print("  Data uji   :", X_test.shape[0], "sampel")
print()

# ─────────────────────────────────────────────────────────────
# 4. TRAINING MODEL XGBoost
# ─────────────────────────────────────────────────────────────
print("[4/5] Melatih model XGBoost...")
n_classes = len(le.classes_)
model = XGBClassifier(
    n_estimators=300,
    max_depth=8,
    learning_rate=0.1,
    subsample=0.85,
    colsample_bytree=0.85,
    min_child_weight=3,
    gamma=0.1,
    reg_alpha=0.1,
    reg_lambda=1.0,
    objective='multi:softprob',
    num_class=n_classes,
    eval_metric='mlogloss',
    use_label_encoder=False,
    random_state=42,
    n_jobs=-1,
    verbosity=0
)

model.fit(
    X_train, y_train,
    eval_set=[(X_test, y_test)],
    verbose=50
)
print()

# ─────────────────────────────────────────────────────────────
# 5. EVALUASI
# ─────────────────────────────────────────────────────────────
print("[5/5] Evaluasi model pada data uji...")
y_pred = model.predict(X_test)

acc   = accuracy_score(y_test, y_pred)
f1_w  = f1_score(y_test, y_pred, average='weighted')
f1_m  = f1_score(y_test, y_pred, average='macro')

print()
print("=" * 60)
print("  HASIL EVALUASI MODEL WEB ATTACK DETECTOR")
print("=" * 60)
print("  Akurasi          :", round(acc * 100, 2), "%")
print("  Weighted F1-Score:", round(f1_w * 100, 2), "%")
print("  Macro F1-Score   :", round(f1_m * 100, 2), "%")
print()
print("  Laporan Per Kelas:")
print(classification_report(y_test, y_pred, target_names=le.classes_))

# ─────────────────────────────────────────────────────────────
# 6. SIMPAN MODEL
# ─────────────────────────────────────────────────────────────
bundle = {
    'model':         model,
    'vectorizer':    vectorizer,
    'label_encoder': le,
    'classes':       list(le.classes_),
    'algorithm':     'XGBoost + TF-IDF CharNGram (1-4)',
    'ngram_range':   (1, 4),
    'max_features':  20000,
    'metrics': {
        'accuracy':   acc,
        'f1_weighted': f1_w,
        'f1_macro':   f1_m,
    },
    'dataset': {
        'source':  'das-lab/deep-xss (XSS) + OWASP SQLi Payloads + Normal HTTP',
        'total':   len(df),
        'classes': df['attack_type'].value_counts().to_dict(),
    }
}
joblib.dump(bundle, MODEL_OUTPUT, compress=3)

size_mb = os.path.getsize(MODEL_OUTPUT) / (1024 * 1024)
print("=" * 60)
print("  Model disimpan ke:", MODEL_OUTPUT)
print("  Ukuran file      :", round(size_mb, 2), "MB")
print("=" * 60)
print()
print("[SELESAI] Model web_attack_model.pkl siap digunakan!")
print("  Hubungkan ke: detectors/web_attack_detector.py")
