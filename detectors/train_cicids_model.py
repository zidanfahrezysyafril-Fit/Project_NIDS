"""
Official Training Script for CICIDS2017 Flow Classification using pure XGBoost.
Trained on 14 Optimal Features (12 Vital Features + PSH Flag Count + Init_Win_bytes_forward).
Outputs: cicids_flow_model.pkl
"""
import os
import glob
import time
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, f1_score
from xgboost import XGBClassifier

# The 14 Optimal Network Flow Features (12 Vital + 2 Key TCP Features)
CICIDS_14_FEATURES = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Flow Packets/s',
    'Flow Bytes/s',
    'Packet Length Mean',
    'Packet Length Std',
    'Flow IAT Mean',
    'Flow IAT Std',
    'SYN Flag Count',
    'ACK Flag Count',
    'Average Packet Size',
    'PSH Flag Count',
    'Init_Win_bytes_forward'
]

# Target 15 standard classes from CICIDS2017
CLASSES_15 = [
    'BENIGN', 'Bot', 'DDoS', 'DoS GoldenEye', 'DoS Hulk', 'DoS Slowhttptest',
    'DoS slowloris', 'FTP-Patator', 'Heartbleed', 'Infiltration', 'PortScan',
    'SSH-Patator', 'Web Attack - Brute Force', 'Web Attack - Sql Injection',
    'Web Attack - XSS'
]

def clean_label(val):
    s = str(val).strip()
    u = s.upper()
    if 'BENIGN' in u: return 'BENIGN'
    if 'DDOS' in u: return 'DDoS'
    if 'PORTSCAN' in u: return 'PortScan'
    if 'BOT' in u: return 'Bot'
    if 'INFILTRATION' in u: return 'Infiltration'
    if 'HEARTBLEED' in u: return 'Heartbleed'
    if 'FTP' in u: return 'FTP-Patator'
    if 'SSH' in u: return 'SSH-Patator'
    if 'GOLDENEYE' in u: return 'DoS GoldenEye'
    if 'HULK' in u: return 'DoS Hulk'
    if 'SLOWHTTP' in u: return 'DoS Slowhttptest'
    if 'SLOWLORIS' in u: return 'DoS slowloris'
    if 'SQL' in u: return 'Web Attack - Sql Injection'
    if 'XSS' in u: return 'Web Attack - XSS'
    if 'BRUTE' in u: return 'Web Attack - Brute Force'
    return s

def load_and_preprocess_dataset(data_dir):
    print("=" * 70)
    print("1. MEMBACA & MEMPROSES 14 FITUR OPTIMAL DARI MACHINELEARNINGCVE")
    print("=" * 70)
    
    files = glob.glob(os.path.join(data_dir, "*.csv"))
    if not files:
        raise FileNotFoundError(f"Tidak ada file CSV di {data_dir}")
        
    print(f"Ditemukan {len(files)} file CSV.")
    
    # Stratified target limits to balance memory & class representation
    MAX_PER_CLASS = {
        'BENIGN': 60000,
        'DoS Hulk': 20000,
        'PortScan': 20000,
        'DDoS': 20000,
    }
    DEFAULT_MAX = 15000 # Keep minority attacks up to 15,000 (most have less, keeping 100%)
    
    class_dfs = {c: [] for c in CLASSES_15}
    class_counts = {c: 0 for c in CLASSES_15}
    
    t0 = time.time()
    
    for f in files:
        fname = os.path.basename(f)
        print(f" -> Membaca: {fname}...", end="", flush=True)
        
        # Read header to find label column and map feature columns
        header_df = pd.read_csv(f, nrows=1, encoding='cp1252')
        col_map = {c: c.strip() for c in header_df.columns}
        inv_map = {c.strip(): c for c in header_df.columns}
        
        label_col_raw = [c for c in header_df.columns if 'label' in c.lower()][0]
        
        # Required columns from this CSV
        use_cols = [inv_map[feat] for feat in CICIDS_14_FEATURES if feat in inv_map]
        use_cols.append(label_col_raw)
        
        # Read data chunk by chunk or full
        df_chunk = pd.read_csv(f, usecols=use_cols, encoding='cp1252', low_memory=False)
        df_chunk = df_chunk.rename(columns=col_map)
        
        # Clean label column
        df_chunk['Label'] = df_chunk['Label'].apply(clean_label)
        
        # Process and bucket by class
        for c, sub_df in df_chunk.groupby('Label'):
            if c not in class_dfs:
                continue
            max_limit = MAX_PER_CLASS.get(c, DEFAULT_MAX)
            current_count = class_counts[c]
            needed = max_limit - current_count
            if needed > 0:
                sample_part = sub_df.head(needed)
                class_dfs[c].append(sample_part)
                class_counts[c] += len(sample_part)
                
        print(f" Selesai ({len(df_chunk):,} baris)")
        
    print(f"\nPengambilan sampel selesai dalam {time.time() - t0:.2f} detik.")
    print("\nKomposisi Sampel per Kelas (14 Fitur):")
    all_dfs = []
    for c in CLASSES_15:
        count = class_counts[c]
        print(f"  - {c:<28}: {count:,} sampel")
        if class_dfs[c]:
            all_dfs.extend(class_dfs[c])
            
    final_df = pd.concat(all_dfs, ignore_index=True)
    print(f"\nTotal Dataset Gabungan: {len(final_df):,} baris x {len(CICIDS_14_FEATURES)} fitur")
    
    # Clean numeric features (inf, nan)
    print("\nMembersihkan nilai inf/NaN dan standardisasi tipe data...")
    X_df = final_df[CICIDS_14_FEATURES].copy()
    X_df = X_df.replace([np.inf, -np.inf], np.nan).fillna(0)
    X = X_df.astype(np.float32).values
    
    y = final_df['Label'].values
    
    return X, y

def train_and_evaluate(X, y, output_paths):
    print("\n" + "=" * 70)
    print("2. TRAINING MODEL XGBOOST 14 FITUR CICIDS2017")
    print("=" * 70)
    
    # Encode target labels
    le = LabelEncoder()
    le.fit(CLASSES_15)
    y_encoded = le.transform(y)
    
    # Train test split (80% train, 20% test stratified)
    print("Membagi data: 80% Train, 20% Test (Stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.20, random_state=42, stratify=y_encoded
    )
    
    # Feature Scaling
    print("Menghitung StandardScaler...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train XGBoost
    print("\nMemulai pelatihan XGBClassifier (100 estimators, max_depth=6)...")
    t0 = time.time()
    
    clf = XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric='mlogloss',
        n_jobs=-1,
        tree_method='hist' # Fast histogram method
    )
    
    clf.fit(X_train_scaled, y_train)
    train_time = time.time() - t0
    print(f"Pelatihan XGBoost selesai dalam {train_time:.2f} detik!")
    
    # Evaluate
    print("\n" + "=" * 70)
    print("3. EVALUASI MODEL PADA TEST SET")
    print("=" * 70)
    
    y_pred = clf.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    f1_macro = f1_score(y_test, y_pred, average='macro')
    f1_weighted = f1_score(y_test, y_pred, average='weighted')
    
    print(f"Akurasi Global : {acc * 100:.2f}%")
    print(f"F1-Score Macro : {f1_macro * 100:.2f}%")
    print(f"F1-Score Weight: {f1_weighted * 100:.2f}%\n")
    
    present_labels = sorted(list(set(y_test) | set(y_pred)))
    target_names = [le.classes_[i] for i in present_labels]
    
    print("Classification Report:")
    print(classification_report(y_test, y_pred, labels=present_labels, target_names=target_names, digits=4))
    
    # Top Features
    importances = clf.feature_importances_
    top_indices = np.argsort(importances)[::-1]
    print("\nPERINGKAT FEATURE IMPORTANCE (14 FITUR):")
    for rank, idx in enumerate(top_indices, 1):
        print(f"  {rank:>2}. {CICIDS_14_FEATURES[idx]:<28}: {importances[idx]:.4f}")
        
    # Save bundle
    print("\n" + "=" * 70)
    print("4. MENYIMPAN MODEL SERIALISASI")
    print("=" * 70)
    
    bundle = {
        'xgb_model': clf,
        'scaler': scaler,
        'label_encoder': le,
        'classes': list(le.classes_),
        'features': CICIDS_14_FEATURES,
        'algorithm': 'XGBoost',
        'metrics': {
            'accuracy': acc,
            'f1_macro': f1_macro,
            'f1_weighted': f1_weighted
        }
    }
    
    for path in output_paths:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(bundle, path, compress=3)
        size_mb = os.path.getsize(path) / (1024 * 1024)
        print(f"Model berhasil disimpan: {path} ({size_mb:.2f} MB)")

if __name__ == "__main__":
    data_directory = r"d:\Semester 5\AI KSI\MachineLearningCVE"
    base_proj = r"d:\Semester 5\AI KSI\Project NIDS"
    
    save_targets = [
        os.path.join(base_proj, "data", "cicids_flow_model.pkl"),
        os.path.join(base_proj, "cicids_flow_model.pkl")
    ]
    
    X, y = load_and_preprocess_dataset(data_directory)
    train_and_evaluate(X, y, save_targets)
