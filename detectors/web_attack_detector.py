import re
import urllib.parse
import os
import joblib
import numpy as np

class WebAttackDetector:
    """
    Two-tier web attack detector:
    Tier 1: High-speed Regex Signature Pre-filter (Catches known SQLi & XSS variants)
    Tier 2: Character N-Gram & TF-IDF statistical scoring model powered by XGBoost to suppress false positives
    """
    
    SQLI_PATTERNS = [
        (r"(?i)(\%27)|(\')|(\-\-)|(\%23)|(#)", "SQL Meta-character (Quotes / Comments)"),
        (r"(?i)\b(union\s+select|union\s+all\s+select)\b", "UNION SELECT Injection"),
        (r"(?i)\b(select\s+.+\s+from\s+.+)\b", "SELECT FROM Query Exposure"),
        (r"(?i)\b(drop\s+table|drop\s+database|truncate\s+table)\b", "Destructive DROP/TRUNCATE Statement"),
        (r"(?i)\b(exec\s*\(|execute\s*\(|xp_cmdshell)\b", "Command Execution Shell Injection"),
        (r"(?i)(\'|\")\s*or\s*(\'|\")?[0-9a-z]+(\'|\")?\s*=\s*(\'|\")?[0-9a-z]+", "' OR '1'='1 Boolean Tautology"),
        (r"(?i)\b(sleep\s*\([0-9]+\)|benchmark\s*\([0-9]+)\b", "Blind Time-Based Delay (SLEEP/BENCHMARK)"),
        (r"(?i)\b(information_schema|sysdatabases|sysobjects)\b", "Information Schema Metatable Probing"),
        (r"(?i)\b(or\s+1\s*=\s*1|and\s+1\s*=\s*1|or\s+true|and\s+true)\b", "Tautology 1=1 Injection")
    ]
    
    XSS_PATTERNS = [
        (r"(?i)<script[\s\S]*?>[\s\S]*?<\/script>", "Standard <script> Tag Execution"),
        (r"(?i)<script[^>]*>", "Unclosed <script> Tag"),
        (r"(?i)javascript\s*:", "JavaScript URI Scheme (javascript:...)"),
        (r"(?i)(onerror\s*=|onload\s*=|onclick\s*=|onmouseover\s*=|onfocus\s*=)", "DOM Event Handler Injection"),
        (r"(?i)<img\s+[^>]*src\s*=\s*[\"']?[^>]*onerror\s*=", "<img onerror=...> Payload"),
        (r"(?i)<svg[\s\S]*?onload\s*=", "<svg onload=...> Vector"),
        (r"(?i)(alert\s*\(|confirm\s*\(|prompt\s*\(|document\.cookie|document\.location)", "Dangerous DOM API Call (alert/cookie)"),
        (r"(?i)<iframe[^>]*src\s*=", "Malicious <iframe> Insertion"),
        (r"(?i)<body[^>]*onload\s*=", "<body> Event Injection")
    ]
    
    def __init__(self, model_path=None):
        self.model = None
        self.vectorizer = None
        self.classes = None
        self.label_encoder = None
        self.algorithm = "XGBoost"

        if model_path and os.path.exists(model_path):
            try:
                bundle = joblib.load(model_path)
                self.model = bundle.get('model')
                self.vectorizer = bundle.get('vectorizer')
                self.classes = bundle.get('classes')
                self.label_encoder = bundle.get('label_encoder')
                self.algorithm = bundle.get('algorithm', 'XGBoost')
            except Exception as e:
                print(f"Warning: Could not load trained ML model: {e}")

    def inspect_request(self, uri, method="GET", post_body=""):
        """
        Inspects an HTTP request URI and optional body for malicious payloads.
        Returns:
            is_attack (bool)
            attack_type (str): 'SQL Injection', 'Cross-Site Scripting (XSS)', or 'BENIGN'
            pattern_detected (str): Name of matched signature
            confidence (float): 0.0 - 100.0%
            payload_sample (str): The suspicious fragment
        """
        if not uri:
            return False, 'BENIGN', '', 0.0, ''
            
        # URL-decode to catch encoded attacks (e.g. %27, %3Cscript%3E)
        decoded_uri = urllib.parse.unquote_plus(uri)
        # Double decode check to catch nested obfuscations (%2527)
        double_decoded = urllib.parse.unquote_plus(decoded_uri)
        
        target_text = f"{decoded_uri} {double_decoded} {post_body}"
        
        # 1. Check for SQL Injection Signatures
        for pattern, desc in self.SQLI_PATTERNS:
            match = re.search(pattern, target_text)
            if match:
                payload = match.group(0)[:120]
                confidence = self._compute_confidence(target_text, 'SQL Injection', match)
                # Suppress false positives on normal text containing dashes or harmless words
                if confidence >= 70.0:
                    return True, 'SQL Injection', desc, confidence, payload
                    
        # 2. Check for XSS Signatures
        for pattern, desc in self.XSS_PATTERNS:
            match = re.search(pattern, target_text)
            if match:
                payload = match.group(0)[:120]
                confidence = self._compute_confidence(target_text, 'Cross-Site Scripting (XSS)', match)
                if confidence >= 70.0:
                    return True, 'Cross-Site Scripting (XSS)', desc, confidence, payload

        # 3. Fallback: ML Vectorizer (XGBoost) if available
        if self.model and self.vectorizer:
            try:
                X_vec = self.vectorizer.transform([target_text])
                raw_pred = self.model.predict(X_vec)[0]

                # Decode prediction jika numerik
                if self.label_encoder is not None and isinstance(raw_pred, (int, np.integer)):
                    pred = self.label_encoder.inverse_transform([raw_pred])[0]
                elif self.classes is not None and isinstance(raw_pred, (int, np.integer)) and raw_pred < len(self.classes):
                    pred = self.classes[raw_pred]
                else:
                    pred = str(raw_pred)

                if pred != 'BENIGN':
                    probs = self.model.predict_proba(X_vec)[0]
                    conf = float(np.max(probs) * 100)
                    return True, pred, f"{self.algorithm} Statistical Text Classifier", conf, target_text[:100]
            except Exception:
                pass
                
        return False, 'BENIGN', '', 0.0, ''

    def _compute_confidence(self, text, attack_type, match):
        """
        Dynamically adjusts confidence based on context length, repetition, and payload clarity.
        """
        matched_str = match.group(0)
        base_confidence = 88.0
        
        if attack_type == 'SQL Injection':
            if any(kw in matched_str.lower() for kw in ['union select', 'drop table', 'xp_cmdshell', 'or 1=1']):
                base_confidence = 98.5
            elif 'sleep(' in matched_str.lower() or 'benchmark(' in matched_str.lower():
                base_confidence = 96.0
            elif matched_str in ["'", "--", "#"]:
                # Isolated quotes have lower certainty without SQL keywords
                if not re.search(r"(?i)\b(select|insert|update|delete|where|and|or)\b", text):
                    base_confidence = 65.0 # Likely suppressed by threshold 70.0
                else:
                    base_confidence = 85.0
                    
        elif attack_type == 'Cross-Site Scripting (XSS)':
            if '<script>' in matched_str.lower() or 'alert(' in matched_str.lower() or 'onerror=' in matched_str.lower():
                base_confidence = 99.0
            elif 'javascript:' in matched_str.lower():
                base_confidence = 95.0
            else:
                base_confidence = 85.0
                
        return min(99.9, base_confidence)

# Singleton instance — load model dari root project atau data/
def _load_web_detector():
    try:
        from config import Config
        path = Config.WEB_ATTACK_MODEL_PATH
    except Exception:
        import os
        base = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        path = os.path.join(base, 'web_attack_model.pkl')
        if not os.path.exists(path):
            path = os.path.join(base, 'data', 'web_attack_model.pkl')
    return WebAttackDetector(model_path=path)

web_detector = _load_web_detector()
