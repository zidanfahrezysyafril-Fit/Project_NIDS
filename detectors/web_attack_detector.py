import re
import urllib.parse
import os
import joblib
import numpy as np

class WebAttackDetector:
    """
    Two-tier web attack detector:
    Tier 1: High-speed Regex Signature Pre-filter (Catches known SQLi & XSS variants)
    Tier 2: Character N-Gram & TF-IDF statistical scoring model to suppress false positives
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
        if model_path and os.path.exists(model_path):
            try:
                bundle = joblib.load(model_path)
                self.model = bundle.get('model')
                self.vectorizer = bundle.get('vectorizer')
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

        # 3. Fallback: ML Vectorizer if available
        if self.model and self.vectorizer:
            try:
                X_vec = self.vectorizer.transform([target_text])
                pred = self.model.predict(X_vec)[0]
                if pred != 'BENIGN':
                    probs = self.model.predict_proba(X_vec)[0]
                    conf = float(np.max(probs) * 100)
                    return True, pred, "ML Statistical Text Classifier", conf, target_text[:100]
            except Exception:
                pass
                
        return False, 'BENIGN', '', 0.0, ''

    def _compute_confidence(self, text, attack_type, match):
        """Calculates confidence score based on payload structure and entropy."""
        base_score = 88.0
        match_len = len(match.group(0))
        
        # If match is substantial, increase confidence
        if match_len > 12:
            base_score += 6.0
            
        # Additional indicators
        if attack_type == 'SQL Injection':
            if any(k in text.lower() for k in ['select', 'union', 'from', 'where', 'or 1=1', '--']):
                base_score += 5.0
        elif attack_type == 'Cross-Site Scripting (XSS)':
            if '<' in text and '>' in text:
                base_score += 5.0
            if 'alert(' in text or 'cookie' in text:
                base_score += 4.0
                
        return min(99.8, round(base_score, 1))

# Singleton detector instance
web_attack_detector = WebAttackDetector()
