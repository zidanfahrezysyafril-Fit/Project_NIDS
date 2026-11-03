import time
from collections import defaultdict, deque
from datetime import datetime

class DDoSDetector:
    """
    Sliding-window rate limiter and HTTP Flood / DDoS detector based on access log streams.
    Tracks request timestamps per IP and calculates request frequency over a configurable window.
    """
    def __init__(self):
        # Dictionary of website_id -> { ip -> deque([timestamps]) }
        self._history = defaultdict(lambda: defaultdict(deque))
        # Rate tracking per website for live RPS
        self._global_req_times = defaultdict(deque)

    def record_request(self, website_id, ip_address, timestamp=None):
        """
        Records an incoming request for a website and checks for DDoS thresholds.
        Returns:
            is_ddos (bool): True if IP exceeded rate threshold
            current_rate (int): requests in current window for this IP
            rps (float): current estimated requests-per-second for this website
        """
        now = timestamp.timestamp() if timestamp else time.time()
        ip_queue = self._history[website_id][ip_address]
        ip_queue.append(now)
        
        # Track global website requests for RPS
        web_queue = self._global_req_times[website_id]
        web_queue.append(now)
        
        # Clean older than 60 seconds from global queue
        while web_queue and now - web_queue[0] > 60:
            web_queue.popleft()
            
        current_rps = len(web_queue) / 60.0 if web_queue else 0.0
        return current_rps

    def evaluate_ip_rate(self, website_id, ip_address, threshold_req=100, window_sec=10, now_ts=None):
        """
        Evaluates if the IP has sent more than threshold_req in the last window_sec.
        """
        now = now_ts or time.time()
        ip_queue = self._history[website_id][ip_address]
        
        # Purge timestamps outside the sliding window
        cutoff = now - window_sec
        while ip_queue and ip_queue[0] < cutoff:
            ip_queue.popleft()
            
        rate_count = len(ip_queue)
        is_attack = rate_count >= threshold_req
        
        confidence = min(99.9, 85.0 + (rate_count / max(1, threshold_req) * 10.0)) if is_attack else 0.0
        return is_attack, rate_count, round(confidence, 1)

    def get_top_talkers(self, website_id, window_sec=60):
        """Returns top IPs and their request frequency in the last window_sec."""
        now = time.time()
        cutoff = now - window_sec
        talkers = []
        
        for ip, queue in self._history[website_id].items():
            # Clean old entries
            while queue and queue[0] < cutoff:
                queue.popleft()
            count = len(queue)
            if count > 0:
                talkers.append({'ip': ip, 'requests': count, 'rps': round(count / float(window_sec), 2)})
                
        # Sort descending by request count
        talkers.sort(key=lambda x: x['requests'], reverse=True)
        return talkers[:15]

    def reset_website_history(self, website_id):
        """Clears memory for a specific website."""
        if website_id in self._history:
            del self._history[website_id]
        if website_id in self._global_req_times:
            del self._global_req_times[website_id]

# Singleton detector instance for the app
ddos_detector = DDoSDetector()
