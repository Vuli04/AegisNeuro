import subprocess
import time
import logging
from collections import defaultdict
from threading import Thread, Lock
import configparser
import os
import re
import sys
from urllib.parse import urlparse, parse_qs

# --- Dependency Imports ---
try:
    from scapy.all import sniff, IP, TCP
except ImportError:
    print("Scapy is not installed. Please run: pip install scapy flask flask-cors")
    exit()
try:
    from flask import Flask, jsonify, request
    from flask_cors import CORS
except ImportError:
    print("Flask is not installed. Please run: pip install flask flask-cors")
    exit()
try:
    import joblib
    import pandas as pd
    import numpy as np
except ImportError:
    print("Scikit-learn or pandas is not installed. Please run: pip install scikit-learn pandas")
    exit()
try:
    import tldextract
except ImportError:
    print("tldextract is not installed. Please run: pip install tldextract")
    exit()
try:
    import openai
except ImportError:
    # --- IMPROVEMENT: Add sqlite3 to the list of standard libraries ---
    print("OpenAI library is not installed. Please run: pip install openai")
    exit()

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        # --- IMPROVEMENT: Use the script's own directory, not the current working directory ---
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)


# --- Script Analysis Logic (from script_analyzer_gui.py) ---
SUSPICIOUS_PATTERNS = {
    # File Operations
    'File Deletion': re.compile(r'os\.remove|shutil\.rmtree', re.IGNORECASE),
    'File Overwriting': re.compile(r'open\(.*[\'"]w[\'"].*\)', re.IGNORECASE),
    # Network Operations
    'Socket Connection': re.compile(r'socket\.socket|socket\.connect', re.IGNORECASE),
    'HTTP Requests': re.compile(r'requests\.(get|post)|urllib\.request', re.IGNORECASE),
    # Execution and Obfuscation
    'Remote Code Execution': re.compile(r'eval\(|exec\(|subprocess\.run|os\.system', re.IGNORECASE),
    'Base64 Encoding/Decoding': re.compile(r'base64\.b64encode|base64\.b64decode', re.IGNORECASE),
    # Windows Specific
    'Registry Modification': re.compile(r'winreg\.|_winreg', re.IGNORECASE),
    'PowerShell Execution': re.compile(r'powershell\.exe', re.IGNORECASE),
}

def analyze_script_code(script_code):
    """
    Performs a static analysis of a script string for suspicious patterns.
    Returns a report string.
    """
    report = []
    try:
        lines = script_code.splitlines()
        report.append(f"--- Static Analysis Report ---\n")
        found_suspicious = False
        for i, line in enumerate(lines):
            for category, pattern in SUSPICIOUS_PATTERNS.items():
                if pattern.search(line):
                    report.append(f"[!] Suspicious Pattern Found: {category}")
                    report.append(f"    Line {i+1}: {line.strip()}")
                    report.append("-" * 20)
                    found_suspicious = True
        if not found_suspicious:
            report.append("\nNo suspicious patterns found based on the current rules.")
    except Exception as e:
        report.append(f"\nError analyzing script: {e}")
    return "\n".join(report)

# --- Phishing Feature Extraction Logic (from phishing/feature_extraction.py) ---
def extract_phishing_url_features(url):
    """Extracts features from a URL for the phishing detection model."""
    features = {}
    if not re.match(r'^(http|https)://', url):
        url = 'http://' + url
    try:
        parsed_url = urlparse(url)
        ext = tldextract.extract(url)
        domain, subdomain = ext.domain, ext.subdomain
        hostname = parsed_url.hostname or ''
        path, query = parsed_url.path, parsed_url.query
    except Exception:
        return {fn: 0 for fn in ['NumDots', 'SubdomainLevel', 'PathLevel', 'UrlLength', 'NumDash', 'NumDashInHostname', 'AtSymbol', 'TildeSymbol', 'NumUnderscore', 'NumPercent', 'NumQueryComponents', 'NumAmpersand', 'NumHash', 'NumNumericChars', 'NoHttps', 'IpAddress', 'DomainInSubdomains', 'DomainInPaths', 'HttpsInHostname', 'HostnameLength', 'PathLength', 'QueryLength', 'DoubleSlashInPath', 'NumSensitiveWords', 'BrandImpersonation']}

    features['UrlLength'] = len(url)
    features['NumDots'] = url.count('.')
    features['NumDash'] = url.count('-')
    features['NumUnderscore'] = url.count('_')
    features['NumPercent'] = url.count('%')
    features['NumAmpersand'] = url.count('&')
    features['NumHash'] = url.count('#')
    features['NumNumericChars'] = sum(c.isdigit() for c in url)
    features['AtSymbol'] = 1 if '@' in url else 0
    features['TildeSymbol'] = 1 if '~' in url else 0
    features['NoHttps'] = 1 if parsed_url.scheme != 'https' else 0
    features['HostnameLength'] = len(hostname)
    features['NumDashInHostname'] = hostname.count('-')
    features['HttpsInHostname'] = 1 if 'https' in hostname else 0
    features['IpAddress'] = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0
    features['SubdomainLevel'] = len(subdomain.split('.')) if subdomain else 0
    features['DomainInSubdomains'] = 1 if domain and subdomain and domain in subdomain else 0
    features['PathLength'] = len(path)
    features['PathLevel'] = path.count('/')
    features['DoubleSlashInPath'] = 1 if '//' in path else 0
    features['DomainInPaths'] = 1 if domain and path and domain in path else 0
    features['QueryLength'] = len(query)
    features['NumQueryComponents'] = len(parse_qs(query))
    
    targeted_brands = ['amazon', 'paypal', 'ebay', 'apple', 'microsoft', 'netflix', 'google', 'facebook', 'instagram', 'chase', 'wellsfargo', 'bankofamerica']
    legitimate_domains = [b + '.com' for b in targeted_brands]
    features['BrandImpersonation'] = 1 if ext.registered_domain not in legitimate_domains and any(b in (subdomain + '.' + domain).lower() for b in targeted_brands) else 0
    sensitive_words = ['login', 'password', 'bank', 'account', 'security', 'signin', 'update', 'confirm', 'verify']
    features['NumSensitiveWords'] = sum(word in url.lower() for word in sensitive_words)
    return features

# --- Malicious Script Feature Extraction Logic (from train_script_analyzer.py) ---
def extract_script_features(script_code):
    """Extracts features for the malicious script detection model."""
    if not isinstance(script_code, str):
        script_code = ""

    features = {}
    # Lexical features
    suspicious_keywords = ['eval', 'unescape', 'document.write', 'String.fromCharCode', 'ActiveXObject']
    for keyword in suspicious_keywords:
        features[f'count_{keyword}'] = len(re.findall(r'\b' + re.escape(keyword) + r'\b', script_code, re.IGNORECASE))
    
    # String features
    if not script_code:
        features['entropy'] = 0
        features['script_length'] = 0
    else:
        prob = [float(script_code.count(c)) / len(script_code) for c in dict.fromkeys(list(script_code))]
        features['entropy'] = -sum([p * np.log2(p) for p in prob])
        features['script_length'] = len(script_code)
        
    return features

# --- Log Anomaly Feature Extraction Logic ---
def parse_log_entry(log_entry, user_map=None, common_ips=None):
    """Parses a single log entry string into a dictionary of features."""
    # Example format: "Jan 01 09:00:00 auth.log: admin login SUCCESS from 192.168.1.10"
    # --- IMPROVEMENT: Made the regex much more flexible to handle different auth log formats ---
    # This pattern now captures various success/failure keywords and user/IP formats.
    pattern = re.compile(
        r"(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})?.*?"  # Optional timestamp
        r"(?P<status>accepted|failed|failure|success|invalid).*" # Status keywords
        r"(?:for|user)\s+(?P<user>[\w\.-]+)\s+from\s+" # User
        r"(?P<ip>[\d\.]+)", re.IGNORECASE # IP Address
    )
    match = pattern.search(log_entry)
    
    timestamp_str = None
    if not match:
        return None # Pattern failed
    else:
        data = match.groupdict()
        timestamp_str, user, status, source_ip = data.get('timestamp'), data.get('user'), data.get('status'), data.get('ip')

    # If no timestamp was parsed, use the current time. Otherwise, parse the string.
    timestamp = pd.to_datetime('now', utc=True) if not timestamp_str else pd.to_datetime(f"2023 {timestamp_str}", format='%Y %b %d %H:%M:%S')

    # Use the provided maps, or default to safe values if they are not provided
    user_map = user_map or {}
    common_ips = common_ips or set()

    # --- IMPROVEMENT: Handle unknown users more gracefully ---
    # Instead of just using -1, we can hash the username to get a consistent ID.
    # This helps the model differentiate between different unknown users.
    user_id = user_map.get(user, hash(user) % 10000) # Use a hashed value for unknown users

    # --- IMPROVEMENT: Create the 'is_success' feature the model was trained on ---
    # The model expects a binary indicator for login success.
    is_success = 1 if status.lower() in ['accepted', 'success'] else 0

    is_common = 1 if source_ip in common_ips else 0

    return {
        'hour': timestamp.hour,
        'day_of_week': timestamp.dayofweek, # Monday=0, Sunday=6
        'is_weekend': 1 if timestamp.dayofweek >= 5 else 0,
        'is_success': is_success,
        'user_id': user_id,
        'is_common': is_common,
        'ip_as_int': int(''.join([f"{int(i):03d}" for i in source_ip.split('.')]))
    }

# --- DGA Feature Extraction Logic ---
def calculate_entropy(s):
    """Calculates the Shannon entropy of a string."""
    if not s: return 0
    p, lns = pd.Series(list(s)).value_counts(normalize=True), float(len(set(s)))
    return -sum(p * np.log2(p))

def extract_dga_features(domain):
    """Extracts features from a domain name for DGA detection."""
    if not isinstance(domain, str): domain = ''
    length = len(domain)
    digits = sum(c.isdigit() for c in domain)
    vowels = sum(c in 'aeiou' for c in domain.lower())
    return {
        'length': length,
        'digit_ratio': digits / length if length > 0 else 0,
        'entropy': calculate_entropy(domain),
        'vowel_ratio': vowels / length if length > 0 else 0
    }

# --- 1. Firewall Manager ---
# This class encapsulates all firewall interaction logic, making it clean and reusable.
import sqlite3

class FirewallManager:
    def __init__(self, db_conn, whitelist=None):
        self.db_conn = db_conn
        self.lock = Lock()  # Ensures thread-safe operations on the blocked_ips set
        self.whitelist = set(whitelist) if whitelist else set()
        if self.whitelist:
            logging.info(f"FirewallManager initialized with whitelist: {self.whitelist}")
        # On startup, ensure firewall rules match the persistent state
        self._sync_firewall_rules()

    def block_ip(self, ip_address, duration, rule_prefix="AegisIPS"):
        """Adds a firewall rule to block an IP address. Returns True on success."""
        if ip_address in self.whitelist:
            logging.warning(f"Detected threat from {ip_address}, but it is on the whitelist. No action taken.")
            return False
            
        with self.lock:
            cursor = self.db_conn.cursor()
            cursor.execute("SELECT expiry_timestamp FROM blocked_ips WHERE ip_address = ?", (ip_address,))
            result = cursor.fetchone()
            if result and time.time() < result[0]:
                logging.debug(f"IP {ip_address} is already in the blocked_ips table. Skipping.")
                return False
            
            rule_name = f"{rule_prefix}_{ip_address.replace('.', '_')}"
            logging.critical(f"ATTEMPTING TO BLOCK IP: {ip_address} with rule '{rule_name}'")
            try:
                # First, add the OS firewall rule
                command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
                subprocess.run(command, check=True, capture_output=True, text=True, shell=True)
                
                # Then, persist it to the database
                expiry_timestamp = time.time() + duration
                cursor.execute("REPLACE INTO blocked_ips (ip_address, rule_name, expiry_timestamp) VALUES (?, ?, ?)",
                               (ip_address, rule_name, expiry_timestamp))
                self.db_conn.commit()

                logging.info(f"Successfully blocked {ip_address} for {duration} seconds. Rule: '{rule_name}'.")
                return True
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to block IP {ip_address}. This script must be run as an Administrator.")
                logging.error(f"Stderr: {e.stderr.strip()}")
                return False
            except FileNotFoundError:
                logging.error("'netsh' command not found. This script is designed for Windows.")
                return False
            except sqlite3.Error as e:
                logging.error(f"Database error while blocking IP {ip_address}: {e}")
                # Attempt to roll back the firewall rule if DB write fails
                self._remove_firewall_rule(rule_name)
                return False

    def update_whitelist(self, whitelist_list):
        """Safely updates the internal whitelist from a list of IPs."""
        with self.lock:
            self.whitelist = set(whitelist_list)
            logging.info(f"Whitelist updated via API to: {self.whitelist}")

    def unblock_ip(self, ip_address):
        """Removes a firewall rule for a given IP address."""
        with self.lock:
            cursor = self.db_conn.cursor()
            cursor.execute("SELECT rule_name FROM blocked_ips WHERE ip_address = ?", (ip_address,))
            result = cursor.fetchone()
            if not result:
                return # IP not in our database
            
            rule_name = result[0]
            logging.info(f"Attempting to unblock {ip_address} and remove rule '{rule_name}'.")
            self._remove_firewall_rule(rule_name)
            
            # Finally, remove from database
            try:
                cursor.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip_address,))
                self.db_conn.commit()
            except sqlite3.Error as e:
                logging.error(f"Database error while unblocking IP {ip_address}: {e}")

    def _remove_firewall_rule(self, rule_name):
        """Internal helper to remove a rule from the OS firewall."""
        try:
            command = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            subprocess.run(command, check=True, capture_output=True, text=True, shell=True)
        except subprocess.CalledProcessError:
            logging.warning(f"Could not remove OS firewall rule '{rule_name}'. It may have been removed manually or permissions are denied.")

    def _sync_firewall_rules(self):
        """Ensures that any rules in the DB are active in the firewall on startup."""
        logging.info("Syncing firewall state with database...")
        with self.lock:
            cursor = self.db_conn.cursor()
            cursor.execute("SELECT ip_address, rule_name FROM blocked_ips")
            all_blocked = cursor.fetchall()
            for ip, rule_name in all_blocked:
                logging.info(f"Re-applying block for {ip} from database.")
                # This is a simplified re-application. It just re-adds the rule.
                # A more complex system might check if the rule exists first.
                try:
                    command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
                    subprocess.run(command, check=True, capture_output=True, text=True, shell=True)
                except subprocess.CalledProcessError:
                    logging.warning(f"Could not re-apply rule '{rule_name}' for IP {ip}. It might already exist.")

    def policy_enforcer(self):
        """Periodically checks for and removes expired IP blocks."""
        logging.info("Policy enforcer thread started.")
        while True:
            try:
                with self.lock:
                    cursor = self.db_conn.cursor()
                    cursor.execute("SELECT ip_address FROM blocked_ips WHERE expiry_timestamp < ?", (time.time(),))
                    expired_ips = [row[0] for row in cursor.fetchall()]
                for ip in expired_ips:
                    self.unblock_ip(ip)
            except sqlite3.Error as e:
                logging.error(f"Database error in policy enforcer: {e}")
            time.sleep(30) # Check for expired blocks every 30 seconds

# --- 2. Detection Engines ---
# This is a base class. All future detection methods (rule-based, ML-based, etc.) will inherit from it.
class DetectionEngine:
    def __init__(self, firewall_manager, alert_logger):
        self.firewall = firewall_manager
        self.alert_logger = alert_logger

    def process_packet(self, packet):
        """Each engine must implement its own logic to process a packet."""
        raise NotImplementedError

class PortScanDetector(DetectionEngine):
    """Detects port scans by tracking connection attempts from IPs."""
    def __init__(self, firewall_manager, alert_logger, time_window=60, port_threshold=20):
        super().__init__(firewall_manager, alert_logger)
        self.TIME_WINDOW = time_window
        self.PORT_SCAN_THRESHOLD = port_threshold
        self.ip_tracker = defaultdict(lambda: {'ports': set(), 'first_seen': time.time()})
        logging.info(f"PortScanDetector initialized: Threshold={port_threshold} ports in {time_window}s.")

    def process_packet(self, packet):
        # This engine only cares about TCP packets with an IP layer
        if not (IP in packet and TCP in packet):
            return

        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        # --- Traffic Filtering: Ignore private IP ranges to reduce noise ---
        # This prevents the IPS from blocking devices on the local network.
        if src_ip.startswith("192.168.") or src_ip.startswith("10.") or src_ip.startswith("172.16."):
             return

        current_time = time.time()
        
        # Reset the tracking window if it has expired for this IP
        if current_time - self.ip_tracker[src_ip]['first_seen'] > self.TIME_WINDOW:
            self.ip_tracker[src_ip]['ports'] = {dst_port}
            self.ip_tracker[src_ip]['first_seen'] = current_time
        else:
            self.ip_tracker[src_ip]['ports'].add(dst_port)

        # Check if the number of unique ports exceeds our threshold
        port_count = len(self.ip_tracker[src_ip]['ports'])
        if port_count > self.PORT_SCAN_THRESHOLD:
            details = f"{port_count} ports in {int(current_time - self.ip_tracker[src_ip]['first_seen'])}s"
            logging.warning(f"Port scan detected from {src_ip} ({details})")
            self.alert_logger(source_ip=src_ip, alert_type='PortScan', details=details)
            self.firewall.block_ip(src_ip, duration=self.firewall.block_duration, rule_prefix="AegisIPS_PortScan")
            # Once blocked, remove from tracker to save memory
            del self.ip_tracker[src_ip]

class MLAnomalyDetector(DetectionEngine):
    """
    A simulated detection engine that loads the trained anomaly detection model.
    In a real-world scenario, this engine would receive fully formed 'flows'
    from a separate, high-performance feature extraction component.
    """
    def __init__(self, firewall_manager, alert_logger, model_path, scaler_path, features_path):
        super().__init__(firewall_manager, alert_logger)
        self.model = None
        self.scaler = None
        self.feature_names = None
        try:
            self.model = joblib.load(resource_path(model_path))
            self.scaler = joblib.load(resource_path(scaler_path))
            self.feature_names = joblib.load(resource_path(features_path))
            logging.info(f"MLAnomalyDetector initialized successfully with model from '{model_path}'.")
        except FileNotFoundError as e:
            logging.error(f"ML model artifact not found: {e}. The MLAnomalyDetector will be disabled.")
        except Exception as e:
            logging.error(f"Error loading ML model: {e}. The MLAnomalyDetector will be disabled.")

    def process_packet(self, packet):
        """
        This method is a placeholder. The ML model works on statistical flows,
        not individual packets. A real implementation would have a separate
        process to build these flows and call 'process_flow'.
        """
        pass # Intentionally left blank

    def process_flow(self, flow_data, source_ip):
        """Simulates processing a completed network flow."""
        if not all([self.model, self.scaler, self.feature_names]):
            return # Do nothing if the model failed to load

        try:
            flow_df = pd.DataFrame([flow_data])
            flow_df = flow_df[self.feature_names] # Enforce column order
            flow_scaled = self.scaler.transform(flow_df)
            prediction = self.model.predict(flow_scaled)
            if prediction[0] == -1: # -1 indicates an anomaly
                details = "Network flow characteristics matched anomalous pattern."
                logging.warning(f"ML model detected an anomaly from IP {source_ip}. Details: {details}")
                self.alert_logger(source_ip=source_ip, alert_type='MLAnomaly', details=details)
                self.firewall.block_ip(source_ip, duration=self.firewall.block_duration, rule_prefix="AegisIPS_ML")
        except Exception as e:
            logging.error(f"Error during ML prediction for flow from {source_ip}: {e}")

# --- 3. Main IPS Service ---
class AegisIPS:
    def __init__(self):
        self.setup_logging()
        logging.info("Initializing Aegis IPS Service...")
        
        # Read configuration from file
        config = configparser.ConfigParser()
        self.config = config # Store config instance
        # self.config.read(resource_path('config.ini')) # This is called in _initialize_components
        
        self.cve_pipeline = None
        self.phishing_model = None
        self.phishing_scaler = None
        self.phishing_features = None
        self.script_analyzer_model = None
        self.script_analyzer_features = None
        self.log_analyzer_model = None
        self.log_analyzer_features = None
        self.log_analyzer_metadata = None
        self.dga_model = None
        self.dga_features = None
        self.soar_pipeline = None
        self.openai_client = None
        self.db_conn = None

        self.firewall = None
        self.engines = []
        self._initialize_components()

    def _initialize_components(self):
        """Reads config and initializes/re-initializes all components."""
        # This must be at the top to ensure all other components can read their settings.
        self.config.read(resource_path('config.ini'))
        
        # --- IMPROVEMENT: Initialize database connection ---
        if not self.db_conn:
            self._initialize_database()

        logging.info("Initializing/Reloading components from configuration...")

        try: # CVE Classifier
            if self.config.getboolean('CVEClassifier', 'enabled', fallback=False):
                model_path = self.config.get('CVEClassifier', 'model_path', fallback='Models/cve_classifier_model.pkl')
                self.cve_pipeline = joblib.load(resource_path(model_path))
                logging.info("CVE Classifier pipeline loaded successfully.")
            else:
                self.cve_pipeline = None
        except Exception as e:
            logging.error(f"Could not load CVE Classifier pipeline: {e}. Tool will be disabled.")
            self.cve_pipeline = None

        try: # Phishing Detector
            if self.config.getboolean('PhishingDetector', 'enabled', fallback=False):
                model_path = resource_path(self.config.get('PhishingDetector', 'model_path', fallback='Models/phishing_model.pkl'))
                scaler_path = resource_path(self.config.get('PhishingDetector', 'scaler_path', fallback='Models/phishing_scaler.pkl'))
                features_path = resource_path(self.config.get('PhishingDetector', 'features_path', fallback='Models/phishing_feature_names.pkl'))
                
                self.phishing_model = joblib.load(model_path)
                self.phishing_scaler = joblib.load(scaler_path)
                self.phishing_features = joblib.load(features_path)
                logging.info("Phishing Detector model loaded successfully.")
            else:
                self.phishing_model = None
        except FileNotFoundError as e:
            logging.error(f"Could not load Phishing Detector component: {e}. Ensure all required files (model, scaler, features) exist. Tool will be disabled.")
            self.phishing_model = None
        except Exception as e:
            logging.error(f"Could not load Phishing Detector model: {e}. Tool will be disabled.")
            self.phishing_model = None

        try: # Script Analyzer ML
            if self.config.getboolean('ScriptAnalyzerML', 'enabled', fallback=False):
                self.script_analyzer_model = joblib.load(resource_path(self.config.get('ScriptAnalyzerML', 'model_path', fallback='Models/script_analyzer_model.pkl')))
                self.script_analyzer_features = joblib.load(resource_path(self.config.get('ScriptAnalyzerML', 'features_path', fallback='Models/script_feature_names.pkl')))
                logging.info("Script Analyzer ML model loaded successfully.")
            else:
                self.script_analyzer_model = None
        except Exception as e:
            logging.error(f"Could not load Script Analyzer ML model: {e}. Tool will be disabled.")
            self.script_analyzer_model = None

        try: # Log Anomaly Detector
            if self.config.getboolean('LogAnomalyDetector', 'enabled', fallback=False):
                self.log_analyzer_model = joblib.load(resource_path(self.config.get('LogAnomalyDetector', 'model_path', fallback='Models/log_analyzer_model.pkl')))
                self.log_analyzer_features = joblib.load(resource_path(self.config.get('LogAnomalyDetector', 'features_path', fallback='Models/log_analyzer_features.pkl')))
                self.log_analyzer_metadata = joblib.load(resource_path(self.config.get('LogAnomalyDetector', 'metadata_path', fallback='Models/log_analyzer_metadata.pkl'))) # Correctly use resource_path
                logging.info("Log Anomaly Detector model and metadata loaded successfully.")
            else:
                self.log_analyzer_model = None
        except Exception as e:
            logging.error(f"Could not load Log Anomaly Detector model: {e}. Tool will be disabled.")
            self.log_analyzer_model = None

        try: # DGA Detector
            if self.config.getboolean('DGADetector', 'enabled', fallback=False):
                self.dga_model = joblib.load(resource_path(self.config.get('DGADetector', 'model_path', fallback='Models/dga_detector_model.pkl')))
                self.dga_features = joblib.load(resource_path(self.config.get('DGADetector', 'features_path', fallback='Models/dga_detector_features.pkl')))
                logging.info("DGA Detector model loaded successfully.")
            else:
                self.dga_model = None
        except Exception as e:
            logging.error(f"Could not load DGA Detector model: {e}. Tool will be disabled.")
            self.dga_model = None

        try: # SOAR Playbook
            if self.config.getboolean('SOARPlaybook', 'enabled', fallback=False):
                self.soar_pipeline = joblib.load(resource_path(self.config.get('SOARPlaybook', 'model_path', fallback='Models/soar_playbook_model.pkl')))
                logging.info("SOAR Playbook model loaded successfully.")
            else:
                self.soar_pipeline = None
        except Exception as e:
            logging.error(f"Could not load SOAR Playbook model: {e}. Tool will be disabled.")
            self.soar_pipeline = None

        try: # Threat Intel Summarizer
            if self.config.getboolean('ThreatIntelSummarizer', 'enabled', fallback=False):
                # Best Practice: Prioritize environment variable, then fall back to config file.
                api_key = os.environ.get('OPENAI_API_KEY') or self.config.get('ThreatIntelSummarizer', 'openai_api_key', fallback='')
                
                if api_key and api_key != 'sk-YOUR_API_KEY_HERE':
                    self.openai_client = openai.OpenAI(api_key=api_key)
                    logging.info("OpenAI client initialized for Threat Intel Summarizer.")
                else:
                    self.openai_client = None
                    logging.warning("ThreatIntelSummarizer is enabled, but OpenAI API key is missing or is the default placeholder.")
                    logging.warning("Set the OPENAI_API_KEY environment variable or update config.ini.")
        except Exception as e:
            self.openai_client = None
            logging.error(f"Could not initialize OpenAI client: {e}. Tool will be disabled.")

        # Setup firewall if it doesn't exist
        if not self.firewall:
            block_duration = self.config.getint('Settings', 'block_duration', fallback=900)
            whitelist = [ip.strip() for ip in self.config.get('Settings', 'whitelist_ips', fallback='').split(',') if ip.strip()]
            self.firewall = FirewallManager(db_conn=self.db_conn, whitelist=whitelist)
            self.firewall.block_duration = block_duration
        
        # This is where you register all your detection engines!
        self.engines.clear() # Clear existing engines before reloading
        if self.config.getboolean('PortScanDetector', 'enabled', fallback=False):
            self.engines.append(
                PortScanDetector( 
                    self.firewall, 
                    alert_logger=self.log_alert,
                    time_window=self.config.getint('PortScanDetector', 'time_window', fallback=60),
                    port_threshold=self.config.getint('PortScanDetector', 'port_threshold', fallback=20)
                )
            )

        if self.config.getboolean('MLAnomalyDetector', 'enabled', fallback=False):
            self.engines.append(
                MLAnomalyDetector( 
                    self.firewall,
                    alert_logger=self.log_alert,
                    model_path=self.config.get('MLAnomalyDetector', 'model_path', fallback='Models/nids_model.pkl'),
                    scaler_path=self.config.get('MLAnomalyDetector', 'scaler_path', fallback='Models/nids_scaler.pkl'),
                    features_path=self.config.get('MLAnomalyDetector', 'features_path', fallback='Models/nids_feature_names.pkl')
                )
            )
        logging.info(f"{len(self.engines)} detection engine(s) loaded.")

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s',
            handlers=[
                logging.FileHandler(resource_path("aegis_ips.log")),
                logging.StreamHandler()
            ]
        )

    def _initialize_database(self):
        """Initializes the SQLite database and creates tables if they don't exist."""
        try:
            import sqlite3
            db_path = resource_path('aegis_hub.db')
            self.db_conn = sqlite3.connect(db_path, check_same_thread=False)
            logging.info(f"Successfully connected to SQLite database at {db_path}")
            cursor = self.db_conn.cursor()
            # Create a table for security alerts
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    source_ip TEXT,
                    alert_type TEXT,
                    details TEXT
                )''')
            # Create a table for persisting blocked IPs
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    ip_address TEXT PRIMARY KEY,
                    rule_name TEXT NOT NULL,
                    expiry_timestamp REAL NOT NULL
                )''')
            self.db_conn.commit()
        except Exception as e:
            logging.error(f"Failed to initialize SQLite database: {e}")
            self.db_conn = None

    def log_alert(self, source_ip, alert_type, details):
        """Logs a security alert to the database."""
        if not self.db_conn:
            return
        try:
            cursor = self.db_conn.cursor()
            cursor.execute("INSERT INTO alerts (source_ip, alert_type, details) VALUES (?, ?, ?)", (source_ip, alert_type, details))
            self.db_conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Database error while logging alert for {source_ip}: {e}")

    def packet_processor(self, packet):
        """This central function is called by Scapy for each captured packet."""
        for engine in self.engines:
            # We can process each engine in a separate thread for performance,
            # but for simplicity, we'll do it sequentially for now.
            try:
                engine.process_packet(packet)
            except Exception as e:
                logging.error(f"Error in engine {engine.__class__.__name__}: {e}")

    def start(self):
        """Starts the main packet sniffing loop."""
        logging.info("--- Aegis Live Network Monitor and IPS Started ---")
        logging.info("IMPORTANT: This script requires Administrator privileges to run.")
        logging.info("IMPORTANT: You must have Npcap installed for Scapy to work on Windows.")
        logging.info("Listening for traffic... (Press Ctrl+C to stop)")

        # 'filter="tcp"' tells Scapy to only capture TCP packets, improving performance.
        sniff(prn=self.packet_processor, store=0, filter="tcp")

    def _setup_api_routes(self):
        """Internal method to define all API endpoints for the GUI to call."""
        self.app = Flask(__name__)
        CORS(self.app)  # Allows your web-based GUI to call this API

        @self.app.route('/api/status', methods=['GET'])
        def get_status():
            # The FirewallManager now uses a database, so we query the DB for the count.
            blocked_count = 0
            if self.db_conn:
                try:
                    cursor = self.db_conn.cursor()
                    cursor.execute("SELECT COUNT(*) FROM blocked_ips")
                    result = cursor.fetchone()
                    blocked_count = result[0] if result else 0
                except Exception as e:
                    logging.error(f"API Error: Could not get blocked IP count from database: {e}")
            engine_names = [engine.__class__.__name__ for engine in self.engines]
            tool_statuses = {
                'CVE Classifier': 'Loaded' if self.cve_pipeline else 'Disabled/Failed',
                'Phishing Detector': 'Loaded' if self.phishing_model else 'Disabled/Failed',
                'Script Analyzer (ML)': 'Loaded' if self.script_analyzer_model else 'Disabled/Failed',
                'Log Anomaly Detector': 'Loaded' if self.log_analyzer_model else 'Disabled/Failed',
                'DGA Detector': 'Loaded' if self.dga_model else 'Disabled/Failed',
                'SOAR Playbook': 'Loaded' if self.soar_pipeline else 'Disabled/Failed',
                'Threat Intel Summarizer': 'Loaded' if self.openai_client else 'Disabled/Failed'
            }
            return jsonify({
                'status': 'Running',
                'active_engines': engine_names,
                'tool_statuses': tool_statuses,
                'currently_blocked': blocked_count
            })

        @self.app.route('/api/blocked_ips', methods=['GET'])
        def get_blocked_ips():
            with self.firewall.lock:
                cursor = self.db_conn.cursor()
                cursor.execute("SELECT ip_address, rule_name, expiry_timestamp FROM blocked_ips")
                blocked_list = [{
                    'ip': row[0], 'rule_name': row[1], 'expiry_time': row[2]
                } for row in cursor.fetchall()]
            return jsonify(blocked_list)

        @self.app.route('/api/unblock', methods=['POST'])
        def manual_unblock():
            data = request.get_json()
            ip_to_unblock = data.get('ip')
            if not ip_to_unblock:
                return jsonify({'error': 'IP address not provided'}), 400
            
            # The unblock_ip method is already thread-safe
            self.firewall.unblock_ip(ip_to_unblock)
            return jsonify({'message': f'Unblock command sent for {ip_to_unblock}.'})

        @self.app.route('/api/config', methods=['GET'])
        def get_config():
            """Reads the config.ini file and returns it as JSON."""
            try:
                config = configparser.ConfigParser()
                config.read(resource_path('config.ini'))
                config_dict = {section: dict(config.items(section)) for section in config.sections()}
                return jsonify(config_dict)
            except Exception as e:
                return jsonify({'error': f'Could not read config file: {e}'}), 500

        @self.app.route('/api/config', methods=['POST'])
        def set_config():
            """Receives new config data, writes it to file, and applies live settings."""
            new_config_data = request.get_json()
            if not new_config_data:
                return jsonify({'error': 'No config data provided'}), 400

            try:
                config = configparser.ConfigParser()
                config.read(resource_path('config.ini')) # Read existing to preserve structure

                for section, values in new_config_data.items():
                    if not config.has_section(section):
                        config.add_section(section)
                    for key, value in values.items():
                        config.set(section, key, str(value))

                with open(resource_path('config.ini'), 'w') as configfile:
                    config.write(configfile)

                # --- APPLY SETTINGS LIVE ---
                # Apply whitelist setting live
                if 'Settings' in new_config_data and 'whitelist_ips' in new_config_data['Settings']:
                    new_whitelist = [ip.strip() for ip in new_config_data['Settings']['whitelist_ips'].split(',') if ip.strip()]
                    self.firewall.update_whitelist(new_whitelist)
                
                # Reload all detection engines to apply their new settings
                self._initialize_components()
                
                logging.info("Configuration updated successfully via API.")
                return jsonify({'message': 'Configuration saved successfully.'})
            except Exception as e:
                logging.error(f"Failed to write config file: {e}")
                return jsonify({'error': f'Could not write config file: {e}'}), 500

        @self.app.route('/api/log', methods=['GET'])
        def get_log_events():
            """Returns the last 50 lines of the log file."""
            try:
                with open(resource_path('aegis_ips.log'), 'r') as f:
                    # Read the last N lines for efficiency
                    lines = f.readlines()
                    last_lines = lines[-50:] # Get the last 50 lines
                return jsonify({'log_events': last_lines})
            except FileNotFoundError:
                return jsonify({'log_events': ['Log file not found.']})
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/alerts', methods=['GET'])
        def get_alerts():
            """Returns the last 100 alerts from the database."""
            if not self.db_conn:
                return jsonify({'error': 'Database not connected'}), 503
            try:
                cursor = self.db_conn.cursor()
                cursor.execute("SELECT timestamp, source_ip, alert_type, details FROM alerts ORDER BY id DESC LIMIT 100")
                alerts = [{
                    'timestamp': row[0], 'source_ip': row[1], 'alert_type': row[2], 'details': row[3]
                } for row in cursor.fetchall()]
                return jsonify({'alerts': alerts})
            except sqlite3.Error as e:
                return jsonify({'error': f'Database error: {e}'}), 500

        @self.app.route('/api/ml_predict', methods=['POST'])
        def ml_predict_flow():
            """Receives flow data and source IP for ML-based anomaly detection."""
            data = request.get_json()
            flow_data = data.get('flow_data')
            source_ip = data.get('source_ip')

            if not flow_data or not source_ip:
                return jsonify({'error': 'Missing flow_data or source_ip'}), 400
            
            # Find the ML detector instance from the engines list
            ml_detector = None
            for engine in self.engines:
                if isinstance(engine, MLAnomalyDetector):
                    ml_detector = engine
                    break
            
            if not ml_detector:
                return jsonify({'error': 'MLAnomalyDetector is not enabled or loaded.'}), 503
            
            # Process the flow data using the ML detector
            ml_detector.process_flow(flow_data, source_ip) # This is thread-safe enough for this context
            
            # Return a success message (actual blocking happens internally)
            return jsonify({'message': f'ML prediction request received for {source_ip}. Check logs for outcome.'})

        @self.app.route('/api/analyze_script', methods=['POST'])
        def analyze_script_endpoint():
            """Receives script code and returns a static analysis report."""
            data = request.get_json()
            script_code = data.get('code')
            analysis_type = data.get('analysis_type', 'static')

            if not script_code or not isinstance(script_code, str):
                return jsonify({'error': 'No script code provided or invalid format.'}), 400
            
            report = ""
            if analysis_type == 'ml':
                if self.script_analyzer_model and self.script_analyzer_features:
                    try:
                        features = extract_script_features(script_code)
                        features_df = pd.DataFrame([features])[self.script_analyzer_features]
                        prediction = self.script_analyzer_model.predict(features_df)[0]
                        prediction_proba = self.script_analyzer_model.predict_proba(features_df)[0]
                        
                        label = "Malicious" if prediction == 1 else "Benign"
                        confidence = max(prediction_proba) * 100
                        
                        report = (
                            f"--- Machine Learning Analysis Report ---\n\n"
                            f"Prediction: {label}\n"
                            f"Confidence: {confidence:.2f}%\n\n"
                            f"This prediction is based on a trained model that analyzes lexical features of the script (e.g., keyword counts, entropy)."
                        )
                    except Exception as e:
                        report = f"Error during ML analysis: {e}"
                else:
                    report = "ML-based analysis is not available. The model may be disabled or failed to load."
            else: # Default to static
                report = analyze_script_code(script_code)
            
            return jsonify({'report': report})

        @self.app.route('/api/classify_cve', methods=['POST'])
        def classify_cve_endpoint():
            """Receives CVE description and returns a classification."""
            if not self.cve_pipeline:
                return jsonify({'error': 'CVE Classifier is not available. The model pipeline may be disabled or failed to load.'}), 503
            
            data = request.get_json()
            description = data.get('description')

            if not description or not isinstance(description, str):
                return jsonify({'error': 'No description provided or invalid format.'}), 400
            
            try:
                # The pipeline handles vectorization and prediction in one step
                prediction_proba = self.cve_pipeline.predict_proba([description])[0]
                
                # Get top 3 predictions with their probabilities
                top_indices = prediction_proba.argsort()[-3:][::-1]
                results = []
                for i in top_indices:
                    # Access classes_ from the final step of the pipeline
                    results.append({
                        'category': self.cve_pipeline.classes_[i],
                        'confidence': prediction_proba[i] * 100
                    })
                
                return jsonify({'results': results})
            except Exception as e:
                return jsonify({'error': f'Error during CVE classification: {e}'}), 500

        @self.app.route('/api/detect_phishing', methods=['POST'])
        def detect_phishing_endpoint():
            """Receives a URL and returns a phishing prediction."""
            if not self.phishing_model:
                return jsonify({'error': 'Phishing Detector is not available. The model may be disabled or failed to load.'}), 503

            data = request.get_json()
            url = data.get('url')

            if not url or not isinstance(url, str):
                return jsonify({'error': 'No URL provided or invalid format.'}), 400

            try:
                url_features = extract_phishing_url_features(url)
                features_df = pd.DataFrame([url_features])[self.phishing_features]
                features_scaled = self.phishing_scaler.transform(features_df)
                prediction_val = self.phishing_model.predict(features_scaled)[0]
                prediction_proba = self.phishing_model.predict_proba(features_scaled)[0]

                label = 'Phishing' if prediction_val == 1 else 'Legitimate'
                confidence = max(prediction_proba) * 100

                return jsonify({'label': label, 'confidence': confidence})
            except Exception as e:
                logging.error(f"Error during phishing prediction for URL '{url}': {e}")
                return jsonify({'error': f'Error during phishing prediction: {e}'}), 500

        @self.app.route('/api/analyze_log', methods=['POST'])
        def analyze_log_endpoint():
            """Receives a log entry and returns an anomaly prediction."""
            if not self.log_analyzer_model:
                return jsonify({'error': 'Log Anomaly Detector is not available. The model may be disabled or failed to load.'}), 503

            data = request.get_json()
            log_entry = data.get('log_entry')

            if not log_entry or not isinstance(log_entry, str):
                return jsonify({'error': 'No log entry provided or invalid format.'}), 400

            try:
                parsed_features = parse_log_entry(
                    log_entry, self.log_analyzer_metadata['user_map'], self.log_analyzer_metadata['common_ips']
                )
                if not parsed_features:
                    return jsonify({'error': 'Could not parse log entry. Ensure it follows the expected format.'}), 400

                # --- ADDED FOR DEBUGGING: Log the exact features being sent to the model ---
                logging.info(f"Log Analyzer Features for Prediction: {parsed_features}")

                # Create a DataFrame from the parsed features
                features_df = pd.DataFrame([parsed_features])
                # Ensure the DataFrame has all the columns the model expects, in the correct order.
                # This is the critical step to align prediction data with training data.
                features_for_prediction = features_df[self.log_analyzer_features]

                prediction = self.log_analyzer_model.predict(features_for_prediction)[0]
                label = 'Anomaly Detected' if prediction == -1 else 'Normal'
                return jsonify({'prediction': label})
            except Exception as e:
                logging.error(f"Error during log analysis for entry '{log_entry}': {e}", exc_info=True)
                return jsonify({'error': f'Error during log analysis: {e}'}), 500

        @self.app.route('/api/detect_dga', methods=['POST'])
        def detect_dga_endpoint():
            """Receives a domain name and returns a DGA prediction."""
            if not self.dga_model:
                return jsonify({'error': 'DGA Detector is not available. The model may be disabled or failed to load.'}), 503

            data = request.get_json()
            domain = data.get('domain')

            if not domain or not isinstance(domain, str):
                return jsonify({'error': 'No domain provided or invalid format.'}), 400

            try:
                features = extract_dga_features(domain)
                features_df = pd.DataFrame([features])[self.dga_features]
                prediction = self.dga_model.predict(features_df)[0]
                prediction_proba = self.dga_model.predict_proba(features_df)[0]

                label = 'DGA (Algorithmically Generated)' if prediction == 1 else 'Legitimate'
                confidence = max(prediction_proba) * 100

                return jsonify({'prediction': label, 'confidence': confidence})

            except Exception as e:
                logging.error(f"Error during DGA prediction for domain '{domain}': {e}")
                return jsonify({'error': f'Error during DGA prediction: {e}'}), 500

        @self.app.route('/api/decide_playbook', methods=['POST'])
        def decide_playbook_endpoint():
            """Receives alert data and returns a recommended SOAR action."""
            if not self.soar_pipeline:
                return jsonify({'error': 'SOAR Playbook is not available. The model may be disabled or failed to load.'}), 503

            data = request.get_json()
            
            # Basic validation
            required_fields = ['alert_source', 'severity', 'confidence', 'entity_type']
            if not all(field in data for field in required_fields):
                return jsonify({'error': f'Missing one or more required fields: {required_fields}'}), 400

            try:
                # Create a DataFrame from the input data for the pipeline
                alert_df = pd.DataFrame([data])
                prediction = self.soar_pipeline.predict(alert_df)[0]
                return jsonify({'recommended_action': prediction})

            except Exception as e:
                logging.error(f"Error during SOAR playbook decision: {e}")
                return jsonify({'error': f'Error during SOAR playbook decision: {e}'}), 500

        @self.app.route('/api/summarize_report', methods=['POST'])
        def summarize_report_endpoint():
            """Receives threat report text and returns an LLM-generated summary."""
            if not self.openai_client:
                return jsonify({'error': 'Threat Intel Summarizer is not available. Check API key in config.'}), 503

            data = request.get_json()
            report_text = data.get('report_text')

            if not report_text or not isinstance(report_text, str):
                return jsonify({'error': 'No report text provided.'}), 400

            try:
                system_prompt = (
                    "You are a senior cybersecurity threat intelligence analyst. Your task is to analyze the provided threat report. "
                    "First, provide a concise executive summary of the threat actor, their motives, and the overall campaign. "
                    "Then, extract all Indicators of Compromise (IOCs) and MITRE ATT&CK Tactics, Techniques, and Procedures (TTPs). "
                    "Format the entire output in clear markdown. Use headings for 'Executive Summary', 'Indicators of Compromise (IOCs)', and 'MITRE ATT&CK TTPs'. "
                    "List all IOCs and TTPs using bullet points."
                )
                
                completion = self.openai_client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": report_text}
                    ]
                )
                summary = completion.choices[0].message.content
                return jsonify({'summary': summary})

            except Exception as e:
                logging.error(f"Error during OpenAI API call: {e}")
                return jsonify({'error': f'An error occurred with the OpenAI API: {e}'}), 500

    def _start_api_server(self):
        """Runs the Flask API server in a separate thread."""
        logging.info("Starting API server on http://0.0.0.0:5555")
        self.app.run(host='0.0.0.0', port=5555, debug=False)

    def run(self):
        self._setup_api_routes()
        # Start background services in separate daemon threads
        enforcer_thread = Thread(target=self.firewall.policy_enforcer, name="PolicyEnforcer", daemon=True)
        enforcer_thread.start()
        api_thread = Thread(target=self._start_api_server, name="APIServer", daemon=True)
        api_thread.start()

        self.start()

if __name__ == "__main__":
    ips_service = AegisIPS()
    ips_service.run()