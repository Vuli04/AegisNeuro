# AegisNeuro
An AI-powered cybersecurity suite for intelligent threat detection, analysis, and automated response.
# AegisNeuro: An AI-Powered Cybersecurity Suite

![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

AegisNeuro is a comprehensive, full-stack cybersecurity platform designed to provide multi-layered security for small and medium-sized businesses. It integrates a live, ML-enhanced Intrusion Prevention System (IPS) with a powerful, API-driven suite of AI-powered tools, creating a "Virtual Security Officer" in a box.

The platform goes beyond traditional network defense by providing tools for proactive threat analysis and automated response, turning complex security data into clear, actionable intelligence.

## Core Features

*   **Live Intrusion Prevention:** A real-time network monitor using Scapy that combines rule-based (Port Scan) and ML-based (Anomaly Detection) engines to automatically block threats.
*   **Automated Firewall Management:** A persistent, database-backed firewall manager that handles blocking, unblocking, and whitelisting.
*   **AI-Powered Security Toolkit (via REST API):**
    *   **Phishing URL Detector:** Classifies URLs as legitimate or phishing.
    *   **Malicious Script Analyzer:** Analyzes code snippets using static and ML techniques.
    *   **CVE Vulnerability Classifier:** Uses NLP to categorize vulnerability descriptions.
    *   **Log Anomaly Detector:** Finds suspicious login patterns in authentication logs.
    *   **DGA Detector:** Identifies malware-generated domain names.
    *   **AI-Driven SOAR Playbook:** Recommends incident response actions for alerts.
    *   **Threat Intelligence Summarizer:** Uses an LLM (GPT) to summarize complex security reports.
*   **Web-Based GUI:** A user-friendly web interface for live monitoring, configuration, and interaction with all security tools.

## Technology Stack

*   **Backend:** Python, Flask, Scapy
*   **Machine Learning:** Scikit-learn, Pandas, NumPy, OpenAI API
*   **Database:** SQLite
*   **Frontend:** HTML, CSS, JavaScript

---

## System Architecture

The system is built around a central Python service (`aegis_ips_service.py`) that orchestrates all components.

```
   +--------------------------------+
   |      User (Web Browser)        |
   |       (web/index.html)         |
   +----------------+---------------+
                    |
                    | (HTTP/HTTPS)
                    v
   +----------------+---------------+   <-- REST API -->   +------------------------+
   |      Flask API Server          |                      |   External Tools       |
   | (in aegis_ips_service.py)      |                      | (e.g., curl, scripts)  |
   +----------------+---------------+                      +------------------------+
                    |
                    | (Internal Calls)
   +----------------v---------------+
   |      AegisIPS Core Service     |
   |                                |
   |  +--------------------------+  |
   |  |   AI Analysis Tools      |  |
   |  | (Phishing, CVE, etc.)    |  |
   |  +--------------------------+  |
   |                                |
   |  +--------------------------+  |
   |  |   Live Packet Sniffer    |  |
   |  |        (Scapy)           |  |
   |  +------------+-------------+  |
   |               |                |
   |  +------------v-------------+  |
   |  |  Detection Engines       |  |
   |  | (PortScan, MLAnomaly)   |  |
   |  +------------+-------------+  |
   |               |                |
   |  +------------v-------------+  |   <-- DB Access -->   +------------------------+
   |  |    FirewallManager       |<>---------------------->|   aegis_hub.db         |
   |  +--------------------------+  |                      | (SQLite: Blocks, Alerts) |
   |                                |                      +------------------------+
   +--------------------------------+
```

---

## Installation & Setup

### Prerequisites

1.  **Python 3.9+**
2.  **Npcap:** For packet sniffing on Windows. Download and install from npcap.com. During installation, ensure you check the "Install Npcap in WinPcap API-compatible Mode" option.
3.  **Git**

### Step-by-Step Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/AegisNeuro.git
    cd AegisNeuro
    ```

2.  **Create and activate a virtual environment:**
    *   On Windows:
        ```bash
        python -m venv venv
        .\venv\Scripts\activate
        ```
    *   On macOS/Linux:
        ```bash
        python3 -m venv venv
        source venv/bin/activate
        ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: You will need to create a `requirements.txt` file. You can do this by running `pip freeze > requirements.txt` in your activated virtual environment after installing all packages.)*

4.  **Set up the configuration file:**
    Copy the example configuration file.
    ```bash
    cp config.ini.example config.ini
    ```

5.  **Set up the OpenAI API Key:**
    The Threat Intelligence Summarizer requires an OpenAI API key.
    *   **Recommended:** Set it as an environment variable.
        *   On Windows (Command Prompt):
            ```bash
            set OPENAI_API_KEY="sk-YOUR_API_KEY_HERE"
            ```
        *   On Windows (PowerShell):
            ```bash
            $env:OPENAI_API_KEY="sk-YOUR_API_KEY_HERE"
            ```
        *   On macOS/Linux:
            ```bash
            export OPENAI_API_KEY="sk-YOUR_API_KEY_HERE"
            ```
    *   Alternatively, you can edit the `config.ini` file directly and replace `sk-YOUR_API_KEY_HERE` with your key, but this is less secure.

---

## Usage

1.  **Run the Aegis Hub:**
    The service requires administrative privileges to interact with the firewall and capture network packets.
    *   **On Windows:** Open Command Prompt or PowerShell **as an Administrator** and run:
        ```bash
        python run_aegis_hub.py
        ```
    *   **On macOS/Linux:**
        ```bash
        sudo python run_aegis_hub.py
        ```

2.  **Access the Web Interface:**
    Once the service is running, open the `web/index.html` file in your web browser. This dashboard provides a live view of the system's status, configuration options, and access to all the analysis tools.

---

## API Endpoints & Examples

The AegisNeuro toolkit is accessible via a REST API, typically running on `http://127.0.0.1:5555`.

### Phishing URL Detector

*   **Endpoint:** `POST /api/detect_phishing`
*   **Body:** `{"url": "http://example-login-portal.com"}`
*   **Example `curl`:**
    ```bash
    curl -X POST -H "Content-Type: application/json" -d '{"url": "http://example-login-portal.com"}' http://127.0.0.1:5555/api/detect_phishing
    ```

### Malicious Script Analyzer

*   **Endpoint:** `POST /api/analyze_script`
*   **Body (Static):** `{"code": "os.remove('important.txt')", "analysis_type": "static"}`
*   **Body (ML):** `{"code": "eval(base64.b64decode(...))", "analysis_type": "ml"}`
*   **Example `curl`:**
    ```bash
    curl -X POST -H "Content-Type: application/json" -d '{"code": "os.remove(\"C:\\\\Windows\\\\System32\")", "analysis_type": "static"}' http://127.0.0.1:5555/api/analyze_script
    ```

### CVE Classifier

*   **Endpoint:** `POST /api/classify_cve`
*   **Body:** `{"description": "A remote code execution vulnerability exists in..."}`
*   **Example `curl`:**
    ```bash
    curl -X POST -H "Content-Type: application/json" -d '{"description": "A cross-site scripting (XSS) vulnerability in the search component allows remote attackers to inject arbitrary web script."}' http://127.0.0.1:5555/api/classify_cve
    ```

*(Other tools like the DGA Detector, Log Anomaly Detector, SOAR Playbook, and Threat Intel Summarizer follow a similar API pattern.)*

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## Disclaimer

AegisNeuro is a portfolio project created for demonstration and educational purposes. While it is a fully functional application, it has not been hardened for production environments. Do not deploy in a live, critical environment without extensive further testing and security hardening.

