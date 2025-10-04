 Nmap Vulnerability Scanner (Python)

This project is a **network vulnerability scanner** built in Python using the `python-nmap` library.  
It automates **subnet-wide vulnerability scanning** using Nmap’s Scripting Engine (NSE) and generates detailed reports in both **JSON** and **CSV** formats.

 Features

- Automated Subnet Scanning**: Scans an entire subnet or a single host using Nmap.
- Nmap NSE Integration**: Uses Nmap’s vulnerability scripts (`--script vuln`) to detect common security flaws.
- Detailed Reports:
  - Lists host IPs, open ports, protocols, and service versions.
  - Includes vulnerabilities identified by NSE.
  - Exports results as both JSON and CSV.
- Customizable via CLI**: Supports custom Nmap arguments using command-line flags.
- Robust Logging & Error Handling**: Clear status updates during scan execution.

 Installation

Clone the repository and install dependencies using `requirements.txt`.

```bash
# 1. Clone this repository
git clone https://github.com/<your-username>/Nmap-Vulnerability-Scanner.git
cd Nmap-Vulnerability-Scanner

# 2. (Optional) Create a virtual environment
python -m venv venv
source venv/bin/activate      # For macOS/Linux
venv\Scripts\activate         # For Windows

# 3. Install dependencies
pip install -r requirements.txt

# Usage 
Run directly from command line . 
python Nmap_vuln.py  --subnet <192.168.1.0/24>  # replace with subnet which needs to scanned .
