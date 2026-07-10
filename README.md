Here is a complete, production-ready README.md explicitly designed for **CloudID-Hunter**. It covers everything from a high-level overview down to step-by-step Termux (Android) mobile installation, deployment flags, and terminal formatting features.
# CloudID-Hunter
**CloudID-Hunter** is a zero-dependency, high-performance command-line interface (CLI) security utility engineered for ethical hackers, penetration testers, and security auditors. The tool automates the process of identifying, probing, and auditing exposed **Instance Metadata Services (IMDS)** across multi-cloud environments, including AWS, GCP, Azure, DigitalOcean, and Kubernetes configurations.
By utilizing lightweight, concurrent network workers, CloudID-Hunter checks for link-local exposures and flags critical token leakages or configuration gaps that could lead to full cloud infrastructure compromise.
## Technical Features
 * **Zero External Dependencies:** Built entirely on Python's native standard library (urllib.request, ssl, socket). Run it anywhere Python 3 is present without needing pip install requests.
 * **High Concurrency Engine:** Uses native thread pools (ThreadPoolExecutor) to scan multiple targets simultaneously, completing full asset passes in milliseconds.
 * **Multi-Cloud Architecture Support:** Bundles unique signature rules and default endpoints tailored specifically for:
   * **AWS:** Explores IMDSv1 roots and includes explicit PUT request handling for AWS IMDSv2 token acquisition.
   * **GCP:** Validates required Metadata-Flavor: Google headers and looks for default Service Account tokens.
   * **Azure:** Targets explicit Metadata: true query headers for Azure AD and managed identity endpoints.
   * **DigitalOcean & Kubernetes:** Probes local configurations and checks for mounted pod service account tokens.
 * **Advanced Noise Reduction:** Includes built-in Shannon Entropy calculations, known documentation placeholder filters, and JWT structural validation checks to prevent false-positive alerts on random character blocks or local git SHAs.
## Installation & Setup
### Running on a PC / Linux Server
Simply pull down the repository and run the file using a modern Python interpreter (Python 3.8+ recommended):
```bash
# Clone the repository
git clone https://github.com/rokechukwu45-create/Cloudid.git

# Change your working directory into the project folder
cd Cloudid

# Give the script executable permissions (Linux/macOS)
chmod +x scanner.py

# Execute the help menu
python3 scanner.py --help

```
### Running on a Mobile Phone (Android via Termux)
Because the application requires zero external packages, it is lightweight and fits perfectly inside mobile testing setups like **Termux**.
#### Step 1: Install Termux
Download and install the latest terminal emulator build via **F-Droid** (avoid the outdated versions on the Google Play Store).
#### Step 2: Prepare the Environment
Open Termux on your phone and run the following setup commands to install Python, git, and update core packages:
```bash
# Update local package definitions
pkg update && pkg upgrade -y

# Install git version control and the Python runtime
pkg install git python -y

```
#### Step 3: Clone and Execute the Project
```bash
# Clone your specific repository
git clone https://github.com/rokechukwu45-create/Cloudid.git

# Move into the project path
cd Cloudid

# Run the scanner tool directly
python scanner.py

```
## CLI Reference & Usage Arguments
```text
usage: cloudid-hunter [-h] [-t BASE_URL] [-o {text,json}] [--timeout SECONDS] [--workers N] [--no-imdsv2] [--no-color] [--no-noise-filter]

```
### Argument Flags Explained
| Flag | Argument Type | Default Value | Description |
|---|---|---|---|
| -h, --help | None | N/A | Prints the complete automated help and options display matrix. |
| -t, --target | BASE_URL | None | Scans an external base URL (useful for probing Server-Side Request Forgery proxy targets). If omitted, defaults to the link-local address 169.254.169.254. |
| -o, --output | text or json | text | Dictates format type. Choose text for a structured terminal readout or json for programmatic log aggregation. |
| --timeout | SECONDS | 4.0 | Total network connection wait limits per probe drop before cutting thread pipes. |
| --workers | N | 20 | Concurrent worker allocation limits across the active execution pool. |
| --no-imdsv2 | None | False | Bypasses the explicit PUT method token probe loop built specifically for AWS IMDSv2. |
| --no-color | None | False | Strips all ANSI colors out of standard shell returns (automatically applied if outputs map to text logs). |
| --no-noise-filter | None | False | Disables entropy thresholds and structure checks to report every raw regex match. |
## Command Examples
### 1. Default Internal Audit
Probes local cloud fabric assets using concurrent workers via standard link-local lookups:
```bash
python3 scanner.py

```
### 2. Remote SSRF Proxy Verification
Audits an external URL or captured endpoint to check if an application is routing traffic directly into an cloud infrastructure metadata layer:
```bash
python3 scanner.py --target http://vulnerable-subdomain.target.local/proxy?url=

```
### 3. CI/CD Pipeline Automation (Structured Data Export)
Suppresses ANSI terminal colors, scales worker engines up, and exports findings to a clean JSON file for integration into security pipelines:
```bash
python3 scanner.py --workers 40 --no-color --output json > cloud_exposure_report.json

```
## License & Legal Terms
This utility is distributed under the **Apache 2.0 License**.
> **CRITICAL CONTRACT**: This security instrument is intended solely for authorized penetration testing, academic security research, and infrastructure auditing. Proper prior written validation must be obtained from target networks before running intrusive network sweeps. Unauthorized usage against third-party platforms violates infrastructure Terms of Service agreements and local criminal laws. Use responsibly.
> 
