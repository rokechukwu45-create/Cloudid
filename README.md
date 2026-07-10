# Cloudid
Tool for Ethical hackers CloudID-Hunter is a zero-dependency, concurrent command-line interface (CLI) tool engineered to discover, audit, and flag exposed cloud metadata fabrics, link-local configuration leaks, and plaintext service tokens.

This scanner targets exposures across multiple providers including AWS, Google Cloud Platform (GCP), Microsoft Azure, DigitalOcean, and Kubernetes. It features an intelligent noise filter to validate genuine exposure and strip out false tracking cookies or placeholders.

📖 Table of Contents
Core Capabilities Explained
Directory Structure Setup
Installation Methods
Command-Line Arguments Reference
Step-by-Step Usage & Command Explanations
Troubleshooting & Verification
🔬 Core Capabilities Explained
When you target a website or run it locally, the engine performs the following operations behind the scenes:

IMDSv1 & IMDSv2 Auditing: Attempts to talk to link-local metadata endpoints (169.254.169.254). For AWS environments, it automatically requests a token payload (X-aws-ec2-metadata-token) to bypass protection layers.
Intelligent Filtering (Anti-False Positive): Instead of logging every random string it encounters, the scanner checks standard deviation and Shannon Entropy thresholds. It also performs structural validation on JSON Web Tokens (JWT) and checks for authentic server headers (like EC2ws or Metadata-Flavor) before reporting vulnerabilities.
📁 Directory Structure Setup
To package this tool or install it locally, your folder structure must look exactly like this. Create these directories and place your script files inside them before running any installation commands:

cloudid_project/
├── pyproject.toml
├── README.md
└── src/
    └── cloudid_hunter/
        ├── __init__.py
        └── scanner.py
