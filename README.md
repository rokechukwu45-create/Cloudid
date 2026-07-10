# CloudID Hunter

**CloudID Hunter** is a high-performance Python tool for discovering publicly exposed cloud metadata services. It helps security professionals identify cloud metadata endpoints that may be unintentionally accessible on internet-facing systems.

> **For authorized security testing only.**

---

## Features

- Fast metadata endpoint detection
- Supports common cloud environments
- Lightweight with no external runtime dependencies
- Simple command-line interface
- Cross-platform (Linux, macOS, Windows)

---

## Installation

Install from PyPI:

```bash
pip install cloudid-hunter
```

Or install from source:

```bash
git clone https://github.com/rokechukwu45-create/Cloudid.git
cd Cloudid
pip install .
```

---

## Usage

Scan a target:

```bash
cloudid-hunter example.com
```

Display help:

```bash
cloudid-hunter --help
```

If running from source:

```bash
python -m cloudid_hunter example.com
```

---

## Example Output

```text
==================================
 CloudID Hunter v1.3.1
==================================

Target: example.com

[+] Checking cloud metadata endpoints...
[+] No exposed metadata service detected.

Scan completed.
```

---

## Requirements

- Python 3.8 or newer

---

## Installation for Developers

Clone the repository:

```bash
git clone https://github.com/rokechukwu45-create/Cloudid.git
cd Cloudid
```

Install in editable mode:

```bash
pip install -e .
```

---

## Project Structure

```
Cloudid/
├── cloudid_hunter/
│   ├── __init__.py
│   ├── __main__.py
│   └── scanner.py
├── pyproject.toml
├── README.md
└── LICENSE
```

---

## Disclaimer

This software is intended for security assessments performed with proper authorization. Users are responsible for ensuring compliance with all applicable laws and regulations.

---

## License

MIT License

---

## Author

Principal Security Engineer

GitHub: https://github.com/rokechukwu45-create
