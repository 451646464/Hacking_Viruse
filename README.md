# Hacking_Viruse — Cybersecurity Threat Analysis Platform

<p align="center">
  <strong>A Python and Flask web application for defensive security analysis, threat triage, and suspicious-file investigation.</strong>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white">
  <img alt="Flask" src="https://img.shields.io/badge/Flask-Web%20Application-000000?logo=flask&logoColor=white">
  <img alt="Machine Learning" src="https://img.shields.io/badge/Machine%20Learning-Analysis-F7931E">
  <img alt="YARA" src="https://img.shields.io/badge/Detection-YARA-6A1B9A">
  <img alt="Security" src="https://img.shields.io/badge/Focus-Defensive%20Security-18794E">
</p>

## Overview

**Hacking_Viruse** is a Python-based web application designed to bring multiple defensive cybersecurity analysis capabilities into one place. Built with Flask, it combines file and image analysis, URL and web analysis, phishing-related checks, machine-learning-assisted detection, threat-intelligence integrations, and reporting features.

The repository includes components for analyzing suspicious files and extracting indicators that may help an analyst decide whether an item requires further investigation. It also includes user-account functionality and a web interface for accessing analysis features.

This project is intended to support security learning, defensive investigation, and authorized analysis. Automated results should be treated as triage signals—not as definitive proof that a file, image, or URL is malicious or safe.

## Features

### Suspicious-file and malware analysis

The codebase includes utilities and modules for file-oriented security analysis, including:

- File hashing and basic file metadata extraction.
- PE-file feature extraction and model-based sample prediction.
- String extraction and entropy analysis.
- Detection-oriented checks for packing and persistence-related indicators.
- Network indicators and possible command-and-control (C2) references.
- YARA rule application.
- Mapping selected findings to MITRE ATT&CK concepts.
- PDF report generation for supported analyses.

The actual results depend on the input, available models, configured rules, and enabled integrations.

### Image analysis

The repository includes image-analysis modules and routes intended to inspect supported image formats. The code references machine-learning-assisted image analysis, behavioral analysis, steganography detection, and optional threat-intelligence lookups.

Supported image extensions configured in the application include PNG, JPG/JPEG, GIF, BMP, TIFF, and WebP. Validate file-size limits and behavior against the current implementation before deploying the application.

### URL and web analysis

The project includes URL-analysis and web-analysis components for examining links and web-related indicators. It also includes a phishing-detection module and a threat-intelligence integration.

URL-analysis output can be affected by redirects, inaccessible sites, changing web content, and limitations in external intelligence sources. Do not open suspicious links in a normal browsing session merely to verify an alert.

### User accounts and application workflow

The codebase includes:

- User login and session management.
- Password-hashing helpers.
- Google OAuth integration.
- Database-backed analysis records and user-related models.
- Notifications and application routes.
- Upload handling and downloadable PDF reports.

Authentication and security controls should be reviewed and tested before any public or production deployment.

## Technology Stack

The repository references the following technologies and libraries:

- **Python** — application and analysis logic.
- **Flask** — web application and routes.
- **Flask-Login** — login and session support.
- **SQLAlchemy** — database integration and ORM models.
- **Flask-WTF / CSRFProtect** — form and CSRF protection components.
- **Joblib and machine-learning models** — loading supported serialized model artifacts.
- **YARA** — rule-based pattern matching for security analysis.
- **Requests** — HTTP requests and external service integrations.
- **PDF processing libraries** — extracting or processing PDF content and generating reports.
- **Plotly** — data visualization where used by the application.

The exact dependency versions are defined in `requirements.txt`; compatibility should be verified in a clean environment.

## Repository Structure

```text
Hacking_Viruse/
├── app.py                         # Flask application entry point and routes
├── config.py                      # Application configuration
├── database.py                    # Database initialization
├── models.py                      # Database models
├── forms.py                       # Form definitions
├── utils.py                       # Shared analysis and reporting utilities
├── web_analysis.py                # Web analysis functions
├── url_analyzer.py                # URL analysis
├── advanced_phishing_detector.py  # Phishing-oriented detection
├── image_analyzer.py              # Image analysis
├── ml_image_analyzer.py           # ML-assisted image analysis
├── behavioral_analyzer.py         # Behavioral image analysis
├── steganography_detector.py      # Steganography detection
├── threat_intelligence.py         # Threat-intelligence integration
├── yara-rules/                    # YARA rules
├── models/                        # Model artifacts
├── templates/                     # HTML templates
├── static/                        # CSS, JavaScript, and static assets
├── Data/                          # Project data
├── requirements.txt               # Python dependencies
├── run.bat                        # Windows launch helper
└── run.ps1                        # PowerShell launch helper
```

This is a high-level view of selected files and directories visible in the repository. Some modules or paths may change over time. Never commit secrets, private logs, production databases, or sensitive uploaded files.

## Getting Started

### Prerequisites

- Python 3 installed (use a version compatible with `requirements.txt`).
- Git.
- `pip`, Python's package installer.
- A supported database configuration.
- Optional API credentials for integrations you choose to enable.

### 1. Clone the repository

```bash
git clone https://github.com/451646464/Hacking_Viruse.git
cd Hacking_Viruse
```

### 2. Create a virtual environment

**Windows (PowerShell):**

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Windows (Command Prompt):**

```bat
py -m venv .venv
.venv\Scripts\activate.bat
```

**Linux / macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If installation fails, check the Python version, operating system requirements, and any external tools required by the analysis utilities. Avoid installing packages globally when working on a development project.

### 4. Configure secrets and environment variables

Before running the application:

1. Review `config.py` and the application configuration.
2. Move all passwords, OAuth client secrets, API keys, mail credentials, and Flask secret keys into environment variables or a secrets manager.
3. Rotate any credentials that have previously been committed to a public repository.
4. Ensure `.env`, local databases, uploaded files, logs, and private model data are excluded from Git.
5. Create a local `.env` file only if the application has been configured to load it; never commit that file.

Use placeholder values in examples and document the required variable names without including real credentials.

### 5. Start the application

The main application file is `app.py`. In a development environment, after configuration is complete, run:

```bash
python app.py
```

Check the startup output for the local address and any missing configuration. The exact startup command and port may depend on the entry-point code.

**Deployment warning:** Do not expose Flask's development server or debug mode to the public internet. Use a production WSGI server, HTTPS, secure cookie settings, access controls, and deployment-specific configuration before hosting the application.

## Typical Defensive Workflow

1. Sign in to the application in an authorized environment.
2. Select the available analysis workflow, such as file, image, or URL analysis.
3. Submit a benign test sample or a suspicious artifact you are authorized to investigate.
4. Review the extracted indicators, model output, and any available threat-intelligence findings.
5. Export a report if the selected workflow supports it.
6. Validate important findings using trusted tools and original evidence before making incident-response decisions.

Do not upload confidential business data or private files to third-party analysis services unless you are authorized to do so and understand their retention and privacy policies.

## Interpreting Results

- **Model predictions** are estimates based on the training data and features used by the model.
- **YARA matches** indicate that a rule matched content; they do not automatically establish that a file is malicious.
- **Threat-intelligence matches** depend on the quality, freshness, and coverage of the external source.
- **Image and URL findings** may contain false positives or miss new threats.
- **A clean result is not a guarantee of safety.** Combine automated analysis with context, trusted detection tools, and manual review.

## Security and Privacy Checklist

Before using this project beyond a local test environment:

- [ ] Rotate all credentials or API keys that have been exposed in Git history.
- [ ] Load secrets from environment variables or a secrets manager.
- [ ] Remove `.env`, database files, logs, uploads, and private data from version control.
- [ ] Review upload validation, file-size limits, file names, and temporary-file cleanup.
- [ ] Analyze untrusted files in an isolated, least-privileged environment.
- [ ] Review authentication, authorization, CSRF protection, and session-cookie settings.
- [ ] Disable debug mode and configure HTTPS for deployment.
- [ ] Review all outbound requests and third-party data-sharing behavior.
- [ ] Add tests for malformed input, large files, failed integrations, and access-control boundaries.
- [ ] Back up the database and protect reports that may contain sensitive indicators.

### Important credential warning

Never publish real API keys, OAuth client secrets, email passwords, application secret keys, or tokens in source code. If a credential has been exposed, revoke or rotate it immediately; removing it from the latest file does not remove it from earlier Git commits.

## Limitations

- Detection quality depends on the available training data, model artifacts, rules, and external services.
- The presence of an analysis module does not by itself establish that every workflow is complete or production-ready.
- Some features may require additional configuration, API access, or external tools.
- False positives and false negatives are possible.
- This repository should not be treated as a replacement for a mature endpoint-protection product, SIEM, sandbox, or incident-response process.
- A security review and controlled testing are recommended before any production deployment.

## Contributing

Contributions and constructive feedback are welcome.

1. Fork the repository.
2. Create a branch for your change.
3. Test changes with safe, non-sensitive sample data.
4. Avoid committing credentials, live malware samples, private logs, or confidential datasets.
5. Submit a pull request describing the change, tests, and any security implications.

## License

Check the repository for a `LICENSE` file. If no license is present, reuse and redistribution permissions may be unclear; add an appropriate license before accepting external reuse.

## Developer

**Rakan Almoliki (راكان المليكي)**

- **Email:** [rakanalmoliki33@gmail.com](mailto:rakanalmoliki33@gmail.com)
- **GitHub:** [451646464](https://github.com/451646464)

---

Built for cybersecurity learning and authorized defensive analysis. Use responsibly and only with systems and data you have permission to examine.
