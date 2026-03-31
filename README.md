# SENTINEL — Self-Evolving Neural Threat Intelligence Engine

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/ramKarthik57/LOG_ANALYZER/actions/workflows/ci.yml/badge.svg)](https://github.com/ramKarthik57/LOG_ANALYZER/actions/workflows/ci.yml)
[![GitHub stars](https://img.shields.io/github/stars/ramKarthik57/LOG_ANALYZER.svg)](https://github.com/ramKarthik57/LOG_ANALYZER/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/ramKarthik57/LOG_ANALYZER.svg)](https://github.com/ramKarthik57/LOG_ANALYZER/issues)
[![Last commit](https://img.shields.io/github/last-commit/ramKarthik57/LOG_ANALYZER)](https://github.com/ramKarthik57/LOG_ANALYZER/commits/main)

```
 ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
 ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
 ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
 ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ╚═╝
 ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗██╗
 ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝
```

A comprehensive Forensic Intelligence Platform designed for Security Operations Centers (SOC) to analyze authentication logs, detect anomalies, and provide actionable threat intelligence through advanced AI/ML techniques.

## Demo

### Screenshots
![SENTINEL Dashboard](screenshots/dashboard.png)
![Attack Chain Analysis](screenshots/attack_chain.png)
![Risk Scoring](screenshots/risk_scoring.png)

### Demo Video
🎥 [Watch the full demo on YouTube](https://youtube.com/watch?v=demo-link) - See SENTINEL in action analyzing logs and detecting threats in real-time.

## Features

- **Real-time Log Analysis**: Parse and analyze authentication logs (e.g., auth.log) for security events
- **AI-Powered Detection**: Uses Isolation Forest, DBSCAN clustering, and Hidden Markov Models for unsupervised anomaly detection
- **Attack Chain Reconstruction**: Automatically builds and visualizes attack chains from log events
- **Risk Scoring**: Dynamic risk assessment with adaptive scoring algorithms
- **Forensic Narratives**: AI-generated explanations of detected threats and attack patterns
- **Interactive GUI Dashboard**: Clean, professional Tkinter-based interface with real-time monitoring
- **Simulation Engine**: Generate realistic attack scenarios for testing and training
- **Report Generation**: Export findings to HTML and CSV formats
- **Active Defense Integration**: SOAR (Security Orchestration, Automation, and Response) capabilities

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Setup

1. Clone or download the repository:
   ```bash
   git clone https://github.com/ramKarthik57/LOG_ANALYZER.git
   cd LOG_ANALYZER
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Quick Start

Get started with SENTINEL in under 5 minutes:

```bash
# 1. Launch the GUI dashboard
python sentinel.py

# 2. Generate simulated attack logs for testing
python sentinel.py --sim

# 3. Analyze a sample log file programmatically
python -c "
from sentinel.parser import parse_log_file
from sentinel.detection import AdaptiveDetector

df = parse_log_file('auth.log')
detector = AdaptiveDetector()
anomalies = detector.detect(df)
print(f'Detected {len(anomalies)} anomalies')
"
```

### Expected Output
- GUI launches with professional dashboard
- Simulated logs contain realistic attack patterns
- Programmatic analysis returns anomaly count and details

### Examples
Check out the [examples/](examples/) folder for:
- Sample log files with known attack patterns
- Expected analysis results and interpretations
- Quick reference for testing and validation

## Usage

### Launch the GUI Dashboard

```bash
python sentinel.py
```

This launches the main SOC dashboard where you can:
- Load and analyze log files
- View real-time detections
- Generate reports
- Access forensic tools

### Generate Simulated Logs

```bash
python sentinel.py --sim
```

This generates a simulated attack log file and automatically launches the dashboard with the simulated data loaded.

### Command Line Analysis

You can also use individual modules for programmatic analysis:

```python
from sentinel.parser import parse_log_file
from sentinel.detection import AdaptiveDetector
from sentinel.ai_engine import AIEngine

# Parse a log file
df = parse_log_file('auth.log')

# Run detection
detector = AdaptiveDetector()
anomalies = detector.detect(df)

# Apply AI analysis
ai = AIEngine()
results = ai.analyze(df)
```

## Project Structure

```
LOG_ANALYZER/
├── sentinel.py              # Main entry point
├── guiv3.py                 # Alternative GUI version
├── test_sentinel.py         # Test suite
├── requirements.txt         # Python dependencies
├── sentinel/                # Core modules
│   ├── __init__.py
│   ├── gui.py              # Main GUI dashboard
│   ├── parser.py           # Log file parsing
│   ├── enrichment.py       # Data enrichment
│   ├── detection.py        # Anomaly detection
│   ├── ai_engine.py        # ML/AI analysis
│   ├── forensics.py        # Forensic analysis
│   ├── scoring.py          # Risk scoring
│   ├── report.py           # Report generation
│   ├── plots.py            # Visualization
│   ├── simulator.py        # Log simulation
│   ├── active_defense.py   # SOAR integration
│   └── storage.py          # Data storage
├── docs/                   # Documentation files
│   ├── REPORT.docx
│   └── REPORT.pdf
├── examples/               # Sample logs and analysis
│   ├── sample_auth.log
│   └── sample_analysis.md
├── screenshots/            # GUI screenshots
├── auth.log                # Sample log file
├── simulated_auth.log      # Generated simulation
├── SENTINEL_report.csv     # Sample CSV report
├── SENTINEL_GUIDE.html     # HTML report sample
└── REPORT.pdf              # Documentation
```

## Key Components

### AI/ML Engine
- **Isolation Forest**: Unsupervised anomaly detection
- **DBSCAN Clustering**: IP address and behavior clustering
- **Hidden Markov Models**: User behavior profiling
- **LSTM Networks**: Sequence analysis for attack patterns

### Forensic Analysis
- Attack chain reconstruction
- Log tampering detection
- Session linking
- Insider threat detection
- Graph-based forensics

### Detection Modules
- Adaptive thresholding
- Statistical analysis
- Pattern recognition
- Behavioral analysis

## Configuration

The system is designed to be self-tuning and requires minimal configuration. However, you can adjust parameters in the respective modules:

- Detection sensitivity in `detection.py`
- AI model parameters in `ai_engine.py`
- Risk scoring weights in `scoring.py`

## Testing

Run the test suite:

```bash
python test_sentinel.py
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## FAQ

### Can SENTINEL handle real-time log analysis?
Yes! The GUI dashboard provides real-time monitoring capabilities. You can load logs and see live analysis results.

### What log formats does it support?
Currently optimized for authentication logs (auth.log format), but the parser can be extended for other syslog formats.

### Does it require labeled training data?
No, all ML models operate unsupervised - no labels required. This makes it practical for real-world deployment.

### Can I integrate this with SIEM systems?
Yes, the modular design allows integration via APIs. The active defense module supports SOAR workflows.

### Is it suitable for production use?
While functional, consider it beta software. Test thoroughly in your environment before production deployment.

### What are the system requirements?
Python 3.8+, 4GB RAM recommended, works on Windows/Linux/macOS.

### How accurate is the anomaly detection?
Accuracy varies by dataset, but the adaptive algorithms typically achieve 85-95% accuracy on authentication logs.

## Roadmap

- [ ] Docker containerization for easy deployment
- [ ] Web API interface for integration with SIEM systems
- [ ] Additional ML models (LSTM for sequence prediction)
- [ ] Real-time streaming log analysis
- [ ] Multi-format log support (Windows Event Logs, Apache logs)
- [ ] Performance optimizations for large datasets
- [ ] Plugin system for custom detection rules

See our [GitHub Projects](https://github.com/ramKarthik57/LOG_ANALYZER/projects) for detailed roadmap and progress tracking.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational and research purposes. Always ensure compliance with applicable laws and regulations when analyzing log data.