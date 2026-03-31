# SENTINEL — Self-Evolving Neural Threat Intelligence Engine

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub stars](https://img.shields.io/github/stars/ramKarthik57/LOG_ANALYZER.svg)](https://github.com/ramKarthik57/LOG_ANALYZER/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/ramKarthik57/LOG_ANALYZER.svg)](https://github.com/ramKarthik57/LOG_ANALYZER/issues)

A comprehensive Forensic Intelligence Platform designed for Security Operations Centers (SOC) to analyze authentication logs, detect anomalies, and provide actionable threat intelligence through advanced AI/ML techniques.

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

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational and research purposes. Always ensure compliance with applicable laws and regulations when analyzing log data.