# Log Analysis Script

## Overview
This Python script analyzes server log files to identify patterns, potential security threats, and access statistics. It was developed as part of the VRV Security Python Intern Assignment to demonstrate proficiency in file handling, string manipulation, and data analysis in a cybersecurity context.

## Features
- Count and sort requests per IP address
- Identify most frequently accessed endpoints
- Detect suspicious activity (e.g., potential brute force attempts)
- Generate detailed reports in both terminal output and Excel format

## Requirements
- Python 3.7 or higher
- Required packages:
  - pandas
  - openpyxl

## Installation

1. Clone the repository or download the source code:
```bash
git clone <repository-url>
cd log-analysis
```

2. Create and activate a virtual environment:
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# MacOS/Linux
python3 -m venv venv
source venv/bin/activate
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

## Project Structure
```
log_analysis/
├── log_analyzer.py    # Main script
├── sample.log        # Sample log file
├── requirements.txt  # Python dependencies
└── README.md        # This file
```

## Usage

1. Prepare your log file in the correct format (see sample.log for reference)

2. Run the script:
```bash
python log_analyzer.py
```

3. View the results:
- Terminal output will show immediate analysis
- An Excel file `log_analysis_results.csv` will be generated with detailed reports

## Output Format

### Terminal Output
```
=== Requests per IP Address ===
IP Address           Request Count
-----------------------------------
192.168.1.1          234
203.0.113.5          187
...

=== Most Frequently Accessed Endpoint ===
/home (Accessed 403 times)

=== Suspicious Activity Detected ===
IP Address           Failed Login Attempts
---------------------------------------------
192.168.1.100        56
203.0.113.34         12
```

### Excel Output
The script generates an Excel file with three sheets:
1. **Requests per IP**: IP addresses and their request counts
2. **Most Accessed Endpoint**: Most frequently accessed endpoints
3. **Suspicious Activity**: IPs with suspicious login attempt patterns

## Configuration
- Default failed login attempt threshold: 10 (configurable in script initialization)
- Log file path can be specified when initializing the LogAnalyzer class

## Error Handling
The script includes robust error handling for:
- Malformed log entries
- File access issues
- Invalid data formats

## Development
### Running Tests
```bash
# Future implementation
python -m pytest tests/
```

### Adding New Features
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with your changes

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Author
Osho Kothari

## Acknowledgments
- VRV Security for the project requirements
- Contributors and reviewers

## Support
For support, please open an issue in the repository.