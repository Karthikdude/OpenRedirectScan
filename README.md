```markdown
# OpenRedirectScan

**Disclaimer**: This tool is intended for educational and ethical hacking purposes only. Always obtain proper authorization before testing any website or application.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Setup](#setup)
- [Usage](#usage)
  - [Prepare Payloads](#prepare-payloads)
  - [Run the Tool](#run-the-tool)
  - [Follow the Prompts](#follow-the-prompts)
- [Example](#example)
- [Output](#output)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Introduction

OpenRedirectScan is an advanced automated tool designed to detect open redirect vulnerabilities in web applications. It leverages the Wayback Machine to collect URLs and performs comprehensive testing using custom payloads to identify potential security risks.

## Features

- **Automated URL Collection**: Collects URLs from the Wayback Machine and filters them for relevant parameters.
- **Custom Payload Testing**: Allows users to specify custom payloads for testing open redirect vulnerabilities.
- **Concurrent Scanning**: Utilizes concurrent processing to speed up the scanning process.
- **Live Testing Output**: Provides real-time feedback on the testing process, highlighting vulnerable URLs and potential issues.
- **Detailed Reporting**: Saves the results of the scan to a file for further analysis.

## Installation

### Prerequisites

- Python 3.x
- `requests` library
- `termcolor` library
- `waybackurls` tool

### Setup

1. **Clone the Repository**:
   ```sh
   git clone https://github.com/yourusername/OpenRedirectScan.git
   cd OpenRedirectScan
   ```

2. **Install Dependencies**:
   ```sh
   pip install -r requirements.txt
   ```

3. **Install `waybackurls`**:
   ```sh
   pip install waybackurls
   ```

## Usage

### Prepare Payloads

- Create a file named `openredirectPayloads.txt` in the same directory as the script.
- Add your custom payloads to this file, one per line.

### Run the Tool

```sh
python open_redirect_scan.py
```

### Follow the Prompts

- Enter the domain name when prompted.
- Specify the location to save the filtered URLs.
- The tool will collect URLs, test them with the specified payloads, and save the results to `results.txt`.

## Example

```sh
python open_redirect_scan.py
[*] Enter domain name (e.g., example.com): testphp.vulnweb.com
[*] Collecting URLs from Wayback Machine...
[*] Filtered URLs saved to /home/kali/Documents/openredirects/testphp.txt
[*] Starting testing with payloads...
[*] Testing: http://testphp.vulnweb.com/listproducts.php?cat=http://evil.com
[*] Response Status Code: 200
[+] Vulnerability detected: http://testphp.vulnweb.com/listproducts.php?cat=http://evil.com -> http://evil.com
```

## Output

- **Live Testing Output**: The tool provides real-time feedback on the testing process, highlighting vulnerable URLs in red and potential issues in yellow.
- **Detailed Reporting**: The results of the scan are saved to `results.txt`, including the URL, payload, and redirect location for each vulnerability detected.

## Contributing

Contributions are welcome! Please feel free to submit issues and enhancement requests.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For more information, please contact https://karthik-s-sathyan.vercel.app
