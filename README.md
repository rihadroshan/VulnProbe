# **CodeSentry**

**CodeSentry** is a robust and comprehensive tool designed to scan websites and source code for potential vulnerabilities. It identifies security issues in Python, JavaScript, Java, Ruby, and web applications, helping developers secure their projects effectively.

## Features

### Code Analysis
- **Supported Languages**: Python, JavaScript, Java, Ruby
- **Detects Vulnerabilities**:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Insecure APIs (e.g., `eval`, `exec`)
  - Insecure HTTP requests
  - Hardcoded secrets (e.g., API keys, passwords)
  - Insecure deserialization
  - DOM-based XSS (JavaScript)
  - Use of `innerHTML` (JavaScript)

### Website Scanning
- **Checks for**:
  - Insecure HTTP vs HTTPS
  - Invalid HTTPS certificates
  - Missing security headers (e.g., `Content-Security-Policy`, `X-Frame-Options`)
  - Insecure cookies (missing `Secure` or `HttpOnly` flags)
  - Mixed content (HTTP resources on HTTPS pages)
  - Clickjacking vulnerabilities
  - Open ports (e.g., 21, 22, 80, 443, 8080, 3306, 3389)

### Reporting
- **Output Formats**: Plain text or JSON
- **Detailed Reports**: Includes vulnerability type, line number (for code), and a description of the issue.

---

## **Installation**

1. Clone this repository:  
   ```bash
   git clone https://github.com/your-username/CodeSentry.git
   cd CodeSentry
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Tool**:
```bash
# Analyze code
python CodeSentry.py --file <path_to_file> --format <text|json>
```
```bash
# Scan website
python CodeSentry.py --url <website_url> --format <text|json>

```

## Usage

### Analyze a Code File

```bash
python CodeSentry.py --file example.py --format json
```

### Scan a Website

```bash
python CodeSentry.py --url https://example.com --format text
```

### Output Formats
- **Text**: Human-readable plain text.
- **JSON**: Structured JSON output.

---

## **Supported Vulnerabilities**

| Type                     | Detected Issues                                                                    |
|--------------------------|------------------------------------------------------------------------------------|
| **Python**               | SQL Injection, XSS, Insecure APIs, Hardcoded Secrets, Insecure HTTP, Pickle misuse |
| **JavaScript**           | XSS, eval usage, Hardcoded Secrets, Insecure HTTP, DOM-based XSS, innerHTML misuse |
| **Website**              | Insecure HTTP, SSL/TLS Certificate Issues, Mixed Content, Insecure Cookies         |
| **Network**              | Open Ports Scanning                                                                |

---

## Supported Languages

### Python
- Detects SQL injection, XSS, insecure APIs, hardcoded secrets, and more.

### JavaScript
- Detects XSS, use of `eval`, insecure HTTP requests, and DOM-based vulnerabilities.

### Java
- Detects SQL injection and other common vulnerabilities.

### Ruby
- Basic support for Ruby code analysis (work in progress).

---

## Examples

### Example 1: Analyzing Python Code
```bash
python CodeSentry.py --file example.py --format text
```

**Output**:
```
SQL Injection: Potential SQL injection vulnerability detected (line 10).
XSS: Potential XSS vulnerability detected (line 15).
Insecure API: Insecure API 'eval' detected (line 20).
```

### Example 2: Scanning a Website
```bash
python CodeSentry.py --url https://example.com --format json
```

**Output**:
```json
[
  {
    "type": "Insecure HTTP",
    "message": "Website uses insecure HTTP (use HTTPS instead)."
  },
  {
    "type": "Missing Security Header",
    "message": "Missing security header: Content-Security-Policy."
  }
]
```


## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
---


## Contributions & Reporting Issues:

Contributions of new features, improvements, or bug fixes are always welcome!

Feel free to open a pull request or open an issue.

## **Acknowledgments**

Thanks to the open-source community and tools like `esprima`, `javalang`, `ripper`, and `BeautifulSoup` for making this project possible.

## Disclaimer
This tool is intended for educational and security testing purposes only. Use it responsibly and only on systems you own or have permission to test. The authors are not responsible for any misuse or damage caused by this tool.

## Files in the Repository

- **`CodeSentry.py`**: Main script for code analysis and website scanning.
- **`requirements.txt`**: Python dependencies for the tool.
- **`README.md`**: This readme file providing an overview and usage instructions.
- **`LICENSE`**: MIT License terms.
