import ast
import argparse
import json
from pathlib import Path
import esprima
import requests
from bs4 import BeautifulSoup
import ssl
import socket
import logging
import javalang
import ripper
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def detect_sql_injection(node):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == 'execute' and isinstance(node.func.value, ast.Name):
            for arg in node.args:
                if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
                    return True
    return False

def detect_xss(node):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == 'write' and isinstance(node.func.value, ast.Name):
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    return True
    return False

def detect_insecure_api(node):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        if node.func.id in ['eval', 'exec']:
            return True
    return False

def detect_insecure_http_py(node):
    if isinstance(node, ast.Str):
        if "http://" in node.s:
            return True
    return False

def detect_hardcoded_secrets_py(node):
    """
    Detect hardcoded secrets like API keys or passwords in Python code.
    """
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name) and isinstance(node.value, ast.Str):
                if "api_key" in target.id.lower() or "password" in target.id.lower():
                    return True
    return False

def detect_insecure_deserialization(node):
    """
    Detect insecure deserialization in Python code.
    """
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "loads" and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "pickle":
                return True
    return False

def detect_js_xss(node):
    """
    Detect potential XSS vulnerabilities in JavaScript code.
    """
    if node.type == "AssignmentExpression" and node.left.property and node.left.property.name == "innerHTML":
        return True
    return False

def detect_js_eval(node):
    """
    Detect the use of `eval()` in JavaScript code.
    """
    if node.type == "CallExpression" and node.callee.name == "eval":
        return True
    return False

def detect_hardcoded_secrets(node):
    """
    Detect hardcoded secrets like API keys or passwords in JavaScript code.
    """
    if node.type == "VariableDeclarator" and node.init and node.init.type == "Literal":
        if "api_key" in str(node.init.value).lower() or "password" in str(node.init.value).lower():
            return True
    return False

def detect_insecure_http_js(node):
    """
    Detect insecure HTTP requests (http://) in JavaScript code.
    """
    if node.type == "Literal" and isinstance(node.value, str):
        if "http://" in node.value:
            return True
    return False

def detect_dom_xss(node):
    """
    Detect DOM-based XSS vulnerabilities in JavaScript code.
    """
    if node.type == "CallExpression" and node.callee.property and node.callee.property.name == "write":
        return True
    return False

def detect_inner_html(node):
    """
    Detect the use of `innerHTML` in JavaScript code.
    """
    if node.type == "AssignmentExpression" and node.left.property and node.left.property.name == "innerHTML":
        return True
    return False

def traverse_esprima(node, vulnerabilities):
    """
    Recursively traverse the esprima AST and detect vulnerabilities.
    """

    if detect_js_xss(node):
        vulnerabilities.append({
            "type": "XSS",
            "line": node.loc.start.line,
            "message": "Potential XSS vulnerability detected (innerHTML)."
        })
    if detect_js_eval(node):
        vulnerabilities.append({
            "type": "Insecure API",
            "line": node.loc.start.line,
            "message": "Insecure API 'eval' detected."
        })
    if detect_hardcoded_secrets(node):
        vulnerabilities.append({
            "type": "Hardcoded Secret",
            "line": node.loc.start.line,
            "message": "Potential hardcoded secret detected."
        })
    if detect_insecure_http_js(node):
        vulnerabilities.append({
            "type": "Insecure HTTP",
            "line": node.loc.start.line,
            "message": "Insecure HTTP request detected (use HTTPS instead)."
        })
    if detect_dom_xss(node):
        vulnerabilities.append({
            "type": "DOM XSS",
            "line": node.loc.start.line,
            "message": "Potential DOM-based XSS vulnerability detected."
        })
    if detect_inner_html(node):
        vulnerabilities.append({
            "type": "Insecure innerHTML",
            "line": node.loc.start.line,
            "message": "Potential XSS vulnerability detected (innerHTML)."
        })

    for key, value in node.__dict__.items():
        if isinstance(value, list):
            for item in value:
                if hasattr(item, "type"):
                    traverse_esprima(item, vulnerabilities)
        elif hasattr(value, "type"):
            traverse_esprima(value, vulnerabilities)

# Source Code Analysis
def analyze_code(file_path):
    """
    Analyze the given file (Python, JavaScript, Java, or Ruby) for vulnerabilities.
    """
    vulnerabilities = []

    try:
        with open(file_path, "r") as file:
            content = file.read()

        # Determine the file type based on the extension
        if file_path.endswith(".py"):
            tree = ast.parse(content, filename=file_path)
            for node in ast.walk(tree):
                if detect_sql_injection(node):
                    vulnerabilities.append({
                        "type": "SQL Injection",
                        "line": node.lineno,
                        "message": "Potential SQL injection vulnerability detected."
                    })
                if detect_xss(node):
                    vulnerabilities.append({
                        "type": "XSS",
                        "line": node.lineno,
                        "message": "Potential XSS vulnerability detected."
                    })
                if detect_insecure_api(node):
                    vulnerabilities.append({
                        "type": "Insecure API",
                        "line": node.lineno,
                        "message": f"Insecure API '{node.func.id}' detected."
                    })
                if detect_insecure_http_py(node):
                    vulnerabilities.append({
                        "type": "Insecure HTTP",
                        "line": node.lineno,
                        "message": "Insecure HTTP request detected (use HTTPS instead)."
                    })
                if detect_hardcoded_secrets_py(node):
                    vulnerabilities.append({
                        "type": "Hardcoded Secret",
                        "line": node.lineno,
                        "message": "Potential hardcoded secret detected."
                    })
                if detect_insecure_deserialization(node):
                    vulnerabilities.append({
                        "type": "Insecure Deserialization",
                        "line": node.lineno,
                        "message": "Potential insecure deserialization detected."
                    })

        elif file_path.endswith(".js"):
            try:
                tree = esprima.parseScript(content, {"loc": True})
                traverse_esprima(tree, vulnerabilities)
            except Exception as e:
                logging.error(f"Error parsing JavaScript file: {e}")
                return []

        elif file_path.endswith(".java"):
            try:
                tree = javalang.parse.parse(content)
                for path, node in tree:
                    if isinstance(node, javalang.tree.MethodInvocation):
                        if node.member == "executeQuery" or node.member == "executeUpdate":
                            vulnerabilities.append({
                                "type": "SQL Injection",
                                "line": node.position.line,
                                "message": "Potential SQL injection vulnerability detected."
                            })
            except Exception as e:
                logging.error(f"Error parsing Java file: {e}")
                return []

        elif file_path.endswith(".rb"):
            try:
                tree = ripper.sexp(content)
            except Exception as e:
                logging.error(f"Error parsing Ruby file: {e}")
                return []

        else:
            logging.error(f"Unsupported file type: {file_path}")
            return []

    except Exception as e:
        logging.error(f"Error analyzing file: {e}")
        return []

    return vulnerabilities

# Web Vulnerability Detectors
def check_insecure_http(url):
    """
    Check if the website uses insecure HTTP instead of HTTPS.
    """
    if url.startswith("http://"):
        return True
    return False

def check_https_certificate(url):
    """
    Check if the HTTPS certificate is valid.
    """
    if url.startswith("https://"):
        try:
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(), server_hostname=url.split("//")[1]) as sock:
                sock.connect((url.split("//")[1], 443))
            return True
        except Exception as e:
            return False
    return True

def check_security_headers(url):
    """
    Check for missing security headers.
    """
    headers_to_check = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
    ]
    missing_headers = []

    try:
        response = requests.get(url)
        for header in headers_to_check:
            if header not in response.headers:
                missing_headers.append(header)
    except Exception as e:
        logging.error(f"Error fetching headers from {url}: {e}")
        return []

    return missing_headers

def check_insecure_cookies(url):
    """
    Check for insecure cookies (missing Secure or HttpOnly flags).
    """
    insecure_cookies = []

    try:
        response = requests.get(url)
        for cookie in response.cookies:
            if not cookie.secure:
                insecure_cookies.append(f"Cookie '{cookie.name}' is missing the Secure flag.")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                insecure_cookies.append(f"Cookie '{cookie.name}' is missing the HttpOnly flag.")
    except Exception as e:
        logging.error(f"Error fetching cookies from {url}: {e}")
        return []

    return insecure_cookies

def detect_mixed_content(url):
    """
    Detect mixed content (HTTP resources loaded on an HTTPS page).
    """
    mixed_content = []

    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")

        for tag in soup.find_all(["script", "img", "iframe", "link"]):
            src = tag.get("src") or tag.get("href")
            if src and src.startswith("http://"):
                mixed_content.append(src)
    except Exception as e:
        logging.error(f"Error detecting mixed content: {e}")
        return []

    return mixed_content

def detect_clickjacking(url):
    """
    Detect missing headers to prevent clickjacking.
    """
    try:
        response = requests.get(url)
        if "X-Frame-Options" not in response.headers and "Content-Security-Policy" not in response.headers:
            return True
    except Exception as e:
        logging.error(f"Error detecting clickjacking: {e}")
        return False
    return False

# Port Scanning
def scan_ports(host, ports=[21, 22, 80, 443, 8080, 3306, 3389]):
    """
    Scan for open ports on the target host.
    """
    open_ports = []

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)  # Increase timeout to 2 seconds
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
                logging.info(f"Port {port} is open on {host}.")
            sock.close()
        except Exception as e:
            logging.error(f"Error scanning port {port}: {e}")

    return open_ports

def scan_website(url):
    """
    Scan a website for vulnerabilities, including open ports.
    """
    vulnerabilities = []

    parsed_url = urlparse(url)
    host = parsed_url.hostname

    if not host:
        logging.error(f"Could not extract host from URL: {url}")
        return vulnerabilities

    # Check for insecure HTTP
    if check_insecure_http(url):
        vulnerabilities.append({
            "type": "Insecure HTTP",
            "message": "Website uses insecure HTTP (use HTTPS instead)."
        })

    # Check HTTPS certificate
    if url.startswith("https://") and not check_https_certificate(url):
        vulnerabilities.append({
            "type": "Invalid HTTPS Certificate",
            "message": "The HTTPS certificate is invalid or expired."
        })

    # Check for missing security headers
    missing_headers = check_security_headers(url)
    for header in missing_headers:
        vulnerabilities.append({
            "type": "Missing Security Header",
            "message": f"Missing security header: {header}."
        })

    # Check for insecure cookies
    insecure_cookies = check_insecure_cookies(url)
    for cookie_message in insecure_cookies:
        vulnerabilities.append({
            "type": "Insecure Cookie",
            "message": cookie_message
        })

    # Check for mixed content
    mixed_content = detect_mixed_content(url)
    if mixed_content:
        vulnerabilities.append({
            "type": "Mixed Content",
            "message": f"Insecure resources loaded over HTTP: {', '.join(mixed_content)}."
        })

    # Check for clickjacking
    if detect_clickjacking(url):
        vulnerabilities.append({
            "type": "Clickjacking",
            "message": "Missing headers to prevent clickjacking (X-Frame-Options or Content-Security-Policy)."
        })

    # Perform port scan
    open_ports = scan_ports(host)
    if open_ports:
        vulnerabilities.append({
            "type": "Open Ports",
            "message": f"Open ports detected: {', '.join(map(str, open_ports))}."
        })

    return vulnerabilities

def generate_report(vulnerabilities, output_format="text"):
    """
    Generate a report of detected vulnerabilities.
    """
    if output_format == "json":
        return json.dumps(vulnerabilities, indent=2)
    else:
        report = []
        for vuln in vulnerabilities:
            report.append(f"{vuln['type']}: {vuln['message']}")
        return "\n".join(report)

def main():
    parser = argparse.ArgumentParser(description="CodeSentry")
    parser.add_argument("--file", help="Path to the file to analyze (Python, JavaScript, Java, or Ruby)")
    parser.add_argument("--url", help="URL of the website to scan for vulnerabilities")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    args = parser.parse_args()

    vulnerabilities = []

    if args.file:
        if not Path(args.file).exists():
            logging.error(f"Error: File '{args.file}' not found.")
            return
        vulnerabilities = analyze_code(args.file)

    elif args.url:
        vulnerabilities = scan_website(args.url)

    else:
        logging.error("Error: Please specify either a file (--file) or a URL (--url).")
        return

    report = generate_report(vulnerabilities, args.format)
    print(report)

if __name__ == "__main__":
    main() 
