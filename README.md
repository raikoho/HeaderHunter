# HeaderHunter
HTTP Header and Vulnerability Checker for multiple sites - is a Python script for analyzing HTTP headers and detecting potential security vulnerabilities such as CORS issues, CSRF vulnerabilities, clickjacking risks, and more. It provides detailed header information and helps you identify potential weaknesses in your target URLs.

## 🚀 Features
- **Header Analysis**: Displays most of HTTP response headers.
- **Vulnerability Detection**: Highlights possible issues like:
  - CORS misconfigurations
  - Missing `X-Frame-Options`
  - Web Cache Poisoning risks
  - CSRF vulnerabilities
- **Session Cookies Extraction**: Displays session cookies separately.
- **File Support**: Read target URLs from a file.
- **Save Output**: Save analysis results to a file for further review.

---

## 🖥️ Usage
Basic Syntax:

```
python check-headers.py [urls...] [options]
```

Options:

  -full	Show all headers and detected vulnerabilities.
  -voln	Show only detected vulnerabilities.
  -headers	Show all headers excluding cookies.
  -cookie	Show only session cookies.
    -f <file>	Read URLs from a file.
    -o <file>	Save output to a text file.
-h	Display help message.

### Examples:

#### Check a single URL:

```
python check-headers.py https://example.com
```

#### Check URLs from a file:

```
python check-headers.py -f list.txt
```

#### Save results to a file:

```
python check-headers.py -f list.txt -o output.txt
```

#### Display only vulnerabilities:

```
python check-headers.py -f list.txt -voln
```

#### Display only cookies:

```
python check-headers.py https://example.com -cookie
```

## 🛡️ Detected Vulnerabilities

    CORS Misconfigurations: Missing or overly permissive Access-Control-Allow-Origin.
    CSRF Risks: Missing or misconfigured X-Frame-Options.
    Clickjacking: Missing X-Frame-Options or too permissive values.
    Web Cache Poisoning: Detected via X-Cache header.
    SameSite Cookie Issues: Insecure SameSite cookie attributes.
    Cookies Structure. JWT or Base64 etc.

## Instaliation

```
git clone https://github.com/raikoho/HeaderHunter.git
cd HeaderHunter
pip install -r requirements.txt
python3 check-headers.py
```
