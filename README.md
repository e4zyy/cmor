# CMOR — CORS Misconfiguration & Open Redirect Scanner

**CMOR** is a lightweight, thread-safe Python scanner that checks a target list for:

- CORS misconfigurations
- Exposed `.git/config` files
- Exposed `.env` files
- Open redirects through common redirect parameters

It is designed for **authorized security testing**, bug bounty work, and controlled assessments. Only run it against systems you are explicitly permitted to test.

> ⚠️ **Important:** Unauthorized scanning, testing, or exploitation of websites is illegal and unethical. Always obtain written permission or follow the target’s official bug bounty scope and rules.

---

## How It Works

CMOR reads a list of URLs from a text file, filters them against its configured scope, and then performs a small number of non-destructive HTTP checks.

### 1. Target Loading and Scope Control

The scanner loads URLs from `targets.txt` by default.

Example:

```text
[https://example.com/](https://example.com/)
[https://api.example.com/](https://api.example.com/)
[https://sub.example.com/path](https://sub.example.com/path)
```

If a line does not include a scheme, CMOR automatically adds `https://`.

For example:

```text
example.com
```

becomes:

```text
[https://example.com](https://example.com)
```

CMOR then checks every URL against its configured allowlist and denylist.

```python
ALLOWED_DOMAINS = ["example.com"]
EXCLUDED_DOMAINS = ["://example.com", "://example.com"]
```

- `ALLOWED_DOMAINS` controls which domains may be scanned.
- `EXCLUDED_DOMAINS` controls which domains must be skipped.
- Subdomains of allowed domains are accepted.
- URLs outside the allowed scope are skipped.

Example:

```text
[https://example.com/](https://example.com/)          → in scope
[https://api.example.com/](https://api.example.com/)      → in scope
[https://evil-test.com/](https://evil-test.com/)        → not allowed
```

### 2. CORS Misconfiguration Check

For each in-scope URL, CMOR sends an HTTP request with a controlled external `Origin` header:

```http
Origin: [https://evil-test.com](https://evil-test.com)
```

It then checks the response for these headers:

```http
Access-Control-Allow-Origin: [https://evil-test.com](https://evil-test.com)
Access-Control-Allow-Credentials: true
```

A finding is reported if the server reflects the attacker-controlled origin **and** allows credentials.

This can indicate a potentially serious CORS misconfiguration because it may allow another origin to make credentialed cross-origin requests.

Example vulnerable response:

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: [https://evil-test.com](https://evil-test.com)
Access-Control-Allow-Credentials: true
```

CMOR records this as:

```text
CORS Misconfiguration
```

### 3. Sensitive File Checks

CMOR checks the root of each unique origin for two common exposed files:

| Path | Check | Severity |
|---|---|---|
| `/.git/config` | Looks for `[core]` in the response body | Medium |
| `/.env` | Looks for environment-variable-style content | Medium |

Example request:

```text
[https://example.com/.git/config](https://example.com/.git/config)
[https://example.com/.env](https://example.com/.env)
```

For `/.git/config`, CMOR considers the file exposed if the response contains:

```text
[core]
```

For `/.env`, CMOR rejects obvious HTML catch-all pages and only reports responses that contain configuration-style lines such as:

```text
APP_ENV=production
DB_PASSWORD=example
```

The scanner only reads the first 512 bytes of the response body to reduce bandwidth usage.

### 4. Open Redirect Check

CMOR looks for common redirect parameters in URLs:

```python
REDIRECT_PARAMS = ("next", "url", "redirect", "returnto")
```

For example, if a target URL is:

```text
[https://example.com/login?next=/dashboard](https://example.com/login?next=/dashboard)
```

CMOR replaces the redirect parameter value with its canary domain:

```text
[https://example.com/login?next=[https://example.org](https://example.org)](https://example.com/login?next=[https://example.org](https://example.org))
```

It then sends the request and checks whether the server responds with a redirect status code:

```text
301, 302, 303, 307, 308
```

If the `Location` header points to the canary domain, CMOR reports an open redirect.

Example vulnerable response:

```http
HTTP/1.1 302 Found
Location: [https://example.org](https://example.org)
```

The canary domain is configured as:

```python
REDIRECT_CANARY = "[https://example.org](https://example.org)"
```

`example.org` is a documentation example domain and should not be relied upon for production testing or monitoring. [1]

### 5. Rate Limiting and Backoff

CMOR is designed to be polite to targets.

It uses:

- A global rate limit of `3` requests per second by default
- Random jitter between requests
- A cooldown after repeated `403` or `429` responses
- Support for the `Retry-After` response header when present

Relevant configuration:

```python
MAX_RPS = 3
JITTER_MIN, JITTER_MAX = 0.05, 0.20
BACKOFF_THRESHOLD = 3
BACKOFF_PAUSE = 30.0
TIMEOUT = 15
```

If CMOR receives three consecutive `403` or `429` responses, it pauses all requests for 30 seconds by default. If the server provides a numeric `Retry-After` value, CMOR uses that value instead.

This helps reduce the chance of triggering rate limits or disrupting the target.

### 6. Concurrency

CMOR uses Python’s `ThreadPoolExecutor`.

By default, it runs with:

```text
4 worker threads
```

However, the rate limiter is global. Increasing workers does **not** increase the request rate beyond `MAX_RPS`; it only allows multiple checks to wait for available request slots.

Example:

```bash
python3 cmor.py -w 8
```

This uses 8 worker threads, but still keeps the global request rate at approximately 3 requests per second.

---

## Requirements

Install Python dependencies:

```bash
pip install requests
```

CMOR requires:

- Python 3.10 or newer
- `requests`

---

## Files

```text
cmor.py
targets.txt
findings.json
README.md
```

| File | Purpose |
|---|---|
| `cmor.py` | Main scanner script |
| `targets.txt` | Input file containing target URLs |
| `findings.json` | Default JSON output file |
| `README.md` | Documentation |

---

## Usage

### Basic Scan

Create `targets.txt`:

```text
[https://example.com/](https://example.com/)
[https://api.example.com/](https://api.example.com/)
```

Run CMOR:

```bash
python3 cmor.py
```

This uses the default settings:

```text
targets.txt
findings.json
4 workers
```

### Specify a Target File

```bash
python3 cmor.py -t my-targets.txt
```

### Specify an Output File

```bash
python3 cmor.py -o results.json
```

### Change Worker Count

```bash
python3 cmor.py -w 8
```

### Full Example

```bash
python3 cmor.py -t targets.txt -o findings.json -w 4
```

---

## Command-Line Options

| Option | Default | Description |
|---|---|---|
| `-t`, `--targets` | `targets.txt` | Input file containing target URLs |
| `-o`, `--output` | `findings.json` | Output JSON file |
| `-w`, `--workers` | `4` | Number of concurrent worker threads |

---

## Example Target File

```text
# Allowed targets
[https://example.com/](https://example.com/)
[https://api.example.com/](https://api.example.com/)
[https://app.example.com/login?next=/dashboard](https://app.example.com/login?next=/dashboard)

# Comments and blank lines are ignored
```

CMOR will skip URLs that are not in the configured allowlist.

---

## Example Output

When a finding is detected, CMOR prints something like:

```text
  [FOUND] CORS Misconfiguration (200) [https://example.com/api/](https://example.com/api/)
         -> ACAO=[https://evil-test.com](https://evil-test.com) ACAC=true
```

or:

```text
  [FOUND] Open Redirect (302) [https://example.com/login?next=https%3A%2F%2Fexample.org](https://example.com/login?next=https%3A%2F%2Fexample.org)
         -> Location: [https://example.org](https://example.org)
```

or:

```text
  [FOUND] Exposed .env (200) [https://example.com/.env](https://example.com/.env)
         -> APP_ENV=production DB_PASSWORD=example
```

---

## JSON Output Format

CMOR saves results to a JSON file.

Example:

```json
{
  "tool": "CMOR",
  "version": "1.0",
  "author": "coded by e4zyy | NOEL BUNSIAU",
  "generated": "2026-11-26T13:58:00+00:00",
  "scope": {
    "allow": [
      "example.com"
    ],
    "deny": [
      "://example.com",
      "://example.com"
    ]
  },
  "stats": {
    "targets": 2,
    "requests": 6,
    "backoff_trips": 0,
    "elapsed_s": 4.2
  },
  "findings": [
    {
      "url": "[https://example.com/api/](https://example.com/api/)",
      "type": "CORS Misconfiguration",
      "severity": "low",
      "status_code": 200,
      "evidence": "ACAO=[https://evil-test.com](https://evil-test.com) ACAC=true",
      "timestamp": "2026-11-26T13:58:01+00:00"
    }
  ]
}
```

---

## Configuration

You can customize the scanner by editing the configuration section at the top of `cmor.py`.

### Change Allowed Domains

```python
ALLOWED_DOMAINS = ["example.com"]
```

Example:

```python
ALLOWED_DOMAINS = ["example.com", "example.org"]
```

### Change Excluded Domains

```python
EXCLUDED_DOMAINS = ["://example.com", "://example.com"]
```

### Change CORS Test Origin

```python
EVIL_ORIGIN = "[https://evil-test.com](https://evil-test.com)"
```

Use a domain you control or one approved by the target program.

### Change Redirect Canary

```python
REDIRECT_CANARY = "[https://example.org](https://example.org)"
```

Use a domain you control for reliable open-redirect validation.

### Add Redirect Parameters

```python
REDIRECT_PARAMS = ("next", "url", "redirect", "returnto")
```

Example:

```python
REDIRECT_PARAMS = (
    "next",
    "url",
    "redirect",
    "returnto",
    "continue",
    "goto",
    "destination",
)
```

### Add More Sensitive Files

```python
SENSITIVE_FILES = (
    ("/.git/config", "Exposed .git/config"),
    ("/.env", "Exposed .env"),
)
```

Example:

```python
SENSITIVE_FILES = (
    ("/.git/config", "Exposed .git/config"),
    ("/.env", "Exposed .env"),
    ("/.git/HEAD", "Exposed .git/HEAD"),
    ("/backup.sql", "Exposed SQL backup"),
)
```

### Change Request Rate

```python
MAX_RPS = 3
```

Use a lower value for sensitive or rate-limited targets:

```python
MAX_RPS = 1
```

### Change Timeout

```python
TIMEOUT = 15
```

---

## What CMOR Does Not Do

CMOR does **not**:

- Crawl or discover URLs automatically
- Perform exploitation
- Brute-force directories
- Send destructive requests
- Test every possible redirect parameter
- Validate business impact automatically
- Bypass authentication or access controls

It performs simple, controlled checks based on the URLs you provide.

---

## Responsible Use

Use CMOR only when you have authorization.

Before scanning:

- Review the target’s bug bounty policy
- Confirm the domain is in scope
- Avoid production systems unless explicitly permitted
- Use a low request rate
- Stop immediately if the target requests it
- Do not scan third-party domains
- Do not use canary domains you do not control for real assessments

---

## License

This project is provided for educational and authorized security-testing purposes only.

The author is not responsible for misuse.
