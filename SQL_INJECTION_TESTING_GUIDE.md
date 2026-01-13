# SQL Injection Test Payloads and Usage Guide

## Quick Start - Testing for SQL Injection

### 1. Using the Web Interface

1. **Start the Backend Server:**
   ```bash
   cd Backend
   python server.py
   ```

2. **Start the Frontend:**
   ```bash
   cd Frontend
   npm run dev
   ```

3. **Open the Application:**
   - Go to http://localhost:5173
   - Scroll down to the "SQL Injection Tester" section

4. **Test with a Safe Vulnerable Site:**
   - Click "Load Test Site" button
   - Or manually enter: `http://testphp.vulnweb.com/artists.php?artist=1`
   - Parameter: `artist`
   - Method: `GET`
   - Click "Scan for SQL Injection"

---

## Simple Test Payloads

### Basic Detection Payloads
These are simple payloads to quickly detect SQL injection:

```
'
"
' OR '1'='1
" OR "1"="1
' OR 1=1--
" OR 1=1--
admin'--
```

### How to Use:
1. Find a URL with a parameter (e.g., `?id=1`)
2. Replace the value with a payload
3. Example: `http://example.com/page.php?id=1'`

---

## Test Sites (Legal & Safe)

### 1. **testphp.vulnweb.com** (Recommended)
```
URL: http://testphp.vulnweb.com/artists.php
Parameter: artist
Example: http://testphp.vulnweb.com/artists.php?artist=1
```
**Status:** ✅ Intentionally vulnerable, safe to test

### 2. **Your Own Local Test Server**
Set up DVWA (Damn Vulnerable Web Application) locally:
```bash
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```

---

## Understanding the Results

### Vulnerability Status

#### ✅ SAFE (Green)
- **Meaning:** No SQL injection vulnerabilities found
- **Example Output:**
  ```
  SQL Injection Protected
  No SQL injection vulnerabilities found
  ```

#### ❌ VULNERABLE (Red)
- **Meaning:** SQL injection vulnerability detected
- **Example Output:**
  ```
  SQL Injection Vulnerable
  5 vulnerabilities detected
  
  Vulnerable Parameters: artist, id
  
  Detected Attack Types:
  - Error-based SQL Injection: 2
  - Union-based SQL Injection: 2
  - Boolean-based SQL Injection: 1
  ```

---

## Quick Command Line Test

Run this in the Backend directory:

```bash
python test_sqli.py
```

This will automatically test the known vulnerable site and show results.

---

## Vulnerability Types Explained

### 1. **Error-based SQL Injection**
- SQL errors are returned in the response
- Example: `MySQL syntax error near...`
- **Severity:** HIGH

### 2. **Union-based SQL Injection**
- Attacker can retrieve data from other tables
- Uses SQL UNION operator
- **Severity:** CRITICAL

### 3. **Boolean-based SQL Injection**
- True/false conditions affect page response
- Slower but effective for blind injection
- **Severity:** HIGH

### 4. **Time-based SQL Injection**
- Uses database sleep functions
- Detects vulnerability through response delay
- **Severity:** HIGH

---

## Example Test Flow

### Step 1: Start Testing
```
URL: http://testphp.vulnweb.com/artists.php?artist=1
Parameter: artist
Method: GET
```

### Step 2: Scanner Tests Payloads
The scanner automatically tests:
- 16 basic payloads
- 10 time-based payloads
- 12 union-based payloads
- 6 error-based payloads
- 10 boolean-based payloads

**Total:** ~54 payloads tested automatically

### Step 3: Results Display
```
✅ Scan Complete!

Vulnerabilities Found: 5
Vulnerable Parameters: artist
Attack Types: Error-based (2), Union-based (2), Boolean-based (1)

Example Payload: ' OR '1'='1
Evidence: SQL error pattern detected
```

---

## Safety & Legal Notice

⚠️ **IMPORTANT:**
- Only test websites you own
- Or use designated test sites like testphp.vulnweb.com
- Unauthorized testing is ILLEGAL
- This tool is for educational purposes only

---

## Troubleshooting

### Backend Server Not Starting?
```bash
cd Backend
pip install -r requirements.txt
python server.py
```

### Frontend Not Connecting?
- Check if backend is running on port 5000
- Check CORS settings
- Verify the API URL in `Frontend/src/services/api.js`

### No Vulnerabilities Found?
- Some sites have WAF protection
- Try the test site: testphp.vulnweb.com
- Check if the parameter name is correct

---

## API Usage (For Developers)

### Endpoint
```
POST http://localhost:5000/api/scan-sqli
```

### Request Body
```json
{
  "url": "http://testphp.vulnweb.com/artists.php?artist=1",
  "param": "artist",
  "method": "GET"
}
```

### Response
```json
{
  "status": "success",
  "sqli_scan": {
    "total_vulnerabilities": 5,
    "vulnerable_params": ["artist"],
    "vulnerabilities": [...],
    "vulnerability_types": {
      "Error-based SQL Injection": 2,
      "Union-based SQL Injection": 2
    }
  }
}
```

---

## What Happens After Detection?

If vulnerabilities are found:

1. **Immediate Action:**
   - Document all findings
   - Do NOT attempt to exploit further
   - Report to website owner if ethical testing

2. **Remediation Steps:**
   - Use prepared statements/parameterized queries
   - Implement input validation
   - Add WAF protection
   - Regular security audits

---

## Simple Payload Reference Card

| Payload | Purpose | Expected Result |
|---------|---------|----------------|
| `'` | Test for SQL error | Error message or different response |
| `' OR '1'='1` | Bypass authentication | Always true condition |
| `' UNION SELECT NULL--` | Test for union injection | Different response or error |
| `' AND SLEEP(5)--` | Test for time-based | 5 second delay in response |
| `' AND 1=2--` | Test for boolean-based | Different response than 1=1 |

---

**Remember:** Always test responsibly and legally! 🔒
