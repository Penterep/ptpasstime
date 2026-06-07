[![penterepTools](https://www.penterep.com/external/penterepToolsLogo.png)](https://www.penterep.com/)

## PTPASSTIME - Password Timing Attack Tester

`ptpasstime` tests whether a login endpoint compares passwords in constant time.
If response time grows with the number of matching prefix characters, the endpoint is
vulnerable to timing attacks.

## How it works

Non-constant-time comparison (`password == input`) stops at the first mismatch:

| Attempt      | Example password   | Response time |
|--------------|--------------------|---------------|
| all_wrong    | `XXXXXXXXXXXXXXXX` | fastest       |
| first_wrong  | `XorrectPassword`  | medium        |
| last_wrong   | `correctPassworX`  | slowest       |

The tool sends each attempt `-n` times and uses the **median** response time.
If `first_wrong` or `last_wrong` exceeds `all_wrong` by a configurable threshold,
the endpoint is reported as vulnerable.

Optional `--brute-force` mode recovers the password character-by-character by picking
the candidate with the longest median response time at each position.

## Installation

```
pip install ptpasstime
```

## Test server

A vulnerable Flask app is included for local testing:

```
pip install -r test_server/requirements.txt
python test_server/vulnerable_app.py
```

Endpoints:

- `POST /login/vulnerable` — early-exit comparison (vulnerable)
- `POST /login/secure` — `hmac.compare_digest` (safe)

Default credentials: `admin` / `correctPassword`

## Usage examples

Detection mode:

```
ptpasstime -u http://127.0.0.1:5000/login/vulnerable \
  -d 'username=admin&password=INJECT' -p correctPassword -n 15
```

Brute-force recovery:

```
ptpasstime -u http://127.0.0.1:5000/login/vulnerable \
  -d 'username=admin&password=INJECT' -p correctPassword --brute-force -n 5
```

Raw request file:

```
ptpasstime -f login.txt -p correctPassword -n 10
```

## Options

```
-u  --url                 <url>            Login endpoint URL
-d  --data                <post-data>      POST body with INJECT placeholder
-f  --request-file        <file|base64>    Raw HTTP request (alternative to -d)
-p  --password            <password>       Reference password (length + validation)
-n  --repeat              <n>              Repetitions per attempt (default 10)
    --brute-force                          Character-by-character recovery mode
    --placeholder         <text>           Password placeholder (default INJECT)
    --threshold-percent   <pct>            Relative threshold % (default 15)
    --threshold-ms        <ms>             Absolute threshold in ms (default 1)
    --charset             <chars>          Charset for brute-force mode
    --wrong-char          <char>           Padding character (default X)
    --proxy               <proxy>          Proxy (e.g. http://127.0.0.1:8080)
-T  --timeout                              Request timeout (default 10)
-c  --cookie              <cookie>         Cookie header
-a  --user-agent          <a>              User-Agent header
-H  --headers             <header:value>   Custom headers
-r  --redirects                            Follow redirects
-j  --json                                 JSON output
-v  --version                              Show version
-h  --help                                 Show help
```

## Dependencies

```
ptlibs
```

## License

Copyright (c) 2026 Penterep Security s.r.o.

ptpasstime is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

## Warning

You are only allowed to run the tool against websites you have permission to test.
Penterep is not responsible for any illegal or malicious use of this code. Be ethical!
