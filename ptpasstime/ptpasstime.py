#!/usr/bin/python3
"""
    Copyright (c) 2026 Penterep Security s.r.o.

    ptpasstime - password comparison timing attack tester

    ptpasstime is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ptpasstime is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with ptpasstime.  If not, see <https://www.gnu.org/licenses/>.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import statistics
import string
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlparse, urlunparse

import requests
from scipy.stats import mannwhitneyu

sys.path.append(__file__.rsplit("/", 1)[0])

from _version import __version__
from ptlibs import ptjsonlib, ptprinthelper, ptmisclib, ptnethelper
from ptlibs.ptprinthelper import ptprint

DEFAULT_PLACEHOLDER = "INJECT"
DEFAULT_WRONG_CHAR = "X"
DEFAULT_CHARSET = string.ascii_lowercase + string.digits + string.ascii_uppercase


@dataclass
class RequestSpec:
    method: str
    url: str
    headers: dict[str, str]
    body_template: str | None


@dataclass
class AttemptResult:
    attempt_type: str
    password: str
    median_ms: float
    samples_ms: list[float]


class PtPassTime:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.ptjsonlib = ptjsonlib.PtJsonLib()
        self.spec = self._build_request_spec()

    def run(self) -> None:
        if self.args.brute_force:
            self._run_brute_force()
        else:
            self._run_detection()

    def _build_request_spec(self) -> RequestSpec:
        if self.args.request_file:
            return self._spec_from_request_file(self.args.request_file)

        if not self.args.url:
            raise ValueError("URL is required when --request-file is not used.")
        if self.args.data is None:
            raise ValueError("POST data (-d) is required when --request-file is not used.")

        return RequestSpec(
            method="POST",
            url=self.args.url,
            headers=self.args.headers.copy(),
            body_template=self.args.data,
        )

    def _spec_from_request_file(self, request_file_or_b64: str) -> RequestSpec:
        raw = self._load_request_source(request_file_or_b64)
        text = raw.decode("utf-8", errors="replace").replace("\r\n", "\n")
        lines = text.split("\n")
        if not lines or not lines[0].strip():
            raise ValueError("Invalid request input: missing request line.")

        first = lines[0].strip()
        parts = first.split()
        if len(parts) < 2:
            raise ValueError("Invalid request line, expected: METHOD PATH HTTP/x.y")

        method = parts[0].upper()
        target = parts[1]
        headers: dict[str, str] = {}
        body_idx = len(lines)
        for i in range(1, len(lines)):
            line = lines[i]
            if line == "":
                body_idx = i + 1
                break
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()

        body_text = "\n".join(lines[body_idx:]) if body_idx < len(lines) else ""
        url = self._build_url_from_target(target, headers)
        merged_headers = self.args.headers.copy()
        merged_headers.update(headers)

        return RequestSpec(
            method=method,
            url=url,
            headers=merged_headers,
            body_template=body_text if body_text else None,
        )

    def _load_request_source(self, value: str) -> bytes:
        path = Path(value)
        if path.is_file():
            return path.read_bytes()
        try:
            return base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(
                "Invalid --request-file value. Use an existing file path or base64 encoded request."
            ) from exc

    def _build_url_from_target(self, target: str, headers: dict[str, str]) -> str:
        if target.startswith(("http://", "https://")):
            return target

        host = headers.get("Host", "").strip()
        if not host:
            raise ValueError("Raw request contains relative path but missing Host header.")
        base = self.args.url if self.args.url else f"http://{host}"
        parsed = urlparse(base if "://" in base else f"http://{base}")
        path = target if target.startswith("/") else f"/{target}"
        return urlunparse((parsed.scheme, host, path, "", "", ""))

    def _build_body(self, password: str) -> str | bytes | dict[str, str] | None:
        if self.spec.body_template is None:
            return None
        if self.args.placeholder not in self.spec.body_template:
            raise ValueError(
                f"Placeholder '{self.args.placeholder}' not found in request body. "
                "Use -d 'username=admin&password=INJECT' or include INJECT in --request-file."
            )
        body = self.spec.body_template.replace(self.args.placeholder, password)
        content_type = self.spec.headers.get("Content-Type", "").lower()
        if "application/x-www-form-urlencoded" in content_type or (
            not content_type and "=" in body and not body.strip().startswith("{")
        ):
            return dict(parse_qsl(body, keep_blank_values=True))
        return body.encode("utf-8")

    def _send_timed_request(self, password: str) -> float:
        start = time.perf_counter()
        requests.request(
            method=self.spec.method,
            url=self.spec.url,
            headers=self.spec.headers,
            data=self._build_body(password),
            timeout=self.args.timeout,
            proxies=self.args.proxy,
            allow_redirects=self.args.redirects,
            verify=False,
        )
        return (time.perf_counter() - start) * 1000

    def _measure_password(self, attempt_type: str, password: str, repeat: int | None = None) -> AttemptResult:
        n = repeat if repeat is not None else self.args.repeat
        samples: list[float] = []
        errors = 0
        for _ in range(n):
            try:
                samples.append(self._send_timed_request(password))
            except requests.RequestException:
                errors += 1

        if not samples:
            raise RuntimeError(f"All {n} attempts failed for type '{attempt_type}'.")

        if errors and not self.args.json:
            ptprint(
                f"{attempt_type}: {errors}/{n} requests failed",
                "WARNING",
                condition=True,
            )

        return AttemptResult(
            attempt_type=attempt_type,
            password=password,
            median_ms=statistics.median(samples),
            samples_ms=samples,
        )

    def _is_server_vulnerable(self) -> bool:
        """Quick pre-check with up to 5 repeats. Returns True if timing side-channel detected."""
        quick_n = min(self.args.repeat, 5)
        passwords = self._build_test_passwords()
        baseline = self._measure_password("all_wrong", passwords["all_wrong"], repeat=quick_n)
        last = self._measure_password("last_wrong", passwords["last_wrong"], repeat=quick_n)
        vuln, _ = self._is_vulnerable(baseline, last)
        return vuln

    def _build_test_passwords(self) -> dict[str, str]:
        password = self.args.password
        length = len(password)
        wrong = self.args.wrong_char

        if length == 0:
            raise ValueError("Password (-p) must not be empty.")

        all_wrong = wrong * length
        first_wrong = wrong + password[1:] if length > 1 else wrong
        last_wrong = password[:-1] + wrong if length > 1 else wrong

        return {
            "all_wrong": all_wrong,
            "first_wrong": first_wrong,
            "last_wrong": last_wrong,
        }

    def _threshold_ms(self, baseline_ms: float) -> float:
        percent_threshold = baseline_ms * (self.args.threshold_percent / 100)
        return max(percent_threshold, self.args.threshold_ms)

    def _is_vulnerable(self, baseline: AttemptResult, candidate: AttemptResult) -> tuple[bool, float]:
        """Return (is_vulnerable, p_value).

        Uses Mann-Whitney U test for statistical significance combined with a
        minimum median-delta guard, so that pure network jitter does not
        trigger false positives on low-latency connections.
        """
        delta = candidate.median_ms - baseline.median_ms
        threshold = self._threshold_ms(baseline.median_ms)
        if delta <= threshold:
            return False, 1.0

        if len(baseline.samples_ms) < 3 or len(candidate.samples_ms) < 3:
            return True, 0.0

        try:
            _, p_value = mannwhitneyu(
                candidate.samples_ms,
                baseline.samples_ms,
                alternative="greater",
            )
        except ValueError:
            return True, 0.0

        p_value = float(p_value)
        return p_value < self.args.p_value, p_value

    LABELS: dict[str, str] = {
        "all_wrong":   "wrong password",
        "first_wrong": "first char off",
        "last_wrong":  "last char off",
    }

    _C_RESET  = "\033[0m"
    _C_CYAN   = "\033[96m"
    _C_RED    = "\033[31m"
    _C_GREEN  = "\033[92m"
    _C_YELLOW = "\033[93m"
    _C_GREY   = "\033[90m"

    def _print_separator(self, width: int = 68) -> None:
        print(f"    {'─' * width}")

    def _run_detection(self) -> None:
        passwords = self._build_test_passwords()
        results: list[AttemptResult] = []
        not_json = not self.args.json
        W = 18

        if not_json:
            ptprint(f"Target : {self.spec.method} {self.spec.url}", "TITLE", condition=True, colortext=True)
            if self.args.verbose:
                ptprint(
                    f"Password : {len(self.args.password)} chars  |  "
                    f"repeats: {self.args.repeat}  |  "
                    f"threshold: {self.args.threshold_percent}%  |  "
                    f"p ≤ {self.args.p_value}",
                    "ADDITIONS", condition=True, indent=4, colortext=True,
                )
                ptprint(" ", "ADDITIONS", condition=True)
                ptprint(f"{'Scenario':<{W}}  {'Avg (ms)':>9}   Samples", "ADDITIONS", condition=True, indent=4, colortext=True)
                ptprint("─" * 68, "ADDITIONS", condition=True, indent=4, colortext=True)

        for attempt_type, candidate in passwords.items():
            result = self._measure_password(attempt_type, candidate)
            results.append(result)
            if not_json and self.args.verbose:
                samples_str = "  ".join(f"{s:.1f}" for s in result.samples_ms)
                label = self.LABELS[attempt_type]
                ptprint(f"{label:<{W}}  {result.median_ms:>9.2f}   {samples_str}", "ADDITIONS", condition=True, indent=4, colortext=True)

        baseline = next(r for r in results if r.attempt_type == "all_wrong")
        first = next(r for r in results if r.attempt_type == "first_wrong")
        last = next(r for r in results if r.attempt_type == "last_wrong")

        threshold = self._threshold_ms(baseline.median_ms)
        first_vuln, first_p = self._is_vulnerable(baseline, first)
        last_vuln, last_p = self._is_vulnerable(baseline, last)
        vulnerable = first_vuln or last_vuln

        if not_json:
            print()
            print(f"    {'Scenario':<{W}}  {'Δ (ms)':>9}   {'p-value':>8}   Result")
            self._print_separator(50)

            for result, vuln, p in (
                (first, first_vuln, first_p),
                (last,  last_vuln,  last_p),
            ):
                delta = result.median_ms - baseline.median_ms
                label = self.LABELS[result.attempt_type]
                color = self._C_RED if vuln else self._C_GREEN
                marker = "[✗] VULNERABLE" if vuln else "[✓] OK"
                print(f"    {label:<{W}}  {delta:>+9.2f}   {p:>8.3f}   {color}{marker}{self._C_RESET}")

            print()
            if vulnerable:
                ptprint(
                    "RESULT: Target is VULNERABLE to a password timing side-channel attack.",
                    "VULN", condition=True, colortext=True,
                )
            else:
                ptprint(
                    "RESULT: No timing side-channel detected on this target.",
                    "OK", condition=True, colortext=True,
                )

        self._emit_json_detection(results, vulnerable, first_vuln, last_vuln, threshold, first_p, last_p)

    def _pick_wrong_char(self, reference: str) -> str:
        for candidate in (DEFAULT_WRONG_CHAR, "#", "!", "0", "z"):
            if candidate not in reference:
                return candidate
        return "Q"

    def _build_bruteforce_candidate(self, prefix: str, char: str, total_len: int) -> str:
        wrong = self._pick_wrong_char(self.args.password)
        suffix_len = total_len - len(prefix) - 1
        if suffix_len < 0:
            raise ValueError("Brute-force prefix longer than target password length.")
        return prefix + char + (wrong * suffix_len)

    def _run_brute_force(self) -> None:
        total_len = len(self.args.password)
        known = ""
        not_json = not self.args.json
        W = 8

        if not_json:
            ptprint(
                f"{'Target':<{W}}: {self.spec.method} {self.spec.url}",
                "TITLE", condition=True, colortext=True,
            )
            ptprint("", "INFO", condition=True)
            ptprint(
                f"{'Mode':<{W}}  brute-force",
                    condition=True, indent=4,
            )
            ptprint(
                f"{'Password':<{W}}  {total_len} chars  |  "
                f"charset: {len(self.args.charset)}  |  "
                f"repeats: {self.args.repeat}", condition=True, indent=4,
            )
            ptprint("", "INFO", condition=True,)
            ptprint("Running vulnerability pre-check...", "INFO", condition=True)

        server_vulnerable = self._is_server_vulnerable()

        if not server_vulnerable:
            if not_json:
                ptprint("", "TEXT", condition=True)
                ptprint(
                    "WARNING: Target does not appear vulnerable to timing attacks.",
                    "WARNING", condition=True, colortext=True,
                )
                ptprint(
                    "Brute-force results may be unreliable.",
                    "WARNING", condition=True, indent=4, colortext=True,
                )
                ptprint("", "TEXT", condition=True)
                try:
                    answer = input("Continue anyway? [y/N] ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    answer = "n"
                if answer != "y":
                    ptprint("Aborted.", "INFO", condition=True)
                    return
                ptprint("", "TEXT", condition=True)
            else:
                return

        if not_json:
            ptprint("Recovering password...", "INFO", condition=True)

        for position in range(total_len):
            best_char = ""
            best_median = -1.0
            char_results: list[tuple[str, float]] = []

            for char in self.args.charset:
                candidate = self._build_bruteforce_candidate(known, char, total_len)
                result = self._measure_password(f"pos{position}_{char}", candidate)
                char_results.append((char, result.median_ms))
                if result.median_ms > best_median:
                    best_median = result.median_ms
                    best_char = char

            known += best_char

            if not_json:
                pos_label = f"Position {position + 1:>{len(str(total_len))}}/{total_len}"
                line = f"{pos_label}   →   '{best_char}'   {best_median:.2f} ms"
                if self.args.verbose:
                    top = sorted(char_results, key=lambda item: item[1], reverse=True)[:5]
                    top_str = "  ".join(f"{c}:{t:.1f}" for c, t in top)
                    line += f"   top: {top_str}"
                ptprint(line, "ADDITIONS", condition=True, indent=4, colortext=True)

        matches = known == self.args.password
        if not_json:
            ptprint("", "TEXT", condition=True)
            ptprint(f"Recovered password: {known}", "TITLE", condition=True, colortext=True)
            ptprint(
                f"Matches supplied password (-p): {'YES' if matches else 'NO'}",
                "OK" if matches else "WARNING",
                condition=True, colortext=True,
            )

        self._emit_json_bruteforce(known, matches)

    def _emit_json_detection(
        self,
        results: list[AttemptResult],
        vulnerable: bool,
        first_vuln: bool,
        last_vuln: bool,
        threshold: float,
        first_p: float,
        last_p: float,
    ) -> None:
        if vulnerable:
            self.ptjsonlib.add_vulnerability("PTV-WEB-AUTH-TIMING")

        if not vulnerable:
            return

        self.ptjsonlib.add_vulnerability("PTV-WEB-AUTH-TIMING")
        self.ptjsonlib.add_properties(
            {
                "mode": "detection",
                "method": self.spec.method,
                "url": self.spec.url,
                "passwordLength": len(self.args.password),
                "repeatCount": self.args.repeat,
                "thresholdPercent": self.args.threshold_percent,
                "thresholdMs": self.args.threshold_ms,
                "pValueThreshold": self.args.p_value,
                "effectiveThresholdMs": round(threshold, 3),
                "firstWrongVulnerable": first_vuln,
                "firstWrongPValue": round(first_p, 4),
                "lastWrongVulnerable": last_vuln,
                "lastWrongPValue": round(last_p, 4),
                "attempts": [
                    {
                        "type": result.attempt_type,
                        "passwordSample": result.password,
                        "medianMs": round(result.median_ms, 3),
                        "samplesMs": [round(sample, 3) for sample in result.samples_ms],
                    }
                    for result in results
                ],
            }
        )
        self.ptjsonlib.set_status("finished")
        ptprint(self.ptjsonlib.get_result_json(), "", self.args.json)

    def _emit_json_bruteforce(
        self,
        recovered: str,
        matches: bool,
    ) -> None:
        if matches:
            self.ptjsonlib.add_vulnerability("PTV-WEB-AUTH-TIMING")

        self.ptjsonlib.add_properties(
            {
                "mode": "brute-force",
                "method": self.spec.method,
                "url": self.spec.url,
                "recoveredPassword": recovered,
                "matchesSuppliedPassword": matches,
            }
        )
        self.ptjsonlib.set_status("finished")
        ptprint(self.ptjsonlib.get_result_json(), "", self.args.json)


def get_help():
    return [
        {
            "description": [
                "Test whether a login endpoint compares passwords in constant time.",
                "Detects timing side-channels exploitable for password recovery.",
            ]
        },
        {"usage": ["ptpasstime <options>"]},
        {
            "usage_example": [
                "ptpasstime -u http://127.0.0.1:5000/login/vulnerable "
                "-d 'username=admin&password=INJECT' -p correctPassword -n 15",
                "ptpasstime -u http://127.0.0.1:5000/login/vulnerable "
                "-d 'username=admin&password=INJECT' -p correctPassword --brute-force",
                "ptpasstime --request-file login.txt -p correctPassword -n 20",
            ]
        },
        {
            "options": [
                ["-u", "--url", "<url>", "Login endpoint URL"],
                ["-d", "--data", "<post-data>", "POST body with INJECT placeholder for password"],
                ["-f", "--request-file", "<file|base64>", "Raw HTTP request file (alternative to -d)"],
                ["-p", "--password", "<password>", "Known/guessed correct password (reference length and chars)"],
                ["-n", "--repeat", "<n>", "Number of repetitions per attempt (default 10)"],
                ["", "--brute-force", "", "Recover password character-by-character via timing"],
                ["", "--placeholder", "<text>", "Password placeholder in request body (default INJECT)"],
                ["", "--threshold-percent", "<pct>", "Relative timing threshold in percent (default 15)"],
                ["", "--threshold-ms", "<ms>", "Minimum absolute timing threshold in ms (default 1)"],
                ["", "--p-value", "<p>", "Mann-Whitney significance threshold (default 0.01)"],
                ["", "--charset", "<chars>", "Character set for --brute-force mode"],
                ["", "--wrong-char", "<char>", "Wrong character for padding attempts (default X)"],
                ["", "--proxy", "<proxy>", "Set proxy (e.g. http://127.0.0.1:8080)"],
                ["-T", "--timeout", "<seconds>", "Set timeout (default 10)"],
                ["-a", "--user-agent", "<a>", "Set User-Agent header"],
                ["-c", "--cookie", "<cookie>", "Set cookie"],
                ["-H", "--headers", "<header:value>", "Set custom header(s)"],
                ["-r", "--redirects", "", "Follow redirects (default False)"],
                ["-C", "--cache", "", "Cache compatibility flag"],
                ["-vv", "--verbose", "", "Show sample timings (additions output)"],
                ["-v", "--version", "", "Show script version and exit"],
                ["-h", "--help", "", "Show this help message and exit"],
                ["-j", "--json", "", "Output in JSON format"],
            ]
        },
    ]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False, description=f"{SCRIPTNAME} <options>")
    parser.add_argument("-u", "--url", type=str)
    parser.add_argument("-d", "--data", type=str, default=None)
    parser.add_argument("-f", "--request-file", type=str, default=None)
    parser.add_argument("-p", "--password", type=str, required=True)
    parser.add_argument("-n", "--repeat", type=int, default=10)
    parser.add_argument("--brute-force", action="store_true")
    parser.add_argument("--placeholder", type=str, default=DEFAULT_PLACEHOLDER)
    parser.add_argument("--threshold-percent", type=float, default=15.0)
    parser.add_argument("--threshold-ms", type=float, default=1.0)
    parser.add_argument("--p-value", type=float, default=0.01)
    parser.add_argument("--charset", type=str, default=DEFAULT_CHARSET)
    parser.add_argument("--wrong-char", type=str, default=DEFAULT_WRONG_CHAR)
    parser.add_argument("--proxy", type=str)
    parser.add_argument("-T", "--timeout", type=int, default=10)
    parser.add_argument("-a", "--user-agent", type=str, default="Penterep Tools")
    parser.add_argument("-c", "--cookie", type=str)
    parser.add_argument("-H", "--headers", type=ptmisclib.pairs, nargs="+")
    parser.add_argument("-vv", "--verbose", action="store_true")
    parser.add_argument("-r", "--redirects", action="store_true")
    parser.add_argument("-C", "--cache", action="store_true")
    parser.add_argument("-j", "--json", action="store_true")
    parser.add_argument("-v", "--version", action="version", version=f"{SCRIPTNAME} {__version__}")

    parser.add_argument("--socket-address", type=str, default=None)
    parser.add_argument("--socket-port", type=str, default=None)
    parser.add_argument("--process-ident", type=str, default=None)

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)

    args = parser.parse_args()

    if not args.url and not args.request_file:
        parser.error("at least one of --url or --request-file is required")
    if not args.request_file and args.data is None:
        parser.error("-d/--data is required when --request-file is not used")
    if args.repeat < 1:
        parser.error("--repeat must be >= 1")
    if len(args.wrong_char) != 1:
        parser.error("--wrong-char must be a single character")
    if not args.charset:
        parser.error("--charset must not be empty")

    if args.proxy:
        args.proxy = {"http": args.proxy, "https": args.proxy}
    else:
        args.proxy = {}

    args.headers = ptnethelper.get_request_headers(args)
    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json)
    return args


def main() -> None:
    global SCRIPTNAME
    SCRIPTNAME = "ptpasstime"
    requests.packages.urllib3.disable_warnings()
    args = parse_args()
    try:
        script = PtPassTime(args)
        script.run()
    except (ValueError, RuntimeError) as exc:
        ptprint(str(exc), "ERROR", condition=not args.json)
        sys.exit(1)


if __name__ == "__main__":
    main()
