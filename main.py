import argparse
import base64
import collections
import csv
import datetime as dt
import hashlib
import io
import math
import json
import os
import pathlib
import re
import ssl
import subprocess
import sys
import tempfile
import stat
import ipaddress
import socket
import urllib.parse

UTC = dt.timezone.utc
PEM = re.compile(rb'-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----', re.S)
DEFAULTS = ['/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem', '/etc/pki/tls/certs/ca-bundle.crt', '/etc/ssl/certs/ca-certificates.crt']
EXTENSIONS = {'.pem', '.crt', '.cer'}


def iso(value):
    return value.isoformat() if value else None


def parse_time(value):
    if not value:
        return None
    try:
        return dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(value), UTC)
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def dn(value):
    return ', '.join(f'{key}={item}' for group in value or () for key, item in group)


def decode(pem):
    with tempfile.NamedTemporaryFile(suffix='.pem') as stream:
        stream.write(pem)
        stream.flush()
        try:
            return ssl._ssl._test_decode_cert(stream.name), None
        except (OSError, ValueError, ssl.SSLError) as error:
            return {}, str(error)


def openssl_details(pem, enabled):
    if not enabled:
        return {}
    try:
        result = subprocess.run(
            ['openssl', 'x509', '-noout', '-text', '-fingerprint', '-sha1'],
            input=pem, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as error:
        return {'openssl_error': str(error)}
    if result.returncode:
        return {'openssl_error': result.stderr.decode('utf-8', 'replace').strip()}
    output = result.stdout.decode('utf-8', 'replace')
    fields = {}
    for key, pattern in {
        'signature_algorithm': r'Signature Algorithm:\s*([^\n]+)',
        'public_key_algorithm': r'Public Key Algorithm:\s*([^\n]+)',
        'public_key_bits': r'Public-Key:\s*\((\d+) bit\)',
        'sha1_fingerprint': r'sha1 Fingerprint=([^\n]+)',
        'subject_key_identifier': r'Subject Key Identifier:\s*\n\s*([^\n]+)',
        'authority_key_identifier': r'Authority Key Identifier:\s*\n\s*([^\n]+)',
    }.items():
        match = re.search(pattern, output, re.I)
        fields[key] = match.group(1).strip() if match else None
    basic = re.search(r'X509v3 Basic Constraints:\s*([^\n]*)\n\s*([^\n]+)', output)
    fields['basic_constraints'] = basic.group(2).strip() if basic else None
    fields['is_ca'] = bool(basic and re.search(r'CA\s*:\s*TRUE', basic.group(2), re.I))
    key_usage = re.search(r'X509v3 Key Usage:\s*([^\n]*)\n\s*([^\n]+)', output)
    fields['key_usage'] = key_usage.group(2).strip() if key_usage else None
    fields['openssl_text'] = output if enabled == 'full' else None
    return fields


def discover(inputs, recursive, max_files):
    found = []
    errors = []
    seen = set()
    for raw in inputs:
        path = pathlib.Path(raw)
        try:
            if path.is_dir():
                iterator = path.rglob('*') if recursive else path.iterdir()
                for item in iterator:
                    if item.suffix.lower() in EXTENSIONS and item.is_file():
                        key = str(item.absolute())
                        if key not in seen:
                            seen.add(key)
                            found.append(item)
                        if len(found) >= max_files:
                            errors.append({'path': str(path), 'error': 'maximum file count reached'})
                            return sorted(found, key=str), errors
            else:
                key = str(path.absolute())
                if key not in seen:
                    seen.add(key)
                    found.append(path)
        except OSError as error:
            errors.append({'path': str(path), 'error': str(error)})
    return sorted(found, key=str), errors


def scan(paths, args):
    now = dt.datetime.now(UTC)
    records = []
    files = []
    errors = []
    for path in paths:
        item = {'path': str(path), 'bytes': None, 'certificates': 0, 'status': 'ok'}
        files.append(item)
        try:
            size = path.stat().st_size
            item['bytes'] = size
            if size > args.max_bytes:
                raise ValueError(f'file exceeds --max-bytes ({size})')
            raw = path.read_bytes()
            blocks = PEM.findall(raw)
            if not blocks:
                raise ValueError('no PEM certificate blocks found')
            for index, body in enumerate(blocks, 1):
                pem = b'-----BEGIN CERTIFICATE-----\n' + body + b'\n-----END CERTIFICATE-----\n'
                try:
                    der = base64.b64decode(re.sub(rb'\s+', b'', body), validate=True)
                    if not der:
                        raise ValueError('empty certificate')
                    ssl.DER_cert_to_PEM_cert(der)
                except (ValueError, TypeError) as error:
                    errors.append({'path': str(path), 'index': index, 'error': str(error)})
                    continue
                decoded, failure = decode(pem)
                before = parse_time(decoded.get('notBefore'))
                after = parse_time(decoded.get('notAfter'))
                remaining = (after - now).total_seconds() / 86400 if after else None
                details = openssl_details(pem, args.openssl)
                flags = []
                if failure:
                    flags.append('decode_failure')
                if after is None:
                    flags.append('unknown_expiration')
                elif remaining < 0:
                    flags.append('expired')
                elif remaining <= args.warn_days:
                    flags.append('expiring_soon')
                if before and before > now:
                    flags.append('not_yet_valid')
                if before and after and before > after:
                    flags.append('invalid_validity_interval')
                if details.get('is_ca') is False and args.openssl:
                    flags.append('not_marked_as_ca')
                record = {
                    'path': str(path), 'index': index, 'der_bytes': len(der),
                    'sha256': hashlib.sha256(der).hexdigest(),
                    'sha1': hashlib.sha1(der).hexdigest(),
                    'subject': dn(decoded.get('subject')),
                    'issuer': dn(decoded.get('issuer')),
                    'serial_number': decoded.get('serialNumber'),
                    'version': decoded.get('version'),
                    'not_before': iso(before), 'not_after': iso(after),
                    'days_remaining': round(remaining, 3) if remaining is not None else None,
                    'self_issued': bool(decoded.get('subject') and decoded.get('subject') == decoded.get('issuer')),
                    'subject_alt_names': decoded.get('subjectAltName', []),
                    'crl_distribution_points': decoded.get('crlDistributionPoints', []),
                    'ca_issuers': decoded.get('caIssuers', []),
                    'ocsp': decoded.get('OCSP', []),
                    'decode_error': failure, 'flags': flags,
                    'openssl': details,
                }
                records.append(record)
                item['certificates'] += 1
        except (OSError, ValueError) as error:
            item['status'] = 'error'
            errors.append({'path': str(path), 'error': str(error)})
    return records, files, errors


def build_report(records, files, errors, args):
    groups = collections.defaultdict(list)
    for record in records:
        groups[record['sha256']].append(record)
    duplicates = [
        {'sha256': digest, 'occurrences': len(items), 'locations': [
            {'path': item['path'], 'index': item['index']} for item in items
        ]}
        for digest, items in groups.items() if len(items) > 1
    ]
    unique = [items[0] for items in groups.values()]
    issuers = collections.Counter(item['issuer'] or 'unknown' for item in unique)
    subjects = collections.Counter(item['subject'] or 'unknown' for item in unique)
    algorithms = collections.Counter(item['openssl'].get('signature_algorithm') or 'unknown' for item in unique)
    buckets = collections.Counter()
    for item in unique:
        days = item['days_remaining']
        bucket = ('unknown' if days is None else 'expired' if days < 0 else
                  '0-30 days' if days <= 30 else '31-90 days' if days <= 90 else
                  '91-180 days' if days <= 180 else '181-365 days' if days <= 365 else '>365 days')
        buckets[bucket] += 1
    findings = [item for item in records if item['flags']]
    summary = {
        'files_scanned': len(files), 'files_failed': sum(item['status'] == 'error' for item in files),
        'certificates_seen': len(records), 'unique_certificates': len(unique),
        'duplicate_fingerprints': len(duplicates),
        'duplicate_extra_copies': len(records) - len(unique),
        'expired': sum('expired' in item['flags'] for item in unique),
        'expiring_soon': sum('expiring_soon' in item['flags'] for item in unique),
        'not_yet_valid': sum('not_yet_valid' in item['flags'] for item in unique),
        'self_issued': sum(item['self_issued'] for item in unique),
        'decode_failures': sum(bool(item['decode_error']) for item in records),
        'file_and_parse_errors': len(errors),
        'findings': len(findings),
    }
    return {
        'tool': 'ca-trust-auditor', 'generated_at': dt.datetime.now(UTC).isoformat(),
        'hostname': os.uname().nodename, 'parameters': {
            'paths': args.paths, 'recursive': args.recursive,
            'warn_days': args.warn_days, 'openssl': args.openssl,
        }, 'summary': summary, 'validity_buckets': dict(buckets),
        'signature_algorithms': dict(algorithms.most_common()),
        'top_issuers': [{'issuer': key, 'count': value} for key, value in issuers.most_common(args.top)],
        'top_subjects': [{'subject': key, 'count': value} for key, value in subjects.most_common(args.top)],
        'files': files, 'duplicates': duplicates, 'errors': errors,
        'certificates': records,
    }


def render(report, args):
    lines = []
    def write(value=''):
        lines.append(str(value))
    def section(name):
        write(); write(name); write('-' * 88)
    write('CA TRUST AUDITOR — DETAILED CERTIFICATE INVENTORY')
    write('=' * 88)
    write(f"Host: {report['hostname']}")
    write(f"Generated: {report['generated_at']}")
    write(f"Expiration warning threshold: {args.warn_days} days")
    write(f"OpenSSL metadata: {args.openssl}")
    section('INVENTORY SUMMARY')
    for key, value in report['summary'].items():
        write(f"{key.replace('_', ' ').title():32} {value}")
    section('CERTIFICATE VALIDITY DISTRIBUTION')
    for key, value in report['validity_buckets'].items():
        write(f'{key:24} {value:>7}')
    section('SIGNATURE ALGORITHMS')
    for key, value in report['signature_algorithms'].items():
        write(f'{key:48} {value:>7}')
    section('MOST COMMON ISSUERS')
    for item in report['top_issuers']:
        write(f"{item['count']:>6}  {item['issuer']}")
    section('SCANNED FILES')
    for item in report['files']:
        write(f"{item['status'].upper():6} {item['certificates']:>5} certificates {str(item['bytes']):>12} bytes  {item['path']}")
    section('CERTIFICATE DETAILS')
    selected = report['certificates'] if args.all else [item for item in report['certificates'] if item['flags']]
    if not selected:
        write('No flagged certificates. Use --all to display the complete inventory.')
    for item in selected[:args.max_display]:
        write()
        write(f"SOURCE       {item['path']} [{item['index']}]")
        write(f"SUBJECT      {item['subject'] or 'unknown'}")
        write(f"ISSUER       {item['issuer'] or 'unknown'}")
        write(f"SERIAL       {item['serial_number'] or 'unknown'}")
        write(f"SHA256       {item['sha256']}")
        write(f"SHA1         {item['sha1']}")
        write(f"DER BYTES    {item['der_bytes']}")
        write(f"VALID FROM   {item['not_before'] or 'unknown'}")
        write(f"VALID UNTIL  {item['not_after'] or 'unknown'}")
        write(f"DAYS LEFT    {item['days_remaining']}")
        write(f"SELF ISSUED  {item['self_issued']}")
        write(f"FLAGS        {', '.join(item['flags']) or 'none'}")
        for key, value in item['openssl'].items():
            if value is not None and key != 'openssl_text':
                write(f"{key.upper():14} {value}")
        if item['decode_error']:
            write(f"DECODE ERROR {item['decode_error']}")
    if len(selected) > args.max_display:
        write(f'... {len(selected) - args.max_display} additional certificates omitted; increase --max-display')
    section('DUPLICATE CERTIFICATES')
    if not report['duplicates']:
        write('None detected in the selected inputs')
    for item in report['duplicates'][:args.top]:
        write(f"{item['sha256']} ({item['occurrences']} copies)")
        for location in item['locations'][:args.top]:
            write(f"  {location['path']} [{location['index']}]")
    section('ERRORS')
    if not report['errors']:
        write('No file or PEM parsing errors')
    for error in report['errors']:
        write(json.dumps(error, ensure_ascii=False))
    section('INTERPRETATION')
    write('Expiry, duplication and metadata findings are inventory observations, not proof of compromise.')
    write('Self-issued does not establish cryptographic self-signature verification.')
    write('This tool does not validate certificate chains, revocation, trust purpose or vendor distrust policy.')
    write('Multiple standard bundle paths may reference the same trust store and inflate duplicate counts.')
    return '\n'.join(lines) + '\n'


def output(report, args):
    if args.format == 'text':
        content = render(report, args)
    elif args.format == 'json':
        content = json.dumps(report, indent=2, ensure_ascii=False) + '\n'
    elif args.format == 'jsonl':
        content = ''.join(json.dumps(item, ensure_ascii=False) + '\n' for item in report['certificates'])
    else:
        buffer = io.StringIO()
        fields = ['path', 'index', 'sha256', 'sha1', 'subject', 'issuer', 'serial_number',
                  'not_before', 'not_after', 'days_remaining', 'self_issued', 'flags', 'decode_error']
        writer = csv.DictWriter(buffer, fieldnames=fields)
        writer.writeheader()
        for item in report['certificates']:
            writer.writerow({key: ','.join(item[key]) if key == 'flags' else item.get(key) for key in fields})
        content = buffer.getvalue()
    if args.output:
        pathlib.Path(args.output).write_text(content, encoding='utf-8')
    else:
        sys.stdout.write(content)


def main():
    parser = argparse.ArgumentParser(description='Verbose, read-only Linux CA bundle auditor')
    parser.add_argument('paths', nargs='*')
    parser.add_argument('--recursive', action='store_true')
    parser.add_argument('--warn-days', type=int, default=90)
    parser.add_argument('--max-bytes', type=int, default=64 * 1024 * 1024)
    parser.add_argument('--max-files', type=int, default=10000)
    parser.add_argument('--max-display', type=int, default=500)
    parser.add_argument('--top', type=int, default=25)
    parser.add_argument('--all', action='store_true')
    parser.add_argument('--openssl', choices=['off', 'summary', 'full'], default='summary')
    parser.add_argument('--format', choices=['text', 'json', 'jsonl', 'csv'], default='text')
    parser.add_argument('--output')
    args = parser.parse_args()
    for name in ('max_bytes', 'max_files', 'max_display', 'top'):
        if getattr(args, name) <= 0:
            parser.error(f'--{name.replace("_", "-")} must be positive')
    if args.warn_days < 0:
        parser.error('--warn-days must be nonnegative')
    paths = args.paths or [path for path in DEFAULTS if pathlib.Path(path).is_file()][:1]
    if not paths:
        parser.error('no default CA bundle found; specify a path')
    args.paths = paths
    discovered, discovery_errors = discover(paths, args.recursive, args.max_files)
    records, files, errors = scan(discovered, args)
    report = build_report(records, files, discovery_errors + errors, args)
    try:
        output(report, args)
    except OSError as error:
        print(f'Output error: {error}', file=sys.stderr)
        return 2
    return 1 if report['errors'] else 0




class Palette:
    def __init__(self, enabled=False):
        self.enabled = enabled
        self.codes = {
            "reset": "0",
            "bold": "1",
            "dim": "2",
            "red": "31",
            "green": "32",
            "yellow": "33",
            "blue": "34",
            "magenta": "35",
            "cyan": "36",
            "white": "37",
        }

    def apply(self, value, style):
        text = str(value)
        if not self.enabled or style not in self.codes:
            return text
        return f"\033[{self.codes[style]}m{text}\033[0m"

    def warning(self, value):
        return self.apply(value, "yellow")

    def failure(self, value):
        return self.apply(value, "red")

    def success(self, value):
        return self.apply(value, "green")

    def heading(self, value):
        return self.apply(value, "cyan")

    def muted(self, value):
        return self.apply(value, "dim")


class TerminalCanvas:
    def __init__(self, width=112, color=False, unicode=False):
        self.width = max(64, width)
        self.palette = Palette(color)
        self.unicode = unicode
        self.lines = []
        self.indent = 0
        self.hline = "─" if unicode else "-"
        self.vline = "│" if unicode else "|"
        self.bar_fill = "█" if unicode else "#"
        self.bar_empty = "░" if unicode else "."

    def write(self, text=""):
        for line in str(text).split("\n"):
            self.lines.append(" " * self.indent + line)

    def blank(self):
        self.lines.append("")

    def rule(self, char=None):
        symbol = char or self.hline
        self.write(symbol * max(1, self.width - self.indent))

    def title(self, text, subtitle=None):
        self.rule("=" if not self.unicode else "═")
        self.write(self.palette.heading(text.upper()))
        if subtitle:
            self.write(self.palette.muted(subtitle))
        self.rule("=" if not self.unicode else "═")

    def section(self, title, description=None):
        self.blank()
        self.write(self.palette.heading(title.upper()))
        self.rule()
        if description:
            self.wrap(description)
            self.blank()

    def subsection(self, title):
        self.blank()
        self.write(self.palette.apply(title, "bold"))
        self.write(self.hline * min(len(title), self.width))

    def wrap(self, value, prefix="", continuation=None):
        import textwrap
        continuation = continuation if continuation is not None else " " * len(prefix)
        text = str(value).replace("\t", " ")
        for paragraph in text.splitlines() or [""]:
            lines = textwrap.wrap(
                paragraph,
                width=max(24, self.width - self.indent),
                initial_indent=prefix,
                subsequent_indent=continuation,
                break_long_words=True,
                break_on_hyphens=False,
            )
            for line in lines or [prefix]:
                self.write(line)

    def pair(self, label, value, label_width=23):
        prefix = f"{label:<{label_width}} : "
        self.wrap(value if value is not None else "unknown", prefix)

    def metric(self, label, value, width=27):
        self.write(f"{label:<{width}} {value}")

    def table(self, headers, rows, widths=None, align=None, limit=None):
        rows = list(rows)
        if limit is not None:
            rows = rows[:limit]
        if not rows:
            self.write(self.palette.muted("No entries"))
            return
        headers = [str(item) for item in headers]
        count = len(headers)
        if widths is None:
            natural = [
                max(len(headers[index]), *(len(str(row[index])) for row in rows))
                for index in range(count)
            ]
            available = self.width - self.indent - 3 * (count - 1)
            widths = [max(7, min(value, max(12, available // count))) for value in natural]
            while sum(widths) > available:
                index = max(range(count), key=lambda pos: widths[pos])
                if widths[index] <= 7:
                    break
                widths[index] -= 1
        align = align or ["left"] * count

        def cell(value, size, direction):
            value = str(value).replace("\n", " ")
            if len(value) > size:
                value = value[:max(0, size - 3)] + "..."
            if direction == "right":
                return value.rjust(size)
            return value.ljust(size)

        def format_row(row):
            return "   ".join(
                cell(row[index], widths[index], align[index])
                for index in range(count)
            )

        self.write(self.palette.apply(format_row(headers), "bold"))
        self.write("   ".join(self.hline * size for size in widths))
        for row in rows:
            self.write(format_row(row))

    def bar(self, label, value, maximum, width=32, suffix=""):
        maximum = max(maximum, 1)
        ratio = max(0, min(1, value / maximum))
        filled = round(ratio * width)
        graphic = self.bar_fill * filled + self.bar_empty * (width - filled)
        self.write(f"{label:<19} {graphic} {value:>6} {suffix}")

    def notice(self, severity, message):
        severity = severity.upper()
        if severity in ("ERROR", "CRITICAL"):
            marker = self.palette.failure(severity)
        elif severity in ("WARNING", "NOTICE"):
            marker = self.palette.warning(severity)
        else:
            marker = self.palette.success(severity)
        self.wrap(message, f"[{marker}] ", " " * (len(severity) + 3))

    def render(self):
        return "\n".join(self.lines).rstrip() + "\n"


def shorten(value, length=80):
    value = str(value or "unknown")
    if len(value) <= length:
        return value
    return value[:max(0, length - 3)] + "..."


def display_bytes(value):
    if value is None:
        return "unknown"
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(amount) < 1024 or unit == "TiB":
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return str(value)


def duration_label(days):
    if days is None:
        return "unknown"
    if days < 0:
        return f"expired {abs(days):.1f} days ago"
    if days < 1:
        return f"{days * 24:.1f} hours remaining"
    if days < 30:
        return f"{days:.1f} days remaining"
    if days < 365:
        return f"{days / 30.4375:.1f} months remaining"
    return f"{days / 365.25:.1f} years remaining"


def parse_iso(value):
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def unique_certificates(report):
    seen = set()
    results = []
    for record in report["certificates"]:
        digest = record["sha256"]
        if digest not in seen:
            seen.add(digest)
            results.append(record)
    return results


def certificate_status(record, warn_days):
    flags = set(record.get("flags", []))
    if "decode_failure" in flags or "invalid_validity_interval" in flags:
        return "INVALID"
    if "expired" in flags:
        return "EXPIRED"
    if "not_yet_valid" in flags:
        return "FUTURE"
    if "unknown_expiration" in flags:
        return "UNKNOWN"
    if record.get("days_remaining") is not None:
        if record["days_remaining"] <= warn_days:
            return "EXPIRING"
    if "not_marked_as_ca" in flags:
        return "NON-CA"
    return "VALIDITY OK"


def certificate_grade(record):
    details = record.get("openssl", {})
    flags = record.get("flags", [])
    issues = []
    if "expired" in flags:
        issues.append("expired certificate")
    if "not_yet_valid" in flags:
        issues.append("not yet valid")
    if "decode_failure" in flags:
        issues.append("unable to decode")
    if "invalid_validity_interval" in flags:
        issues.append("invalid validity interval")
    signature = (details.get("signature_algorithm") or "").lower()
    if "md5" in signature:
        issues.append("MD5 signature algorithm")
    if "sha1" in signature or "sha-1" in signature:
        issues.append("SHA-1 signature algorithm")
    bits = details.get("public_key_bits")
    algorithm = (details.get("public_key_algorithm") or "").lower()
    try:
        bit_count = int(bits)
    except (TypeError, ValueError):
        bit_count = None
    if bit_count is not None and "rsa" in algorithm and bit_count < 2048:
        issues.append("RSA key shorter than 2048 bits")
    if bit_count is not None and ("ec" in algorithm or "id-ec" in algorithm) and bit_count < 224:
        issues.append("small elliptic-curve key")
    return issues


def summarize_risks(report):
    unique = unique_certificates(report)
    results = collections.Counter()
    for record in unique:
        for issue in certificate_grade(record):
            results[issue] += 1
    return results


def timeline_months(records, months=18):
    now = dt.datetime.now(UTC)
    first = now.year * 12 + now.month - 1
    bins = collections.Counter()
    for record in records:
        expiration = parse_iso(record.get("not_after"))
        if expiration is None:
            continue
        month = expiration.year * 12 + expiration.month - 1
        offset = month - first
        if 0 <= offset < months:
            bins[offset] += 1
    result = []
    for offset in range(months):
        index = first + offset
        year = index // 12
        month = index % 12 + 1
        result.append((f"{year:04d}-{month:02d}", bins[offset]))
    return result


def validity_statistics(records):
    values = [
        record["days_remaining"]
        for record in records
        if record.get("days_remaining") is not None
    ]
    if not values:
        return {}
    values.sort()
    import statistics
    return {
        "minimum": min(values),
        "maximum": max(values),
        "mean": statistics.mean(values),
        "median": statistics.median(values),
        "population_stddev": statistics.pstdev(values),
        "p10": percentile(values, 10),
        "p25": percentile(values, 25),
        "p75": percentile(values, 75),
        "p90": percentile(values, 90),
    }


def percentile(values, percentage):
    if not values:
        return None
    position = (len(values) - 1) * percentage / 100
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return values[lower]
    fraction = position - lower
    return values[lower] * (1 - fraction) + values[upper] * fraction


def key_algorithm_statistics(records):
    results = collections.Counter()
    for record in records:
        details = record.get("openssl", {})
        name = details.get("public_key_algorithm") or "unknown"
        bits = details.get("public_key_bits")
        if bits:
            name = f"{name} ({bits} bits)"
        results[name] += 1
    return results


def issuer_groups(records):
    groups = collections.defaultdict(list)
    for record in records:
        groups[record.get("issuer") or "unknown"].append(record)
    return groups


def subject_groups(records):
    groups = collections.defaultdict(list)
    for record in records:
        groups[record.get("subject") or "unknown"].append(record)
    return groups


def fingerprint_prefix_groups(records, size=4):
    groups = collections.defaultdict(list)
    for record in records:
        groups[record["sha256"][:size]].append(record)
    return groups


def file_inventory_statistics(report):
    files = report["files"]
    total_bytes = sum(item.get("bytes") or 0 for item in files)
    counts = [item.get("certificates", 0) for item in files]
    return {
        "total_bytes": total_bytes,
        "files": len(files),
        "nonempty_files": sum(value > 0 for value in counts),
        "empty_files": sum(value == 0 for value in counts),
        "largest_file": max((item.get("bytes") or 0 for item in files), default=0),
        "largest_certificate_count": max(counts, default=0),
    }


def detailed_findings(report, warn_days):
    findings = []
    for record in unique_certificates(report):
        status = certificate_status(record, warn_days)
        issues = certificate_grade(record)
        if status != "VALIDITY OK" or issues:
            findings.append({
                "status": status,
                "subject": record.get("subject") or "unknown",
                "issuer": record.get("issuer") or "unknown",
                "sha256": record["sha256"],
                "days_remaining": record.get("days_remaining"),
                "issues": issues,
                "path": record["path"],
                "index": record["index"],
            })
    severity = {
        "INVALID": 0,
        "EXPIRED": 1,
        "FUTURE": 2,
        "UNKNOWN": 3,
        "EXPIRING": 4,
        "NON-CA": 5,
        "VALIDITY OK": 6,
    }
    findings.sort(key=lambda item: (
        severity.get(item["status"], 99),
        item["days_remaining"] if item["days_remaining"] is not None else 1e12,
        item["subject"],
    ))
    return findings


def render_header(canvas, report, args):
    canvas.title(
        "CA TRUST AUDITOR / CERTIFICATE FORENSICS",
        "Linux trust-store inventory and cryptographic metadata review",
    )
    canvas.blank()
    canvas.pair("Host", report["hostname"])
    canvas.pair("Generated UTC", report["generated_at"])
    canvas.pair("Certificate sources", ", ".join(report["parameters"]["paths"]))
    canvas.pair("Warning threshold", f"{args.warn_days} days")
    canvas.pair("OpenSSL mode", args.openssl)
    canvas.pair("Report width", args.width)
    canvas.pair("Rendering mode", "verbose" if args.all else "findings")


def render_dashboard(canvas, report, args):
    canvas.section("01 / Inventory dashboard")
    summary = report["summary"]
    metrics = [
        ("Files scanned", summary["files_scanned"]),
        ("Files with errors", summary["files_failed"]),
        ("Certificates observed", summary["certificates_seen"]),
        ("Unique certificates", summary["unique_certificates"]),
        ("Duplicate fingerprints", summary["duplicate_fingerprints"]),
        ("Extra certificate copies", summary["duplicate_extra_copies"]),
        ("Expired unique certificates", summary["expired"]),
        ("Expiring unique certificates", summary["expiring_soon"]),
        ("Not yet valid", summary["not_yet_valid"]),
        ("Self-issued certificates", summary["self_issued"]),
        ("Decode failures", summary["decode_failures"]),
        ("File and parsing errors", summary["file_and_parse_errors"]),
    ]
    canvas.table(
        ["Metric", "Observed"],
        metrics,
        widths=[40, 18],
        align=["left", "right"],
    )
    if summary["file_and_parse_errors"]:
        canvas.notice("warning", "Some files or PEM blocks could not be processed")
    elif summary["files_scanned"]:
        canvas.notice("info", "Inventory scan completed without file parsing errors")
    else:
        canvas.notice("warning", "No certificate files were scanned")


def render_status_distribution(canvas, report, args):
    canvas.section("02 / Validity status")
    records = unique_certificates(report)
    counter = collections.Counter(
        certificate_status(record, args.warn_days)
        for record in records
    )
    order = [
        "INVALID", "EXPIRED", "FUTURE", "UNKNOWN",
        "EXPIRING", "NON-CA", "VALIDITY OK",
    ]
    maximum = max(counter.values(), default=1)
    for status in order:
        canvas.bar(status, counter[status], maximum, width=34)
    canvas.blank()
    canvas.wrap(
        "Validity status describes local certificate metadata. It does not "
        "establish trust, revocation status, or successful chain validation."
    )


def render_expiration_buckets(canvas, report, args):
    canvas.section("03 / Expiration distribution")
    buckets = report["validity_buckets"]
    order = [
        "expired", "0-30 days", "31-90 days", "91-180 days",
        "181-365 days", ">365 days", "unknown",
    ]
    maximum = max(buckets.values(), default=1)
    for name in order:
        canvas.bar(name, buckets.get(name, 0), maximum, width=34)
    stats = validity_statistics(unique_certificates(report))
    if stats:
        canvas.subsection("Remaining lifetime statistics")
        rows = [
            (name.replace("_", " ").title(), f"{value:,.2f} days")
            for name, value in stats.items()
        ]
        canvas.table(["Statistic", "Days"], rows, widths=[28, 22])


def render_expiration_timeline(canvas, report, args):
    canvas.section("04 / Upcoming expiration timeline")
    timeline = timeline_months(unique_certificates(report), args.months)
    maximum = max((value for _, value in timeline), default=1)
    for label, count in timeline:
        canvas.bar(label, count, maximum, width=34)
    canvas.blank()
    canvas.wrap("Months with no expirations remain visible to make gaps explicit.")


def render_signature_algorithms(canvas, report, args):
    canvas.section("05 / Signature algorithm inventory")
    values = list(report["signature_algorithms"].items())
    values.sort(key=lambda item: (-item[1], item[0]))
    canvas.table(
        ["Signature algorithm", "Certificates"],
        [(shorten(name, 65), count) for name, count in values[:args.top]],
        widths=[65, 14],
        align=["left", "right"],
    )


def render_public_keys(canvas, report, args):
    canvas.section("06 / Public-key algorithm inventory")
    counter = key_algorithm_statistics(unique_certificates(report))
    canvas.table(
        ["Algorithm and key size", "Certificates"],
        counter.most_common(args.top),
        widths=[65, 14],
        align=["left", "right"],
    )


def render_issuer_rankings(canvas, report, args):
    canvas.section("07 / Certificate issuer ranking")
    groups = issuer_groups(unique_certificates(report))
    ranked = sorted(groups.items(), key=lambda item: (-len(item[1]), item[0]))
    rows = []
    for issuer, records in ranked[:args.top]:
        expired = sum(
            record.get("days_remaining") is not None
            and record["days_remaining"] < 0
            for record in records
        )
        rows.append((shorten(issuer, 74), len(records), expired))
    canvas.table(
        ["Issuer", "Count", "Expired"],
        rows,
        widths=[74, 8, 8],
        align=["left", "right", "right"],
    )


def render_subject_rankings(canvas, report, args):
    canvas.section("08 / Repeated certificate subjects")
    groups = subject_groups(unique_certificates(report))
    ranked = sorted(groups.items(), key=lambda item: (-len(item[1]), item[0]))
    rows = [
        (shorten(subject, 79), len(records))
        for subject, records in ranked[:args.top]
    ]
    canvas.table(
        ["Subject", "Unique certificates"],
        rows,
        widths=[79, 20],
        align=["left", "right"],
    )


def render_file_inventory(canvas, report, args):
    canvas.section("09 / Scanned source files")
    stats = file_inventory_statistics(report)
    canvas.pair("Aggregate file size", display_bytes(stats["total_bytes"]))
    canvas.pair("Files containing certificates", stats["nonempty_files"])
    canvas.pair("Files without certificates", stats["empty_files"])
    canvas.pair("Largest file", display_bytes(stats["largest_file"]))
    canvas.blank()
    rows = []
    for item in report["files"][:args.max_display]:
        rows.append((
            shorten(item["path"], 72),
            item["certificates"],
            display_bytes(item["bytes"]),
            item["status"],
        ))
    canvas.table(
        ["Source", "Certs", "Size", "Status"],
        rows,
        widths=[72, 7, 11, 8],
        align=["left", "right", "right", "left"],
    )
    omitted = len(report["files"]) - len(rows)
    if omitted > 0:
        canvas.write(f"Additional files omitted: {omitted}")


def render_findings(canvas, report, args):
    canvas.section("10 / Prioritized certificate findings")
    findings = detailed_findings(report, args.warn_days)
    if not findings:
        canvas.notice("info", "No metadata findings under the selected rules")
        return
    rows = []
    for finding in findings[:args.max_display]:
        rows.append((
            finding["status"],
            shorten(finding["subject"], 60),
            duration_label(finding["days_remaining"]),
        ))
    canvas.table(
        ["Status", "Subject", "Validity"],
        rows,
        widths=[13, 60, 29],
    )
    if len(findings) > len(rows):
        canvas.write(f"Additional findings omitted: {len(findings) - len(rows)}")


def render_duplicate_groups(canvas, report, args):
    canvas.section("11 / Duplicate certificate fingerprints")
    duplicates = sorted(
        report["duplicates"],
        key=lambda item: (-item["occurrences"], item["sha256"]),
    )
    if not duplicates:
        canvas.notice("info", "No duplicate SHA-256 fingerprints found")
        return
    for index, group in enumerate(duplicates[:args.top], 1):
        canvas.subsection(f"Duplicate group {index}")
        canvas.pair("SHA-256", group["sha256"])
        canvas.pair("Occurrences", group["occurrences"])
        for location in group["locations"][:args.max_display]:
            canvas.wrap(
                f"{location['path']}  certificate #{location['index']}",
                prefix="  ",
                continuation="  ",
            )
        if len(group["locations"]) > args.max_display:
            canvas.write("  Additional locations omitted")
    if len(duplicates) > args.top:
        canvas.write(f"Additional duplicate groups omitted: {len(duplicates) - args.top}")


def render_cryptographic_findings(canvas, report, args):
    canvas.section("12 / Cryptographic review")
    risks = summarize_risks(report)
    if not risks:
        canvas.notice("info", "No configured cryptographic warning patterns detected")
    else:
        canvas.table(
            ["Observation", "Unique certificates"],
            risks.most_common(),
            widths=[62, 22],
            align=["left", "right"],
        )
    canvas.blank()
    canvas.wrap(
        "Algorithm and key-size findings are heuristic indicators, not "
        "complete assessments of certificate security or cryptographic strength."
    )


def render_certificate_record(canvas, record, ordinal, args):
    canvas.subsection(f"Certificate {ordinal:04d} / {certificate_status(record, args.warn_days)}")
    canvas.pair("Source", record["path"])
    canvas.pair("Bundle index", record["index"])
    canvas.pair("Subject", record.get("subject") or "unknown")
    canvas.pair("Issuer", record.get("issuer") or "unknown")
    canvas.pair("Serial", record.get("serial_number") or "unknown")
    canvas.pair("X.509 version", record.get("version"))
    canvas.pair("SHA-256", record["sha256"])
    canvas.pair("SHA-1", record["sha1"])
    canvas.pair("Encoded DER size", display_bytes(record["der_bytes"]))
    canvas.pair("Valid from", record.get("not_before") or "unknown")
    canvas.pair("Valid until", record.get("not_after") or "unknown")
    canvas.pair("Remaining lifetime", duration_label(record.get("days_remaining")))
    canvas.pair("Self-issued", "yes" if record["self_issued"] else "no")
    canvas.pair("Flags", ", ".join(record["flags"]) or "none")
    details = record.get("openssl", {})
    canvas.pair("Signature algorithm", details.get("signature_algorithm"))
    canvas.pair("Public-key algorithm", details.get("public_key_algorithm"))
    canvas.pair("Public-key bits", details.get("public_key_bits"))
    canvas.pair("Basic constraints", details.get("basic_constraints"))
    canvas.pair("Key usage", details.get("key_usage"))
    canvas.pair("Subject key ID", details.get("subject_key_identifier"))
    canvas.pair("Authority key ID", details.get("authority_key_identifier"))
    canvas.pair("SHA-1 fingerprint", details.get("sha1_fingerprint"))
    for key, title in (
        ("subject_alt_names", "Subject alternative names"),
        ("crl_distribution_points", "CRL distribution points"),
        ("ca_issuers", "CA issuer endpoints"),
        ("ocsp", "OCSP endpoints"),
    ):
        values = record.get(key) or []
        if values:
            canvas.pair(title, "; ".join(map(str, values)))
    issues = certificate_grade(record)
    if issues:
        canvas.pair("Review observations", "; ".join(issues))
    if record.get("decode_error"):
        canvas.pair("Decode error", record["decode_error"])
    if details.get("openssl_error"):
        canvas.pair("OpenSSL error", details["openssl_error"])
    if args.openssl == "full" and args.show_openssl_text:
        raw = details.get("openssl_text")
        if raw:
            canvas.subsection("Raw OpenSSL output")
            for line in raw.splitlines():
                canvas.wrap(line, "  ", "  ")


def render_certificate_details(canvas, report, args):
    canvas.section("13 / Certificate-by-certificate investigation")
    records = report["certificates"]
    if not args.all:
        records = [record for record in records if record["flags"]]
    if args.sort == "expiration":
        records = sorted(
            records,
            key=lambda record: (
                record.get("days_remaining") is None,
                record.get("days_remaining") or 0,
            ),
        )
    elif args.sort == "subject":
        records = sorted(records, key=lambda record: record["subject"])
    elif args.sort == "issuer":
        records = sorted(records, key=lambda record: record["issuer"])
    elif args.sort == "source":
        records = sorted(records, key=lambda record: (record["path"], record["index"]))
    if not records:
        canvas.notice("info", "No selected certificate details; use --all for every certificate")
        return
    for ordinal, record in enumerate(records[:args.max_display], 1):
        render_certificate_record(canvas, record, ordinal, args)
    if len(records) > args.max_display:
        canvas.blank()
        canvas.notice("notice", f"{len(records) - args.max_display} records omitted; increase --max-display")


def render_error_log(canvas, report, args):
    canvas.section("14 / File and parsing diagnostics")
    errors = report["errors"]
    if not errors:
        canvas.notice("info", "No file or parsing errors were recorded")
        return
    for index, error in enumerate(errors[:args.max_display], 1):
        canvas.subsection(f"Diagnostic {index}")
        for key, value in error.items():
            canvas.pair(key.replace("_", " ").title(), value)
    if len(errors) > args.max_display:
        canvas.write(f"Additional diagnostics omitted: {len(errors) - args.max_display}")


def render_interpretation(canvas, report, args):
    canvas.section("15 / Scope and interpretation")
    observations = [
        "The program reads local certificate files and does not change the system trust store.",
        "Certificate expiration does not by itself establish whether the certificate is actively trusted.",
        "Self-issued means subject and issuer names match; it is not proof of a valid self-signature.",
        "Duplicate fingerprints can be normal when multiple bundle paths refer to the same certificates.",
        "Vendor distrust decisions and CA purpose restrictions are not evaluated by this inventory.",
        "Revocation status, OCSP responses, CRLs, and complete certificate chains are not validated.",
        "OpenSSL text parsing depends on the installed OpenSSL version and its output conventions.",
        "Some trust stores include certificates for purposes other than public TLS server authentication.",
        "Warnings about signatures and key sizes are screening indicators, not comprehensive security findings.",
        "Certificate content, subjects, and source paths may be sensitive in certain environments.",
    ]
    for index, observation in enumerate(observations, 1):
        canvas.wrap(observation, f"{index:>2}. ", "    ")
    canvas.blank()
    canvas.write(canvas.palette.muted("END OF CA TRUST AUDIT REPORT"))


def render_enhanced(report, args):
    canvas = TerminalCanvas(
        width=args.width,
        color=args.color == "always" or (
            args.color == "auto"
            and not args.output
            and sys.stdout.isatty()
            and not os.environ.get("NO_COLOR")
        ),
        unicode=args.unicode,
    )
    sections = [
        ("dashboard", render_dashboard),
        ("status", render_status_distribution),
        ("expiration", render_expiration_buckets),
        ("timeline", render_expiration_timeline),
        ("signatures", render_signature_algorithms),
        ("keys", render_public_keys),
        ("issuers", render_issuer_rankings),
        ("subjects", render_subject_rankings),
        ("files", render_file_inventory),
        ("findings", render_findings),
        ("duplicates", render_duplicate_groups),
        ("crypto", render_cryptographic_findings),
        ("certificates", render_certificate_details),
        ("errors", render_error_log),
        ("interpretation", render_interpretation),
        ("advanced", render_advanced_audit),
        ("comparison", render_comparison),
        ("policy", render_policy_inventory),
        ("verification", render_verification_inventory),
        ("issuergraph", render_issuer_graph),
        ("integrity", render_integrity),
        ("keyfamilies", render_key_families),
        ("validitywindows", render_validity_windows),
        ("calendar", render_expiration_calendar),
    ]
    render_header(canvas, report, args)
    enabled = set(args.sections.split(",")) if args.sections != "all" else None
    for name, renderer in sections:
        if enabled is None or name in enabled:
            renderer(canvas, report, args)
    return canvas.render()


def write_atomic(destination, content):
    target = pathlib.Path(destination)
    parent = target.parent
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=parent,
        prefix=".ca-trust-auditor-",
        suffix=".tmp",
        delete=False,
    ) as stream:
        temporary = pathlib.Path(stream.name)
        try:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        temporary.replace(target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def export_enhanced(report, args):
    if args.format == "text":
        content = render_enhanced(report, args)
    elif args.format == "json":
        content = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    elif args.format == "jsonl":
        content = "".join(
            json.dumps(record, ensure_ascii=False) + "\n"
            for record in report["certificates"]
        )
    else:
        buffer = io.StringIO()
        fields = [
            "path", "index", "sha256", "sha1", "subject", "issuer",
            "serial_number", "not_before", "not_after", "days_remaining",
            "self_issued", "flags", "decode_error", "signature_algorithm",
            "public_key_algorithm", "public_key_bits", "basic_constraints",
            "key_usage", "status",
        ]
        writer = csv.DictWriter(buffer, fieldnames=fields)
        writer.writeheader()
        for record in report["certificates"]:
            details = record.get("openssl", {})
            row = {key: record.get(key) for key in fields}
            row["flags"] = ";".join(record.get("flags", []))
            row["status"] = certificate_status(record, args.warn_days)
            for key in (
                "signature_algorithm", "public_key_algorithm", "public_key_bits",
                "basic_constraints", "key_usage",
            ):
                row[key] = details.get(key)
            writer.writerow(row)
        content = buffer.getvalue()
    if args.output:
        write_atomic(args.output, content)
    else:
        sys.stdout.write(content)


def add_enhanced_arguments(parser):
    parser.add_argument("--width", type=int, default=112)
    parser.add_argument("--months", type=int, default=18)
    parser.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    parser.add_argument("--unicode", action="store_true")
    parser.add_argument("--show-openssl-text", action="store_true")
    parser.add_argument(
        "--sort",
        choices=["expiration", "subject", "issuer", "source"],
        default="expiration",
    )
    parser.add_argument(
        "--sections",
        default="all",
        help="Comma-separated report sections or all",
    )
    return parser


def enhanced_parser():
    parser = argparse.ArgumentParser(
        prog="ca-trust-auditor",
        description="Verbose read-only Linux CA certificate inventory and analysis",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--recursive", action="store_true")
    parser.add_argument("--warn-days", type=int, default=90)
    parser.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--max-files", type=int, default=10000)
    parser.add_argument("--max-display", type=int, default=500)
    parser.add_argument("--top", type=int, default=25)
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--openssl", choices=["off", "summary", "full"], default="summary")
    parser.add_argument("--format", choices=["text", "json", "jsonl", "csv"], default="text")
    parser.add_argument("--output")
    parser.add_argument("--baseline", help="Compare against a previous JSON report")
    parser.add_argument("--write-baseline", help="Write current inventory as a JSON baseline")
    parser.add_argument("--strict", action="store_true", help="Return nonzero for selected findings")
    parser.add_argument("--strict-expiring", action="store_true")
    parser.add_argument("--strict-crypto", action="store_true")
    parser.add_argument("--min-rsa-bits", type=int, default=2048)
    parser.add_argument("--fingerprint", action="append", default=[])
    parser.add_argument("--subject-regex")
    parser.add_argument("--issuer-regex")
    parser.add_argument("--only-findings", action="store_true")
    parser.add_argument("--inspect-files", action="store_true")
    parser.add_argument("--inspect-policy", action="store_true")
    parser.add_argument("--verify-with", help="Explicit CA bundle for offline OpenSSL chain verification")
    parser.add_argument("--verify-timeout", type=float, default=5.0)
    parser.add_argument("--fail-on-change", action="store_true")
    return add_enhanced_arguments(parser)


def validate_enhanced_arguments(parser, args):
    for key in ("max_bytes", "max_files", "max_display", "top", "months"):
        if getattr(args, key) <= 0:
            parser.error(f"--{key.replace('_', '-')} must be positive")
    if args.width < 64 or args.width > 300:
        parser.error("--width must be between 64 and 300")
    if args.warn_days < 0:
        parser.error("--warn-days must not be negative")
    if args.min_rsa_bits < 1024 or args.min_rsa_bits > 16384:
        parser.error("--min-rsa-bits must be between 1024 and 16384")
    if args.verify_timeout <= 0 or args.verify_timeout > 120:
        parser.error("--verify-timeout must be between 0 and 120 seconds")
    for key in ("subject_regex", "issuer_regex"):
        value = getattr(args, key)
        if value:
            try:
                re.compile(value)
            except re.error as error:
                parser.error(f"Invalid {key}: {error}")
    allowed = {
        "dashboard", "status", "expiration", "timeline", "signatures",
        "keys", "issuers", "subjects", "files", "findings", "duplicates",
        "crypto", "certificates", "errors", "interpretation",
        "advanced", "comparison", "policy", "verification",
        "issuergraph", "integrity", "keyfamilies", "validitywindows", "calendar",
    }
    if args.sections != "all":
        chosen = {part.strip() for part in args.sections.split(",")}
        unknown = chosen - allowed
        if unknown:
            parser.error("Unknown report sections: " + ", ".join(sorted(unknown)))
        args.sections = ",".join(sorted(chosen))


def resolve_default_paths():
    for raw in DEFAULTS:
        candidate = pathlib.Path(raw)
        if candidate.is_file():
            return [raw]
    return []



def normalize_fingerprint(value):
    return re.sub(r"[^0-9a-f]", "", str(value).lower())


def validate_fingerprint(value):
    normalized = normalize_fingerprint(value)
    if len(normalized) not in (40, 64):
        raise ValueError("fingerprint must be SHA-1 (40 hex) or SHA-256 (64 hex)")
    return normalized


def file_metadata(path):
    result = {"path": str(path), "exists": False}
    try:
        info = path.lstat()
        result["exists"] = True
        result["mode"] = stat.filemode(info.st_mode)
        result["mode_octal"] = oct(stat.S_IMODE(info.st_mode))
        result["uid"] = info.st_uid
        result["gid"] = info.st_gid
        result["inode"] = info.st_ino
        result["device"] = info.st_dev
        result["mtime_utc"] = dt.datetime.fromtimestamp(info.st_mtime, UTC).isoformat()
        result["size"] = info.st_size
        result["is_symlink"] = stat.S_ISLNK(info.st_mode)
        result["world_writable"] = bool(info.st_mode & stat.S_IWOTH)
        result["group_writable"] = bool(info.st_mode & stat.S_IWGRP)
        if result["is_symlink"]:
            result["symlink_target"] = os.readlink(path)
            result["resolved"] = str(path.resolve(strict=False))
            try:
                target = path.stat()
                result["target_mode"] = stat.filemode(target.st_mode)
                result["target_world_writable"] = bool(target.st_mode & stat.S_IWOTH)
            except OSError as error:
                result["target_error"] = str(error)
        else:
            result["target_world_writable"] = result["world_writable"]
    except OSError as error:
        result["error"] = str(error)
    return result


def inspect_sources(report):
    return [file_metadata(pathlib.Path(item["path"])) for item in report["files"]]


def classify_key(record, minimum_rsa_bits):
    details = record.get("openssl") or {}
    name = (details.get("public_key_algorithm") or "").lower()
    raw = details.get("public_key_bits")
    try:
        bits = int(raw)
    except (ValueError, TypeError):
        bits = None
    findings = []
    if "rsa" in name and bits is not None and bits < minimum_rsa_bits:
        findings.append({"rule": "rsa_key_length", "severity": "high", "detail": f"RSA {bits} bits below {minimum_rsa_bits}"})
    if ("ec" in name or "elliptic" in name) and bits is not None and bits < 224:
        findings.append({"rule": "ec_key_length", "severity": "high", "detail": f"EC key length {bits} bits"})
    if bits is None:
        findings.append({"rule": "unknown_key_size", "severity": "info", "detail": "Public key size not extracted"})
    return findings


def classify_signature(record):
    signature = ((record.get("openssl") or {}).get("signature_algorithm") or "").lower()
    if not signature:
        return [{"rule": "unknown_signature", "severity": "info", "detail": "Signature algorithm unavailable"}]
    if "md5" in signature or "md2" in signature:
        return [{"rule": "obsolete_signature", "severity": "high", "detail": signature}]
    if "sha1" in signature or "sha-1" in signature:
        return [{"rule": "legacy_signature", "severity": "medium", "detail": signature}]
    return []


def classify_validity(record, now, warn_days):
    findings = []
    before = parse_iso(record.get("not_before"))
    after = parse_iso(record.get("not_after"))
    if before is None or after is None:
        findings.append({"rule": "missing_validity", "severity": "medium", "detail": "Incomplete validity metadata"})
    if before is not None and after is not None and before > after:
        findings.append({"rule": "reversed_validity", "severity": "high", "detail": "NotBefore exceeds NotAfter"})
    if before is not None and before > now:
        findings.append({"rule": "not_yet_valid", "severity": "medium", "detail": before.isoformat()})
    if after is not None:
        remaining = (after - now).total_seconds() / 86400
        if remaining < 0:
            findings.append({"rule": "expired", "severity": "high", "detail": f"Expired {abs(remaining):.2f} days ago"})
        elif remaining <= warn_days:
            findings.append({"rule": "expiring", "severity": "medium", "detail": f"Expires in {remaining:.2f} days"})
    return findings


def classify_certificate(record, args, now):
    findings = classify_validity(record, now, args.warn_days)
    findings.extend(classify_signature(record))
    findings.extend(classify_key(record, args.min_rsa_bits))
    if record.get("decode_error"):
        findings.append({"rule": "decode_error", "severity": "high", "detail": record["decode_error"]})
    if "not_marked_as_ca" in record.get("flags", []):
        findings.append({"rule": "non_ca_certificate", "severity": "low", "detail": "Basic Constraints does not mark CA:TRUE"})
    if record.get("self_issued"):
        findings.append({"rule": "self_issued", "severity": "info", "detail": "Subject and issuer DNs match; signature not verified"})
    return findings


def inventory_map(report):
    mapping = {}
    for record in report.get("certificates", []):
        digest = record.get("sha256")
        if digest:
            mapping.setdefault(digest, record)
    return mapping


def compare_inventories(current, previous):
    current_map = inventory_map(current)
    previous_map = inventory_map(previous)
    added = sorted(current_map.keys() - previous_map.keys())
    removed = sorted(previous_map.keys() - current_map.keys())
    common = sorted(current_map.keys() & previous_map.keys())
    changed_metadata = []
    for digest in common:
        old = previous_map[digest]
        new = current_map[digest]
        fields = ("subject", "issuer", "serial_number", "not_before", "not_after")
        differences = {field: {"before": old.get(field), "after": new.get(field)}
                       for field in fields if old.get(field) != new.get(field)}
        if differences:
            changed_metadata.append({"sha256": digest, "differences": differences})
    return {
        "changed": bool(added or removed or changed_metadata),
        "previous_unique": len(previous_map),
        "current_unique": len(current_map),
        "unchanged": len(common) - len(changed_metadata),
        "added": [{"sha256": digest, "subject": current_map[digest].get("subject"),
                   "issuer": current_map[digest].get("issuer")} for digest in added],
        "removed": [{"sha256": digest, "subject": previous_map[digest].get("subject"),
                     "issuer": previous_map[digest].get("issuer")} for digest in removed],
        "metadata_changes": changed_metadata,
    }


def load_baseline(path):
    location = pathlib.Path(path)
    if location.stat().st_size > 256 * 1024 * 1024:
        raise ValueError("baseline exceeds 256 MiB")
    with location.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict) or not isinstance(value.get("certificates"), list):
        raise ValueError("baseline must be a JSON report containing certificates")
    for item in value["certificates"]:
        if not isinstance(item, dict):
            raise ValueError("baseline certificate entries must be objects")
    return value


def run_command(argv, timeout=10, input_data=None):
    try:
        completed = subprocess.run(argv, input=input_data, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, timeout=timeout, check=False)
        return {"command": argv, "exit_code": completed.returncode,
                "stdout": completed.stdout.decode("utf-8", "replace")[:2_000_000],
                "stderr": completed.stderr.decode("utf-8", "replace")[:200_000]}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"command": argv, "error": str(error)}


def inspect_system_policy():
    result = {"platform": sys.platform, "tools": {}, "paths": []}
    for name in ("trust", "update-ca-trust", "openssl"):
        from shutil import which
        result["tools"][name] = which(name)
    for path in (
        "/etc/pki/ca-trust", "/etc/pki/ca-trust/source/anchors",
        "/etc/pki/ca-trust/source/blacklist", "/etc/pki/tls/certs",
        "/etc/ssl/certs", "/usr/share/pki/ca-trust-source",
    ):
        result["paths"].append(file_metadata(pathlib.Path(path)))
    if result["tools"].get("trust"):
        result["trust_anchor_listing"] = run_command(
            ["trust", "list", "--filter=ca-anchors"], timeout=20)
        result["trust_blocklist_listing"] = run_command(
            ["trust", "list", "--filter=blocklist"], timeout=20)
    return result


def extract_pem_by_digest(path, digest, max_bytes=64 * 1024 * 1024):
    source = pathlib.Path(path)
    if source.stat().st_size > max_bytes:
        return None
    raw = source.read_bytes()
    for body in PEM.findall(raw):
        try:
            der = base64.b64decode(re.sub(rb"\s+", b"", body), validate=True)
        except (ValueError, TypeError):
            continue
        if hashlib.sha256(der).hexdigest() == digest:
            return b"-----BEGIN CERTIFICATE-----\n" + body + b"\n-----END CERTIFICATE-----\n"
    return None


def verify_inventory(report, args):
    result = {"bundle": args.verify_with, "results": [], "verified": 0,
              "failed": 0, "unavailable": 0}
    bundle = pathlib.Path(args.verify_with)
    if not bundle.is_file():
        raise ValueError("--verify-with requires an existing CA bundle file")
    if bundle.stat().st_size > args.max_bytes:
        raise ValueError("verification CA bundle exceeds --max-bytes")
    for record in unique_certificates(report):
        item = {"sha256": record["sha256"], "subject": record.get("subject"),
                "source": record["path"]}
        try:
            pem = extract_pem_by_digest(record["path"], record["sha256"], args.max_bytes)
            if pem is None:
                item["status"] = "unavailable"
                item["detail"] = "Certificate bytes could not be recovered"
            else:
                with tempfile.NamedTemporaryFile(suffix=".pem") as stream:
                    stream.write(pem)
                    stream.flush()
                    command = run_command(["openssl", "verify", "-CAfile", str(bundle),
                                           stream.name], timeout=args.verify_timeout)
                item["status"] = "verified" if command.get("exit_code") == 0 else "failed"
                item["detail"] = (command.get("stdout") or command.get("stderr") or
                                  command.get("error") or "")[:1000].strip()
        except (OSError, ValueError) as error:
            item["status"] = "unavailable"
            item["detail"] = str(error)
        result["results"].append(item)
        result[item["status"]] += 1
    result["caveat"] = "Offline OpenSSL verification against explicitly selected CAfile; no revocation or vendor policy validation"
    return result


def filter_report(report, args):
    records = report["certificates"]
    if args.fingerprint:
        selected = {validate_fingerprint(value) for value in args.fingerprint}
        records = [item for item in records if item["sha256"] in selected or item["sha1"] in selected]
    if args.subject_regex:
        expression = re.compile(args.subject_regex)
        records = [item for item in records if expression.search(item.get("subject") or "")]
    if args.issuer_regex:
        expression = re.compile(args.issuer_regex)
        records = [item for item in records if expression.search(item.get("issuer") or "")]
    if args.only_findings:
        records = [item for item in records if item.get("audit_findings") and
                   any(f["severity"] != "info" for f in item["audit_findings"])]
    return records


def enrich_report(report, args):
    now = dt.datetime.now(UTC)
    unique = inventory_map(report)
    critical = 0
    crypto = 0
    severity_counts = collections.Counter()
    rule_counts = collections.Counter()
    for digest, record in unique.items():
        findings = classify_certificate(record, args, now)
        for finding in findings:
            severity_counts[finding["severity"]] += 1
            rule_counts[finding["rule"]] += 1
            if finding["severity"] == "high":
                critical += 1
            if finding["rule"] in ("rsa_key_length", "ec_key_length", "obsolete_signature", "legacy_signature"):
                crypto += 1
    for record in report["certificates"]:
        record["audit_findings"] = classify_certificate(record, args, now)
    report["audit"] = {
        "evaluated_unique": len(unique), "critical_count": critical,
        "crypto_count": crypto, "severity_counts": dict(severity_counts),
        "rule_counts": dict(rule_counts),
        "scope": "Heuristic local metadata review, not proof of trust or compromise",
    }
    report["issuer_graph"] = build_issuer_graph(report)
    report["bundle_integrity"] = inspect_bundle_integrity(report)
    report["key_families"] = summarize_key_families(report)
    report["validity_windows"] = summarize_validity_windows(report)
    report["expiration_calendar"] = certificate_expiration_calendar(report)
    if args.inspect_files:
        report["file_metadata"] = inspect_sources(report)
        report["audit"]["writable_sources"] = sum(
            item.get("world_writable", False) or item.get("target_world_writable", False)
            for item in report["file_metadata"])
    if args.inspect_policy:
        report["system_policy"] = inspect_system_policy()
    if args.verify_with:
        report["verification"] = verify_inventory(report, args)
    if args.baseline:
        report["comparison"] = compare_inventories(report, load_baseline(args.baseline))
    if args.fingerprint or args.subject_regex or args.issuer_regex or args.only_findings:
        selected = filter_report(report, args)
        report["selection"] = {"selected": len(selected), "original": len(report["certificates"])}
        report["certificates"] = selected


def render_advanced_audit(canvas, report, args):
    canvas.section("16 / Advanced metadata assessment")
    audit = report.get("audit", {})
    if not audit:
        canvas.notice("info", "No advanced audit information")
        return
    canvas.pair("Unique certificates assessed", audit.get("evaluated_unique"))
    canvas.pair("High-severity observations", audit.get("critical_count"))
    canvas.pair("Cryptographic observations", audit.get("crypto_count"))
    canvas.subsection("Finding severity distribution")
    canvas.table(["Severity", "Observations"],
                 sorted(audit.get("severity_counts", {}).items()), widths=[25, 18])
    canvas.subsection("Finding rule distribution")
    canvas.table(["Rule", "Observations"],
                 sorted(audit.get("rule_counts", {}).items(), key=lambda x: (-x[1], x[0])),
                 widths=[45, 18])
    if "writable_sources" in audit:
        canvas.pair("World-writable sources", audit["writable_sources"])
    canvas.wrap(audit.get("scope", ""))


def render_comparison(canvas, report, args):
    canvas.section("17 / Baseline drift analysis")
    comparison = report.get("comparison")
    if not comparison:
        canvas.notice("info", "Provide --baseline to compare against a previous JSON inventory")
        return
    canvas.pair("Inventory changed", comparison["changed"])
    canvas.pair("Previously unique", comparison["previous_unique"])
    canvas.pair("Currently unique", comparison["current_unique"])
    canvas.pair("Unchanged", comparison["unchanged"])
    for title, key in (("New certificates", "added"), ("Removed certificates", "removed"),
                       ("Metadata differences", "metadata_changes")):
        entries = comparison[key]
        canvas.subsection(f"{title}: {len(entries)}")
        for item in entries[:args.top]:
            canvas.pair(item["sha256"][:20], shorten(item.get("subject") or item.get("differences"), 85))
        if len(entries) > args.top:
            canvas.write(f"Additional entries omitted: {len(entries) - args.top}")


def render_policy_inventory(canvas, report, args):
    canvas.section("18 / Local trust policy inventory")
    policy = report.get("system_policy")
    if not policy:
        canvas.notice("info", "Enable --inspect-policy to inspect local trust policy sources")
        return
    for tool, location in policy.get("tools", {}).items():
        canvas.pair(tool, location or "not installed")
    for entry in policy.get("paths", []):
        canvas.pair(entry["path"], "present" if entry.get("exists") else "missing")
    for key in ("trust_anchor_listing", "trust_blocklist_listing"):
        listing = policy.get(key)
        if listing:
            canvas.pair(key, f"exit={listing.get('exit_code', 'error')}; "
                        f"{len(listing.get('stdout', ''))} output characters")
    canvas.wrap("Trust listings are raw local policy observations; this report does not establish TLS application-specific trust decisions")


def render_verification_inventory(canvas, report, args):
    canvas.section("19 / Explicit offline chain verification")
    verification = report.get("verification")
    if not verification:
        canvas.notice("info", "Enable --verify-with PATH to perform offline OpenSSL verification")
        return
    canvas.pair("Reference CA bundle", verification["bundle"])
    for status in ("verified", "failed", "unavailable"):
        canvas.pair(status.title(), verification.get(status, 0))
    for item in verification["results"][:args.max_display]:
        canvas.pair(item["status"].upper(),
                    shorten(item.get("subject"), 65) + " / " + shorten(item.get("detail"), 80))
    canvas.wrap(verification["caveat"])


def certificate_identity(record):
    return {
        "fingerprint": record.get("sha256"),
        "subject": record.get("subject") or "",
        "issuer": record.get("issuer") or "",
        "serial": record.get("serial_number") or "",
    }


def build_issuer_graph(report):
    records = unique_certificates(report)
    by_subject = collections.defaultdict(list)
    by_issuer = collections.defaultdict(list)
    for record in records:
        by_subject[record.get("subject") or ""].append(record)
        by_issuer[record.get("issuer") or ""].append(record)
    nodes = []
    for record in records:
        subject = record.get("subject") or ""
        issuer = record.get("issuer") or ""
        candidates = [item for item in by_subject.get(issuer, [])
                      if item.get("sha256") != record.get("sha256")]
        nodes.append({
            "sha256": record.get("sha256"),
            "subject": subject,
            "issuer": issuer,
            "self_issued": subject == issuer,
            "issuer_name_candidates": [item.get("sha256") for item in candidates],
            "candidate_count": len(candidates),
            "issued_name_matches": len(by_issuer.get(subject, [])),
            "issuer_name_missing": not candidates and subject != issuer,
        })
    return {
        "nodes": nodes,
        "issuer_name_missing": sum(item["issuer_name_missing"] for item in nodes),
        "ambiguous_issuer_names": sum(item["candidate_count"] > 1 for item in nodes),
        "self_issued": sum(item["self_issued"] for item in nodes),
        "caveat": "Distinguished-name correlation only; no signature, path-length, AKI/SKI, or trust validation",
    }


def certificate_expiration_calendar(report):
    entries = []
    for record in unique_certificates(report):
        timestamp = parse_iso(record.get("not_after"))
        if timestamp is None:
            continue
        entries.append({
            "sha256": record["sha256"],
            "date": timestamp.date().isoformat(),
            "timestamp": timestamp.isoformat(),
            "subject": record.get("subject"),
            "issuer": record.get("issuer"),
            "source": record.get("path"),
        })
    entries.sort(key=lambda item: (item["timestamp"], item["sha256"]))
    return entries


def inspect_bundle_integrity(report):
    sources = []
    for file_record in report["files"]:
        path = pathlib.Path(file_record["path"])
        entry = {"path": str(path), "sha256": None, "bytes": None}
        try:
            if path.stat().st_size > 64 * 1024 * 1024:
                entry["error"] = "file exceeds integrity inspection limit"
            else:
                digest = hashlib.sha256()
                with path.open("rb") as stream:
                    while True:
                        chunk = stream.read(1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
                entry["sha256"] = digest.hexdigest()
                entry["bytes"] = path.stat().st_size
        except OSError as error:
            entry["error"] = str(error)
        sources.append(entry)
    return sources


def summarize_key_families(report):
    families = collections.Counter()
    sizes = collections.defaultdict(collections.Counter)
    for record in unique_certificates(report):
        detail = record.get("openssl") or {}
        algorithm = (detail.get("public_key_algorithm") or "unknown").lower()
        if "rsa" in algorithm:
            family = "RSA"
        elif "ec" in algorithm or "elliptic" in algorithm:
            family = "EC"
        elif "ed25519" in algorithm:
            family = "Ed25519"
        elif "ed448" in algorithm:
            family = "Ed448"
        elif "dsa" in algorithm:
            family = "DSA"
        else:
            family = "Other/unknown"
        families[family] += 1
        sizes[family][str(detail.get("public_key_bits") or "unknown")] += 1
    return {"families": dict(families),
            "sizes": {key: dict(counter) for key, counter in sizes.items()}}


def summarize_validity_windows(report):
    periods = []
    for record in unique_certificates(report):
        start = parse_iso(record.get("not_before"))
        end = parse_iso(record.get("not_after"))
        if start is None or end is None:
            continue
        periods.append({"sha256": record["sha256"],
                        "subject": record.get("subject"),
                        "validity_days": round((end - start).total_seconds() / 86400, 2)})
    periods.sort(key=lambda item: (item["validity_days"], item["sha256"]))
    return {"shortest": periods[:20], "longest": list(reversed(periods[-20:])),
            "total_with_validity": len(periods)}


def render_issuer_graph(canvas, report, args):
    canvas.section("20 / Issuer distinguished-name correlation")
    graph = report.get("issuer_graph")
    if not graph:
        canvas.notice("info", "Issuer correlation unavailable")
        return
    canvas.pair("Self-issued names", graph["self_issued"])
    canvas.pair("Issuer names without candidates", graph["issuer_name_missing"])
    canvas.pair("Ambiguous issuer names", graph["ambiguous_issuer_names"])
    selected = [node for node in graph["nodes"] if node["issuer_name_missing"]
                or node["candidate_count"] > 1]
    for node in selected[:args.top]:
        canvas.pair(shorten(node["subject"], 38),
                    f"issuer candidates={node['candidate_count']}; issuer={shorten(node['issuer'], 70)}")
    canvas.wrap(graph["caveat"])


def render_integrity(canvas, report, args):
    canvas.section("21 / Source bundle integrity fingerprints")
    entries = report.get("bundle_integrity") or []
    if not entries:
        canvas.notice("info", "No source bundle integrity information")
        return
    for entry in entries[:args.max_display]:
        canvas.subsection(shorten(entry["path"], 90))
        canvas.pair("SHA-256", entry.get("sha256") or "unavailable")
        canvas.pair("Size", entry.get("bytes"))
        if entry.get("error"):
            canvas.pair("Error", entry["error"])


def render_key_families(canvas, report, args):
    canvas.section("22 / Cryptographic key-family breakdown")
    families = report.get("key_families") or {}
    canvas.table(["Key family", "Count"],
                 sorted(families.get("families", {}).items(), key=lambda x: (-x[1], x[0])),
                 widths=[30, 12])
    for family, sizes in sorted(families.get("sizes", {}).items()):
        canvas.subsection(family)
        canvas.table(["Reported key bits", "Count"],
                     sorted(sizes.items(), key=lambda x: (-x[1], x[0])), widths=[25, 12])


def render_validity_windows(canvas, report, args):
    canvas.section("23 / Certificate validity-period extremes")
    windows = report.get("validity_windows") or {}
    canvas.pair("Records with complete validity", windows.get("total_with_validity", 0))
    for title, key in (("Shortest validity periods", "shortest"),
                       ("Longest validity periods", "longest")):
        canvas.subsection(title)
        canvas.table(["Subject", "Days"],
                     [(shorten(item["subject"], 70), item["validity_days"])
                      for item in windows.get(key, [])[:args.top]], widths=[70, 15])


def render_expiration_calendar(canvas, report, args):
    canvas.section("24 / Chronological certificate expiration register")
    calendar = report.get("expiration_calendar") or []
    canvas.pair("Dated certificates", len(calendar))
    canvas.table(["Expiration date", "Subject"],
                 [(item["date"], shorten(item["subject"], 78))
                  for item in calendar[:args.max_display]], widths=[18, 78])
    if len(calendar) > args.max_display:
        canvas.write(f"Additional records omitted: {len(calendar) - args.max_display}")


def enhanced_main(argv=None):
    parser = enhanced_parser()
    args = parser.parse_args(argv)
    validate_enhanced_arguments(parser, args)
    args.paths = args.paths or resolve_default_paths()
    if not args.paths:
        parser.error("No default CA bundle found; specify a certificate path")
    try:
        paths, discovery_errors = discover(
            args.paths,
            args.recursive,
            args.max_files,
        )
        records, files, scan_errors = scan(paths, args)
        report = build_report(
            records,
            files,
            discovery_errors + scan_errors,
            args,
        )
        enrich_report(report, args)
        export_enhanced(report, args)
        if args.write_baseline:
            write_atomic(args.write_baseline, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    except BrokenPipeError:
        return 0
    except (OSError, ValueError) as error:
        print(f"ca-trust-auditor: {error}", file=sys.stderr)
        return 2
    if args.fail_on_change and report.get("comparison", {}).get("changed"):
        return 3
    if args.strict and report.get("audit", {}).get("critical_count", 0):
        return 3
    if args.strict_expiring and report["summary"]["expiring_soon"]:
        return 3
    if args.strict_crypto and report.get("audit", {}).get("crypto_count", 0):
        return 3
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    sys.exit(enhanced_main())
