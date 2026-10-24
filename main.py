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
    return add_enhanced_arguments(parser)


def validate_enhanced_arguments(parser, args):
    for key in ("max_bytes", "max_files", "max_display", "top", "months"):
        if getattr(args, key) <= 0:
            parser.error(f"--{key.replace('_', '-')} must be positive")
    if args.width < 64 or args.width > 300:
        parser.error("--width must be between 64 and 300")
    if args.warn_days < 0:
        parser.error("--warn-days must not be negative")
    allowed = {
        "dashboard", "status", "expiration", "timeline", "signatures",
        "keys", "issuers", "subjects", "files", "findings", "duplicates",
        "crypto", "certificates", "errors", "interpretation",
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
        export_enhanced(report, args)
    except BrokenPipeError:
        return 0
    except (OSError, ValueError) as error:
        print(f"ca-trust-auditor: {error}", file=sys.stderr)
        return 2
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    sys.exit(enhanced_main())
