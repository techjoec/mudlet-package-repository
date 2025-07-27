import zipfile
import re
from pathlib import Path
import csv
import dns.resolver

PATTERNS = {
    # explicit function calls that could execute external processes
    'Process Spawning': [
        (r'\bos\.execute\s*\(', 'os.execute'),
        (r'\bio\.popen\s*\(', 'io.popen'),
        (r'\bspawn\s*\(', 'spawn'),
    ],
    # network activity via LuaSocket or Mudlet helpers
    'External Communications': [
        (r'require\s*\(?["\']socket\.http["\']\)?', 'require'),
        (r'\bsocket\.http\s*[\.:]', 'socket.http'),
        (r'\bopenUrl\s*\(', 'openUrl'),
        (r'\bdownloadFile\s*\(', 'downloadFile'),
    ],
    # literal addresses or URLs embedded in code
    'Network Identifiers': [
        (r'((?:https?|ftp)://[^\s"\']+)', ''),
        (r'((?:\d{1,3}\.){3}\d{1,3})', ''),
    ],
    # running code from strings or files
    'Unsafe Inputs': [
        (r'\bloadstring\s*\(', 'loadstring'),
        (r'\bdofile\s*\(', 'dofile'),
        (r'\bloadfile\s*\(', 'loadfile'),
        (r'\bload\s*\(', 'load'),
    ],
}

# packages that should be ignored during scanning
IGNORED_PACKAGES = {"MudletBusted.mpackage"}

CONTEXT_LINES = 2

PUBLIC_HOST_PATTERNS = [
    r"\.github\.io$",
    r"\.gitlab\.io$",
    r"\.bitbucket\.io$",
    r"gist\.github\.com$",
    r"pastebin\.com$",
    r"raw\.githubusercontent\.com$",
    r"\.amazonaws\.com$",
    r"\.cloudfront\.net$",
    r"\.azurewebsites\.net$",
    r"\.pages\.dev$",
]


def check_domain_status(domain: str) -> str:
    """Return status for a domain: Unregistered, Public Host, or Resolved."""
    if not domain:
        return ""
    try:
        dns.resolver.resolve(domain, "A")
        resolved = True
    except dns.resolver.NXDOMAIN:
        return "Unregistered"
    except Exception:
        resolved = False

    for pattern in PUBLIC_HOST_PATTERNS:
        if re.search(pattern, domain):
            return "Publicly Writable"

    return "Resolved" if resolved else "Unknown"


def remove_comments(text: str) -> str:
    """Strip Lua single-line and block comments."""
    lines = text.splitlines()
    result = []
    in_block = False
    for line in lines:
        i = 0
        out = ''
        while i < len(line):
            if not in_block and line.startswith('--[[', i):
                in_block = True
                i += 4
                continue
            if in_block:
                end = line.find(']]', i)
                if end == -1:
                    i = len(line)
                    continue
                i = end + 2
                in_block = False
                continue
            if line.startswith('--', i):
                break
            out += line[i]
            i += 1
        if not in_block:
            result.append(out)
        else:
            result.append(out)
    return '\n'.join(result)


def strip_description_blocks(text: str) -> str:
    """Remove multiline description strings used for documentation."""
    lines = text.splitlines()
    output = []
    in_desc = False
    for line in lines:
        if not in_desc and re.search(r'^\s*description\s*=\s*\[\[', line):
            in_desc = True
            if ']]' in line:
                in_desc = False
            continue
        if in_desc:
            if ']]' in line:
                in_desc = False
            continue
        output.append(line)
    return '\n'.join(output)


def find_matches(text, regexes):
    matches = []
    text = remove_comments(text)
    text = strip_description_blocks(text)
    lines = text.splitlines()
    for idx, line in enumerate(lines, 1):
        for category, regs in regexes.items():
            for reg, token in regs:
                m = re.search(reg, line)
                if m:
                    if token and (re.search(rf'(?:^|\s)(?:local\s+)?function\s+{re.escape(token)}\b', line) or \
                                 re.search(rf'{re.escape(token)}\s*=\s*function\b', line)):
                        continue
                    start = max(0, idx - CONTEXT_LINES - 1)
                    end = min(len(lines), idx + CONTEXT_LINES)
                    context = '\n'.join(lines[start:end])
                    address = ''
                    uri = ''
                    domain = ''
                    if category == 'Network Identifiers':
                        addr = m.group(1)
                        if re.match(r'^(?:https?|ftp)://', addr):
                            uri = addr
                            domain = re.sub(r'^(?:https?|ftp)://', '', addr)
                            domain = domain.split('/')[0]
                            address = domain
                        else:
                            domain = addr
                            address = addr
                    matches.append((idx, context, line.strip(), m.group(0), category, address, domain, uri))
    return matches


def scan_package(path):
    results = []
    try:
        with zipfile.ZipFile(path) as z:
            for member in z.namelist():
                if not member.lower().endswith('.lua'):
                    continue
                with z.open(member) as f:
                    text = f.read().decode('utf-8', errors='ignore')
                matches = find_matches(text, PATTERNS)
                for idx, context, line, match, category, address, domain, uri in matches:
                    results.append({
                        'package': path.name,
                        'file': member,
                        'line_number': idx,
                        'context': context,
                        'matched': match,
                        'category': category,
                        'address': address,
                        'domain': domain,
                        'uri': uri,
                        'domain_status': check_domain_status(domain),
                    })
    except zipfile.BadZipFile:
        pass
    return results


def write_html(results, path='scan_report.html'):
    """Write a human readable HTML report."""
    with open(path, 'w', encoding='utf-8') as f:
        f.write('<!DOCTYPE html><html><head><meta charset="utf-8">')
        f.write('<title>Scan Report</title>')
        f.write('<style>table{border-collapse:collapse} th,td{border:1px solid #ccc;padding:4px;} th{background:#eee}</style>')
        f.write('</head><body>')
        f.write('<h1>Scan Report</h1>')
        if not results:
            f.write('<p>No matches found.</p>')
            f.write('</body></html>')
            return

        f.write('<table>')
        headers = ['Package', 'File', 'Line', 'Category', 'Match', 'Address', 'Domain/IP', 'Domain Status', 'URI', 'Context']
        f.write('<tr>' + ''.join(f'<th>{h}</th>' for h in headers) + '</tr>')
        for row in results:
            context = (row['context']
                        .replace('&', '&amp;')
                        .replace('<', '&lt;')
                        .replace('>', '&gt;')
                        .replace('\n', '<br>'))
            f.write('<tr>'
                    f'<td>{row["package"]}</td>'
                    f'<td>{row["file"]}</td>'
                    f'<td>{row["line_number"]}</td>'
                    f'<td>{row["category"]}</td>'
                    f'<td>{row["matched"]}</td>'
                    f'<td>{row.get("address", "")}</td>'
                    f'<td>{row.get("domain", "")}</td>'
                    f'<td>{row.get("domain_status", "")}</td>'
                    f'<td>{row.get("uri", "")}</td>'
                    f'<td>{context}</td>'
                    '</tr>')
        f.write('</table></body></html>')


def write_csv(results, path='scan_report.csv'):
    """Write a CSV report with simple headers."""
    headers = ['Package', 'File', 'Line', 'Category', 'Match', 'Address', 'Domain/IP', 'Domain Status', 'URI', 'Context']
    with open(path, 'w', encoding='utf-8', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(headers)
        for row in results:
            writer.writerow([
                row['package'],
                row['file'],
                row['line_number'],
                row['category'],
                row['matched'],
                row.get('address', ''),
                row.get('domain', ''),
                row.get('domain_status', ''),
                row.get('uri', ''),
                row['context'].replace('\n', '\\n')
            ])


def main():
    pkg_dir = Path('packages')
    package_files = [p for p in pkg_dir.glob('*.mpackage')] + list(pkg_dir.glob('*.zip'))
    package_files = [p for p in package_files if p.name not in IGNORED_PACKAGES]
    results = []
    for pkg in package_files:
        results.extend(scan_package(pkg))

    write_html(results)
    write_csv(results)


if __name__ == '__main__':
    main()
