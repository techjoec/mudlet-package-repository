import zipfile
import re
import csv
import random
from pathlib import Path

PATTERNS = {
    'Process Spawning': [r'\bos\.execute\b', r'\bio\.popen\b', r'\bspawn\b'],
    'External Communications': [r'socket\.http', r'https?://'],
    'Unsafe Inputs': [r'\bloadstring\b', r'\bdofile\b', r'\bloadfile\b'],
}

CONTEXT_LINES = 2
MAX_MATCHES = 10


def find_matches(text, regexes, remaining):
    matches = []
    lines = text.splitlines()
    for idx, line in enumerate(lines, 1):
        for category, regs in regexes.items():
            for reg in regs:
                m = re.search(reg, line)
                if m:
                    start = max(0, idx - CONTEXT_LINES - 1)
                    end = min(len(lines), idx + CONTEXT_LINES)
                    context = '\n'.join(lines[start:end])
                    matches.append((idx, context, line.strip(), m.group(0), category))
                    if len(matches) >= remaining:
                        return matches
    return matches


def scan_package(path, remaining):
    results = []
    try:
        with zipfile.ZipFile(path) as z:
            for member in z.namelist():
                if not member.lower().endswith('.lua'):
                    continue
                with z.open(member) as f:
                    text = f.read().decode('utf-8', errors='ignore')
                matches = find_matches(text, PATTERNS, remaining - len(results))
                for idx, context, line, match, category in matches:
                    results.append({
                        'package': path.name,
                        'file': member,
                        'line_number': idx,
                        'context': context,
                        'matched': match,
                        'category': category,
                    })
                    if len(results) >= remaining:
                        return results
    except zipfile.BadZipFile:
        pass
    return results


def main():
    pkg_dir = Path('packages')
    package_files = list(pkg_dir.glob('*.mpackage')) + list(pkg_dir.glob('*.zip'))
    random.shuffle(package_files)
    results = []
    for pkg in package_files:
        remaining = MAX_MATCHES - len(results)
        if remaining <= 0:
            break
        results.extend(scan_package(pkg, remaining))
        if len(results) >= MAX_MATCHES:
            break

    with open('scan_report.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['package', 'file', 'line_number', 'category', 'matched', 'context'])
        writer.writeheader()
        for row in results:
            writer.writerow(row)


if __name__ == '__main__':
    main()
