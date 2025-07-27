import os
import re
import sys
import zipfile
import json
import time
import argparse

SUSPICIOUS_PATTERNS = [
    r"http://",
    r"https://",
    r"spawn\s*\(",
    r"os\.execute\s*\(",
    r"irc",
    r"telnet",
    r"io\.open\s*\(",
    r"socket\.tcp",
    r"socket\.connect",
    r"socket\.http",
    r"http\.request",
]

ALLOWED_EXTS = (".mpackage", ".zip", ".lua", ".xml", ".txt", ".json", ".md")


def scan_content(content):
    found = []
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            found.append(pattern)
    return found


def scan_package(path):
    results = {}
    archive_exts = (".mpackage", ".zip")
    text_exts = (".lua", ".xml", ".txt", ".json", ".md")

    if path.lower().endswith(archive_exts):
        try:
            with zipfile.ZipFile(path) as z:
                for name in z.namelist():
                    if not name.lower().endswith(text_exts):
                        continue
                    try:
                        data = z.read(name).decode("utf-8", errors="ignore")
                    except Exception:
                        continue
                    res = scan_content(data)
                    if res:
                        results[name] = res
        except zipfile.BadZipFile:
            pass
    else:
        if not path.lower().endswith(text_exts):
            return results
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                data = f.read()
            res = scan_content(data)
            if res:
                results[path] = res
        except Exception:
            pass
    return results


def get_not_scanned_packages(index_file):
    try:
        with open(index_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return [os.path.join("packages", p["filename"]) for p in data.get("packages", []) if p.get("scan_status") == "Not Scanned"]
    except Exception:
        return []


def main(args):
    suspicious = {}

    if args.only_not_scanned:
        files_to_scan = get_not_scanned_packages("packages/mpkg.packages.json")
    else:
        files_to_scan = []
        for root, dirs, files in os.walk("packages"):
            for f in files:
                if os.path.splitext(f)[1].lower() in ALLOWED_EXTS:
                    files_to_scan.append(os.path.join(root, f))

    for file_path in files_to_scan:
        res = scan_package(file_path)
        if res:
            suspicious[file_path] = res
        time.sleep(args.throttle)
    if suspicious:
        print("Suspicious patterns detected:")
        for pkg, res in suspicious.items():
            print(f"{pkg} ->")
            for file, patterns in res.items():
                pattern_list = ", ".join(patterns)
                print(f"  {file}: {pattern_list}")
        sys.exit(1)
    else:
        print("No suspicious patterns found.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan Mudlet packages for suspicious content")
    parser.add_argument("--only-not-scanned", action="store_true", help="Scan only packages marked as Not Scanned")
    parser.add_argument("--throttle", type=float, default=float(os.environ.get("THROTTLE_SECONDS", 1)), help="Seconds to sleep between scanning each package")
    main(parser.parse_args())
