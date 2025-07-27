import os
import re
import sys
import zipfile

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


def scan_content(content):
    found = []
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            found.append(pattern)
    return found


def scan_package(path):
    results = {}
    if path.endswith(".mpackage"):
        try:
            with zipfile.ZipFile(path) as z:
                for name in z.namelist():
                    if not name.lower().endswith((".lua", ".xml", ".txt", ".json")):
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
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                data = f.read()
            res = scan_content(data)
            if res:
                results[path] = res
        except Exception:
            pass
    return results


def main():
    suspicious = {}
    for root, dirs, files in os.walk("packages"):
        for f in files:
            file_path = os.path.join(root, f)
            res = scan_package(file_path)
            if res:
                suspicious[file_path] = res
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
    main()
