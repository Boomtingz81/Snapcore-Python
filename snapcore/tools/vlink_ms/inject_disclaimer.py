#!/usr/bin/env python3
import os

DISCLAIMER = """# ⚠️ DISCLAIMER
# This software communicates directly with live vehicle systems.
# You use this software entirely at your own risk.
#
# The developers, contributors, and any associated parties accept no liability for:
# - Damage to vehicles, ECUs, batteries, or electronics
# - Data loss, unintended resets, or corrupted configurations
# - Physical injury, legal consequences, or financial loss
#
# This tool is intended only for qualified professionals who
# understand the risks of direct OBD/CAN access.
"""

# Folders we want to scan
TARGET_DIRS = ["snapcore", "protocol", "vag_black"]

# Folders to skip (tests, docs, etc.)
SKIP_DIRS = {"tests", "docs"}

def should_process(path: str) -> bool:
    parts = path.split(os.sep)
    return not any(skip in parts for skip in SKIP_DIRS)

def inject_disclaimer(file_path: str):
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Skip if disclaimer already present
    if "⚠️ DISCLAIMER" in content:
        print(f"✅ Already has disclaimer: {file_path}")
        return

    # Prepend disclaimer
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(DISCLAIMER.strip() + "\n\n" + content)

    print(f"🔒 Disclaimer added to: {file_path}")

def main():
    for base in TARGET_DIRS:
        for root, _, files in os.walk(base):
            if not should_process(root):
                continue
            for file in files:
                if file.endswith(".py"):
                    inject_disclaimer(os.path.join(root, file))

if __name__ == "__main__":
    main()
