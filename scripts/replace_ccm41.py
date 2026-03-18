#!/usr/bin/env python3
"""Replace the partial CCM-4.1 (27 controls) with the complete version (207 controls)."""
import re

FRAMEWORKS_FILE = "scanner/compliance/frameworks.py"

with open(FRAMEWORKS_FILE, "r") as f:
    content = f.read()

# Find the CCM-4.1 block: starts with "CCM-4.1": { and ends before the next top-level key or }
# The CCM-4.1 section includes the header comment
start_marker = '    # ═══════════════════════════════════════════════════════════════════\n    # CSA Cloud Controls Matrix (CCM) v4.1\n    # ═══════════════════════════════════════════════════════════════════\n    "CCM-4.1":'
end_marker = '\n}'  # The closing brace of FRAMEWORKS dict

# Find start of CCM section
start_idx = content.find('    # CSA Cloud Controls Matrix (CCM) v4.1')
if start_idx == -1:
    # Try alternative
    start_idx = content.find('"CCM-4.1":')
    if start_idx == -1:
        print("ERROR: Could not find CCM-4.1 section")
        exit(1)
    # Back up to the comment line before it
    prev_newline = content.rfind('\n', 0, start_idx)
    # Check if there's a comment header
    check_region = content[max(0, start_idx-300):start_idx]
    header_start = check_region.rfind('# ═══')
    if header_start >= 0:
        start_idx = max(0, start_idx-300) + header_start

# Find the end of the CCM-4.1 block
# It ends with "    },\n" followed by the closing "}\n" of FRAMEWORKS or the next framework
# We need to find the matching closing brace at the right indentation level
# The CCM block is at 4-space indent, its closing is "    },"
# Find the closing },\n after the CCM block
search_from = content.find('"CCM-4.1":', start_idx) + 10
brace_depth = 0
found_opening = False
end_idx = None

for i in range(search_from, len(content)):
    if content[i] == '{':
        brace_depth += 1
        found_opening = True
    elif content[i] == '}':
        brace_depth -= 1
        if found_opening and brace_depth == 0:
            # Found the closing brace of CCM-4.1's value dict
            # Include the trailing comma and newline
            end_idx = i + 1
            if end_idx < len(content) and content[end_idx] == ',':
                end_idx += 1
            if end_idx < len(content) and content[end_idx] == '\n':
                end_idx += 1
            break

if end_idx is None:
    print("ERROR: Could not find end of CCM-4.1 block")
    exit(1)

# Read the new CCM content
with open("/tmp/ccm41_framework.py") as f:
    new_ccm = f.read()

# Replace
old_section = content[start_idx:end_idx]
print(f"Replacing {len(old_section)} chars ({old_section[:80]}...)")
print(f"With {len(new_ccm)} chars")

new_content = content[:start_idx] + new_ccm + "\n" + content[end_idx:]

with open(FRAMEWORKS_FILE, "w") as f:
    f.write(new_content)

print("Successfully replaced CCM-4.1 with full 207-control version")
