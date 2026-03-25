"""Fix conditional resource fields in check files.

Changes patterns like `aname if not compliant else ""` to just `aname`
so that PASS results include the resource name and don't get deduped.
"""

import re


def fix_file(path: str, replacements: list[tuple[str, str]]) -> int:
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    count = 0
    for old, new in replacements:
        if old in content:
            content = content.replace(old, new)
            count += 1

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

    return count


# ── s9.py ──────────────────────────────────────────────────────────────────
s9_replacements = [
    ('aname if not compliant else "",', "aname,"),
    ('aname if not _sd_ok else "",', "aname,"),
    ('aname if not _cd_ok else "",', "aname,"),
    ('aname if not ver else "",', "aname,"),
    ('aname if not flag else "",', "aname,"),
    ('aname if _log_status == ERROR else "",', "aname,"),
    ('aname if _blob_status == ERROR else "",', "aname,"),
    ('aname if not _fs_ok else "",', "aname,"),
    ('aname if not has_good_ver and smb else "",', "aname,"),
    ('aname if not has_good_enc and smb else "",', "aname,"),
    ('aname if _file_status == ERROR else "",', "aname,"),
    ('aname if not reminder_days else "",', "aname,"),
    ('aname if not rotated else "",', "aname,"),
    ('aname if not has_delete else "",', "aname,"),
    ('aname if not has_read else "",', "aname,"),
]
n = fix_file("checks/s9.py", s9_replacements)
print(f"s9.py: {n} replacements")

# ── s7.py ──────────────────────────────────────────────────────────────────
s7_replacements = [
    ('name if bad else "",', "name,"),
    ('fname if not ok else "",', "fname,"),
    # Application gateways — these are inline expressions, not simple var names
]
n = fix_file("checks/s7.py", s7_replacements)
print(f"s7.py: {n} replacements (simple patterns)")

# For gw/pol patterns, do regex
with open("checks/s7.py", "r", encoding="utf-8") as f:
    content = f.read()

gw_count = 0
# gw.get("name", "") if not SOMETHING else ""
# Replace with gw.get("name", "")
for pattern, repl in [
    (
        r'gw\.get\("name", ""\) if not \(gw\.get\("wafEnabled"\) or gw\.get\("wafPolicyId"\)\) else ""',
        'gw.get("name", "")',
    ),
    (
        r'gw\.get\("name", ""\) if str\(gw\.get\("sslMinProto", ""\)\)\.lower\(\) not in GOOD_PROTOS else ""',
        'gw.get("name", "")',
    ),
    (r'gw\.get\("name", ""\) if not gw\.get\("enableHttp2"\) else ""', 'gw.get("name", "")'),
    (r'gw\.get\("name", ""\) if not gw\.get\("wafReqBody"\) else ""', 'gw.get("name", "")'),
    (
        r'pol\.get\("name", ""\) if str\(pol\.get\("botEnabled", ""\)\)\.lower\(\) != "prevention" else ""',
        'pol.get("name", "")',
    ),
]:
    new_content = re.sub(pattern, repl, content)
    if new_content != content:
        gw_count += 1
        content = new_content
with open("checks/s7.py", "w", encoding="utf-8") as f:
    f.write(content)
print(f"s7.py: {gw_count} gateway/policy replacements")

# ── s8.py ──────────────────────────────────────────────────────────────────
s8_replacements = [
    ('vname if not purge else "",', "vname,"),
    ('vname if not is_rbac else "",', "vname,"),
    ('vname if not exp else "",', "vname,"),
    ('vname if not has_rotate else "",', "vname,"),
    ('vname if not ok else "",', "vname,"),
]
n = fix_file("checks/s8.py", s8_replacements)
print(f"s8.py: {n} replacements (simple patterns)")

with open("checks/s8.py", "r", encoding="utf-8") as f:
    content = f.read()

s8_count = 0
for pattern, repl in [
    (r'vname if str\(pub\)\.lower\(\) != "disabled" else ""', "vname"),
    (r'vname if pe_count == 0 else ""', "vname"),
    (r'v\.get\("name", ""\) if not v\.get\("hasDdos"\) else ""', 'v.get("name", "")'),
]:
    new_content = re.sub(pattern, repl, content)
    if new_content != content:
        s8_count += 1
        content = new_content
with open("checks/s8.py", "w", encoding="utf-8") as f:
    f.write(content)
print(f"s8.py: {s8_count} complex replacements")

print("\nDone! Run black and tests to verify.")
