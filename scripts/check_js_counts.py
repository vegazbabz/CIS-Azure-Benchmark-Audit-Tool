import cis_azure_audit
from cis_azure_audit import R, PASS

res = [
    R(
        control_id="1.1",
        level=1,
        title="t",
        subscription_name="sub",
        resource="",
        status=PASS,
        details="d",
        remediation="",
        section="sec",
    )
]

cis_azure_audit.generate_html(res, "test.html")
with open("test.html", "r", encoding="utf-8") as f:
    for line in f:
        if "JS_COUNTS" in line:
            print(line)
