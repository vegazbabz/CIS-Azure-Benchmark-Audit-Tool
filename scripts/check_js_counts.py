"""Sanity-check helper for HTML report JS count markers.

This script generates a tiny synthetic report and prints the line that
contains ``JS_COUNTS`` so developers can quickly verify the JavaScript
summary payload is present after template changes.
"""

import cis_azure_audit
from cis_azure_audit import R, PASS


def main() -> None:
    """Generate a minimal report and print the JS summary line.

    The generated file is intentionally small, so this utility can be run
    quickly during local development.
    """
    sample_results = [
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

    cis_azure_audit.generate_html(sample_results, "test.html")
    with open("test.html", "r", encoding="utf-8") as report_file:
        for line in report_file:
            if "JS_COUNTS" in line:
                print(line)


if __name__ == "__main__":
    main()
