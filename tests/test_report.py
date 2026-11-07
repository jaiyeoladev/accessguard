from accessguard.models import Finding
from accessguard.report import render_csv


def test_csv_neutralises_formula_injection():
    f = Finding("AG-001", "Dormant", "medium", "Dormant accounts", "id", "user", "=HYPERLINK(\"x\")",
                "summary", "why", "fix")
    body = render_csv([f], {})
    assert "'=HYPERLINK" in body
