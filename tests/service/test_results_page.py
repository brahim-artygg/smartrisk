from pathlib import Path


def test_results_page_assets_exist():
    root = Path(__file__).resolve().parents[2] / "smartrisk" / "web"
    assert (root / "results.html").is_file()
    assert (root / "results.css").is_file()
    assert (root / "results.js").is_file()


def test_results_page_has_report_modules():
    html = (Path(__file__).resolve().parents[2] / "smartrisk" / "web" / "results.html").read_text()
    assert "Honeypot" in html
    assert "Liquidity" in html
    assert "Holders" in html
    assert "Ownership" in html
    assert "Permissions matrix" in html
    assert "Vulnerability inventory" in html
    assert "Technical checks" in html
