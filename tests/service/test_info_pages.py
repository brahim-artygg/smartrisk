from pathlib import Path


def test_contact_and_privacy_pages_exist():
    root = Path(__file__).resolve().parents[2] / "smartrisk" / "web"
    assert (root / "contact.html").is_file()
    assert (root / "privacy.html").is_file()
    assert (root / "info.css").is_file()


def test_info_pages_have_human_content_and_navigation():
    root = Path(__file__).resolve().parents[2] / "smartrisk" / "web"
    contact = (root / "contact.html").read_text()
    privacy = (root / "privacy.html").read_text()
    assert "We’d like to hear from you." in contact
    assert "support@smartrisk.io" in contact
    assert "Security reports" in contact
    assert "How SmartRisk handles your information" in privacy
    assert "We do not require an account simply to run a scan." in privacy
    assert "Resend" in privacy
    assert "Last updated: September 21, 2026" in privacy


def test_full_site_page_set_exists_and_is_linked():
    root = Path(__file__).resolve().parents[2] / "smartrisk" / "web"
    pages = ["about.html", "security.html", "terms.html", "how-it-works.html", "methodology.html", "supported-networks.html", "risk-library.html", "faq.html", "disclaimer.html"]
    for page in pages:
        assert (root / page).is_file()
    landing = (root / "index.html").read_text()
    footer_checks = ["/about", "/security", "/privacy", "/terms", "/contact", "/how-it-works", "/methodology", "/supported-networks", "/risk-library", "/faq", "/disclaimer"]
    for href in footer_checks:
        assert f'href="{href}"' in landing
    assert "Risk signals are stronger when the evidence agrees." in (root / "methodology.html").read_text()
    assert "No. The scanner is intentionally open." in (root / "faq.html").read_text()
