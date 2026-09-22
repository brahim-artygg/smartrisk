import re
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


def test_public_pages_are_english_and_search_ready():
    root = Path(__file__).resolve().parents[2] / "smartrisk" / "web"
    public = ["index.html", "about.html", "how-it-works.html", "methodology.html", "faq.html", "risk-library.html", "security.html", "supported-networks.html", "contact.html", "privacy.html", "terms.html", "disclaimer.html"]
    arabic = re.compile(r"[\u0600-\u06ff]")
    for page in public:
        html = (root / page).read_text()
        assert '<html lang="en">' in html
        assert 'name="robots" content="index, follow' in html
        assert 'rel="canonical"' in html
        assert 'property="og:title"' in html
        assert 'name="twitter:card" content="summary_large_image"' in html
        assert 'type="application/ld+json"' in html
        assert not arabic.search(html)


def test_private_pages_are_noindex():
    root = Path(__file__).resolve().parents[2] / "smartrisk" / "web"
    for page in ["auth.html", "developer.html", "admin.html", "results.html", "embed.html"]:
        html = (root / page).read_text()
        assert 'name="robots" content="noindex, nofollow' in html
        assert not re.search(r"[\u0600-\u06ff]", html)


def test_crawl_and_brand_assets_exist():
    root = Path(__file__).resolve().parents[2] / "smartrisk" / "web"
    assert (root / "robots.txt").is_file()
    assert (root / "sitemap.xml").is_file()
    assert (root / "favicon.ico").is_file()
    assert (root / "favicon-96x96.png").is_file()
    assert (root / "apple-touch-icon.png").is_file()
    assert (root / "site.webmanifest").is_file()
    assert (root / "og-image.png").is_file()
    robots = (root / "robots.txt").read_text()
    assert "Sitemap: https://smartrisk.io/sitemap.xml" in robots
    assert "Disallow: /v1/" in robots
    sitemap = (root / "sitemap.xml").read_text()
    assert "https://smartrisk.io/" in sitemap
    assert "https://smartrisk.io/about" in sitemap
    assert "https://smartrisk.io/faq" in sitemap
    assert "https://smartrisk.io/sitemap.xml" not in sitemap
