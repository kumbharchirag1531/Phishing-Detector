import re


def normalize_url(url: str) -> str:
    """
    Strip the scheme (http://, https://) and a leading 'www.' so the
    classifier learns from the actual domain/path content instead of
    superficial prefixes that are unevenly distributed between the
    benign and phishing classes in the training data.
    """
    url = url.strip().lower()
    url = re.sub(r"^https?://", "", url)
    url = re.sub(r"^www\.", "", url)
    return url
