import ipaddress
import math
from collections import Counter
from urllib.parse import urlparse


def normalize_url(url):
    url = str(url).strip()

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    return url


def calculate_entropy(text):
    if not text:
        return 0.0

    probabilities = [
        count / len(text)
        for count in Counter(text).values()
    ]

    return -sum(
        p * math.log2(p)
        for p in probabilities
    )


def is_ip_address(hostname):
    if not hostname:
        return 0

    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


def extract_url_features(url):

    original_url = str(url).strip()
    normalized_url = normalize_url(original_url)

    parsed = urlparse(normalized_url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    features = {}

    # Length features
    features["url_length"] = len(original_url)
    features["domain_length"] = len(hostname)
    features["path_length"] = len(path)
    features["query_length"] = len(query)

    # Character counts
    features["dot_count"] = original_url.count(".")
    features["hyphen_count"] = original_url.count("-")
    features["underscore_count"] = original_url.count("_")
    features["slash_count"] = original_url.count("/")
    features["question_count"] = original_url.count("?")
    features["equal_count"] = original_url.count("=")
    features["ampersand_count"] = original_url.count("&")
    features["at_count"] = original_url.count("@")
    features["percent_count"] = original_url.count("%")

    # Digits and letters
    features["digit_count"] = sum(
        char.isdigit() for char in original_url
    )

    features["letter_count"] = sum(
        char.isalpha() for char in original_url
    )

    if len(original_url) > 0:
        features["digit_ratio"] = (
            features["digit_count"] / len(original_url)
        )

        features["letter_ratio"] = (
            features["letter_count"] / len(original_url)
        )
    else:
        features["digit_ratio"] = 0
        features["letter_ratio"] = 0

    # Protocol/domain
    features["is_https"] = int(
        parsed.scheme.lower() == "https"
    )

    features["is_domain_ip"] = is_ip_address(hostname)

    # Subdomains
    hostname_parts = hostname.split(".")

    if features["is_domain_ip"]:
        features["subdomain_count"] = 0
    elif len(hostname_parts) > 2:
        features["subdomain_count"] = len(hostname_parts) - 2
    else:
        features["subdomain_count"] = 0

    # Suspicious words
    suspicious_words = [
        "login",
        "signin",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "bank",
        "payment",
        "confirm",
        "password",
        "credential",
        "wallet"
    ]

    lower_url = original_url.lower()

    features["suspicious_word_count"] = sum(
        word in lower_url
        for word in suspicious_words
    )

    # Entropy
    features["url_entropy"] = calculate_entropy(original_url)

    return features