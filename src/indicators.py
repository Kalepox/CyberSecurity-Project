from urllib.parse import urlparse

from src.knowledge_base import (
    BRAND_TO_DOMAIN,
    CREDENTIAL_KEYWORDS,
    DANGEROUS_ATTACHMENT_TYPES,
    PAYMENT_KEYWORDS,
    SUSPICIOUS_TLDS,
    TRUSTED_DOMAINS,
    URGENCY_KEYWORDS,
    URL_SHORTENERS,
    WEIGHTS,
)

def email_domain(address):
    if "@" in address:
        return address.split("@")[-1].lower()
    return ""

def url_domain(url):
    try:
        host = urlparse(url).netloc.lower()
        return host.removeprefix("www.")
    except Exception:
        return ""

def base_domain(domain):
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain

def distance_between(a, b):
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = curr
    return prev[-1]

def lookalike_of(domain):
    if not domain or domain in TRUSTED_DOMAINS:
        return None
    for trusted in TRUSTED_DOMAINS:
        if distance_between(domain, trusted) <= 2:
            return trusted
    return None

def brand_in(text):
    text_lower = text.lower()
    for brand, domain in BRAND_TO_DOMAIN.items():
        if brand in text_lower:
            return brand, domain
    return None

def scan(text, keywords):
    text_lower = text.lower()
    return [kw for kw in keywords if kw in text_lower]

def hit(name, evidence):
    return {"name": name, "weight": WEIGHTS[name], "evidence": evidence}

def check_suspicious_or_unknown_sender(message):
    channel = message["channel"]
    sender_name = message.get("sender_name") or ""
    sender_address = message.get("sender_address") or ""

    if channel == "email":
        domain = email_domain(sender_address)
        if domain and domain not in TRUSTED_DOMAINS:
            return hit(
                "suspicious_or_unknown_sender",
                f"sender domain '{domain}' is not in the trusted domain set",
            )

    elif channel == "sms":
        normalized = sender_address.lstrip("+").replace(" ", "")
        if normalized.isdigit() and len(normalized) > 7:
            return hit(
                "suspicious_or_unknown_sender",
                f"SMS sender '{sender_address}' is a long-form number, "
                "inconsistent with a named service sender",
            )

    elif channel == "social":
        address_lower = sender_address.lower()
        significant = [w for w in sender_name.lower().split() if len(w) > 2]
        missing = [w for w in significant if w not in address_lower]
        if missing:
            return hit(
                "suspicious_or_unknown_sender",
                f"sender '{sender_name}' uses handle '{sender_address}', "
                "which does not match the claimed name",
            )

    return None

def check_lookalike_domain(message):
    candidates = []

    if message["channel"] == "email":
        domain = email_domain(message.get("sender_address") or "")
        if domain:
            candidates.append(("sender domain", domain))

    for link in message.get("links") or []:
        domain = url_domain(link.get("actual_url") or "")
        if domain:
            candidates.append(("link domain", domain))

    for label, domain in candidates:
        trusted = lookalike_of(domain)
        if trusted:
            dist = distance_between(domain, trusted)
            return hit(
                "lookalike_domain",
                f"{label} '{domain}' resembles '{trusted}' (edit distance: {dist})",
            )

    return None

def check_urgent_language(message):
    subject = message.get("subject") or ""
    body = message.get("body") or ""

    in_subject = scan(subject, URGENCY_KEYWORDS)
    in_body = scan(body, URGENCY_KEYWORDS)

    if not in_subject and not in_body:
        return None

    parts = []
    if in_subject:
        parts.append("subject contains: " + ", ".join(in_subject))
    if in_body:
        parts.append("body contains: " + ", ".join(in_body))

    return hit("urgent_language", "urgency keywords found; " + "; ".join(parts))

def check_credential_request(message):
    text = (message.get("subject") or "") + " " + (message.get("body") or "")
    matches = scan(text, CREDENTIAL_KEYWORDS)
    if not matches:
        return None
    return hit(
        "credential_request",
        "credential-related terms found: " + ", ".join(matches),
    )

def check_payment_request(message):
    text = (message.get("subject") or "") + " " + (message.get("body") or "")
    matches = scan(text, PAYMENT_KEYWORDS)
    if not matches:
        return None
    return hit(
        "payment_request",
        "payment-related terms found: " + ", ".join(matches),
    )

def check_suspicious_link(message):
    for link in message.get("links") or []:
        domain = url_domain(link.get("actual_url") or "")
        if not domain:
            continue
        has_suspicious_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
        has_many_hyphens = domain.count("-") >= 2
        if has_suspicious_tld or has_many_hyphens:
            reason = "suspicious TLD" if has_suspicious_tld else "excessive hyphens in domain"
            return hit(
                "suspicious_link",
                f"link domain '{domain}' appears suspicious ({reason})",
            )
    return None

def check_non_https_link(message):
    for link in message.get("links") or []:
        url = link.get("actual_url") or ""
        if url.startswith("http://"):
            return hit(
                "non_https_link",
                f"link '{url}' uses http instead of https",
            )
    return None

def check_dangerous_attachment(message):
    for attachment in message.get("attachments") or []:
        att_type = attachment.get("type") or ""
        filename = attachment.get("filename") or ""
        if att_type in DANGEROUS_ATTACHMENT_TYPES:
            return hit(
                "dangerous_attachment",
                f"attachment '{filename}' has dangerous type '{att_type}'",
            )
    return None

def check_authority_impersonation(message):
    sender_name = message.get("sender_name") or ""
    sender_address = message.get("sender_address") or ""

    found = brand_in(sender_name)
    if not found:
        return None
    brand, expected_domain = found

    if message["channel"] == "email":
        actual_domain = email_domain(sender_address)
        if actual_domain and actual_domain != expected_domain:
            return hit(
                "authority_impersonation",
                f"sender claims to be {brand.title()} but uses domain "
                f"'{actual_domain}' instead of '{expected_domain}'",
            )
    else:
        if brand not in sender_address.lower():
            return hit(
                "authority_impersonation",
                f"sender claims to be {brand.title()} but "
                f"identifier '{sender_address}' does not match",
            )

    return None


def check_external_link_inconsistent(message):
    if message["channel"] != "email":
        return None

    sender_domain = email_domain(message.get("sender_address") or "")
    if not sender_domain:
        return None
    sender_base = base_domain(sender_domain)

    for link in message.get("links") or []:
        link_domain = url_domain(link.get("actual_url") or "")
        if link_domain and base_domain(link_domain) != sender_base:
            return hit(
                "external_link_inconsistent",
                f"email from '{sender_domain}' contains a link to "
                f"unrelated domain '{link_domain}'",
            )

    return None

def check_display_text_destination_mismatch(message):
    for link in message.get("links") or []:
        display = link.get("display_text") or ""
        actual_domain = url_domain(link.get("actual_url") or "")

        found = brand_in(display)
        if not found:
            continue
        brand, expected_domain = found

        if actual_domain and actual_domain != expected_domain:
            return hit(
                "display_text_destination_mismatch",
                f"link displays '{display}' (implies {expected_domain}) "
                f"but points to '{actual_domain}'",
            )

    return None

def check_suspicious_phone_pattern(message):
    if message["channel"] != "sms":
        return None

    sender = message.get("sender_address") or ""
    normalized = sender.lstrip("+").replace(" ", "")

    if normalized.isdigit() and len(normalized) >= 8:
        return hit(
            "suspicious_phone_pattern",
            f"SMS sender '{sender}' is a long-form number, "
            "not a typical service short code",
        )

    return None

def check_suspicious_shortening_service(message):
    for link in message.get("links") or []:
        domain = url_domain(link.get("actual_url") or "")
        if domain in URL_SHORTENERS:
            return hit(
                "suspicious_shortening_service",
                f"link uses URL shortening service '{domain}', "
                "which hides the true destination",
            )
    return None

ALL_INDICATORS = [
    check_suspicious_or_unknown_sender,
    check_lookalike_domain,
    check_urgent_language,
    check_credential_request,
    check_payment_request,
    check_suspicious_link,
    check_non_https_link,
    check_dangerous_attachment,
    check_authority_impersonation,
    check_external_link_inconsistent,
    check_display_text_destination_mismatch,
    check_suspicious_phone_pattern,
    check_suspicious_shortening_service,
]