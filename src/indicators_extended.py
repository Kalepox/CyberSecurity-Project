# ---------------------------------------------------------------------------
# indicators_extended.py
# Extended indicators beyond the Topic-C minimum set.
# These are imported by engine.py via ALL_INDICATORS.
# ---------------------------------------------------------------------------

from src.indicators import (
    check_suspicious_or_unknown_sender,
    check_lookalike_domain,
    check_urgent_language,
    check_credential_request,
    check_payment_request,
    check_suspicious_link,
    check_non_https_link,
    check_dangerous_attachment_type,
    _hit,
    _miss,
    _email_domain,
    _url_domain,
    _base_domain,
    _brand_in_text,
)
from src.knowledge_base import URL_SHORTENERS



# ── authority_impersonation ───────────────────────────────────────────────────

def check_authority_impersonation(message: dict) -> dict:
    """Detect when a sender claims to be a known brand but uses a mismatched domain."""
    name = "authority_impersonation"
    sender_name = message.get("sender_name") or ""
    sender_address = message.get("sender_address") or ""

    found = _brand_in_text(sender_name)
    if not found:
        return _miss(name)

    brand, expected_domain = found
    channel = (message.get("channel") or "").lower()

    if channel == "email":
        actual_domain = _email_domain(sender_address)
        if actual_domain and actual_domain != expected_domain:
            return _hit(
                name,
                f"sender claims to be {brand.title()} but uses domain "
                f"'{actual_domain}' instead of '{expected_domain}'",
            )
    else:
        if brand not in sender_address.lower():
            return _hit(
                name,
                f"sender claims to be {brand.title()} but identifier "
                f"'{sender_address}' does not match",
            )

    return _miss(name)


# ── external_link_inconsistent ───────────────────────────────────────────────

def check_external_link_inconsistent(message: dict) -> dict:
    """Flag email links that point to a domain unrelated to the sender's domain."""
    name = "external_link_inconsistent"

    if (message.get("channel") or "").lower() != "email":
        return _miss(name)

    sender_domain = _email_domain(message.get("sender_address") or "")
    if not sender_domain:
        return _miss(name)

    sender_base = _base_domain(sender_domain)

    for link in message.get("links") or []:
        link_domain = _url_domain(link.get("actual_url") or "")
        if link_domain and _base_domain(link_domain) != sender_base:
            return _hit(
                name,
                f"email from '{sender_domain}' contains a link to "
                f"unrelated domain '{link_domain}'",
            )

    return _miss(name)


# ── display_text_destination_mismatch ────────────────────────────────────────

def check_display_text_destination_mismatch(message: dict) -> dict:
    """Detect links whose display text implies a brand different from the actual URL."""
    name = "display_text_destination_mismatch"

    for link in message.get("links") or []:
        display = link.get("display_text") or ""
        actual_domain = _url_domain(link.get("actual_url") or "")

        found = _brand_in_text(display)
        if not found:
            continue

        brand, expected_domain = found
        if actual_domain and actual_domain != expected_domain:
            return _hit(
                name,
                f"link text '{display}' implies {expected_domain} "
                f"but points to '{actual_domain}'",
            )

    return _miss(name)


# ── suspicious_phone_pattern ─────────────────────────────────────────────────

def check_suspicious_phone_pattern(message: dict) -> dict:
    """Flag SMS messages whose sender is a long raw number instead of a short-code."""
    name = "suspicious_phone_pattern"

    if (message.get("channel") or "").lower() != "sms":
        return _miss(name)

    sender = message.get("sender_address") or ""
    normalized = sender.lstrip("+").replace(" ", "").replace("-", "")

    if normalized.isdigit() and len(normalized) >= 8:
        return _hit(
            name,
            f"SMS sender '{sender}' is a long-form number, "
            "not a typical service short-code",
        )

    return _miss(name)


# ── suspicious_shortening_service ────────────────────────────────────────────

def check_suspicious_shortening_service(message: dict) -> dict:
    """Flag links that use a URL-shortening service to hide the true destination."""
    name = "suspicious_shortening_service"

    for link in message.get("links") or []:
        domain = _url_domain(link.get("actual_url") or "")
        if domain in URL_SHORTENERS:
            return _hit(
                name,
                f"link uses URL shortening service '{domain}', "
                "which hides the true destination",
            )

    return _miss(name)


# ── Full indicator list consumed by engine.py ─────────────────────────────────

ALL_INDICATORS = [
    # Minimum required set (Topic C)
    check_suspicious_or_unknown_sender,
    check_lookalike_domain,
    check_urgent_language,
    check_credential_request,
    check_payment_request,
    check_suspicious_link,
    check_non_https_link,
    check_dangerous_attachment_type,
    # Extended indicators
    check_authority_impersonation,
    check_external_link_inconsistent,
    check_display_text_destination_mismatch,
    check_suspicious_phone_pattern,
    check_suspicious_shortening_service,
]
