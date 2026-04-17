TRUSTED_DOMAINS = {
    "polito.it",
    "microsoft.com",
    "google.com",
    "amazon.com",
    "paypal.com",
    "apple.com",
    "netflix.com",
    "instagram.com",
    "facebook.com",
    "twitter.com",
    "linkedin.com",
    "github.com",
    "students.polito.it",
}

BRAND_TO_DOMAIN = {
    "microsoft": "microsoft.com",
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "google": "google.com",
    "netflix": "netflix.com",
    "instagram": "instagram.com",
    "facebook": "facebook.com",
    "twitter": "twitter.com",
    "linkedin": "linkedin.com",
    "github": "github.com",
    "polito": "polito.it",
}

URGENCY_KEYWORDS = [
    "urgent",
    "immediately",
    "today",
    "right now",
    "within 10 minutes",
    "account will be disabled",
    "time-sensitive",
    "confirm now",
    "on hold",
    "as soon as possible",
    "asap",
    "act now",
    "last chance",
    "expires soon",
    "suspended",
    "limited time",
    "deadline",
]

CREDENTIAL_KEYWORDS = [
    "password",
    "credentials",
    "login",
    "username",
    "verification code",
    "account confirmation",
    "sign in",
    "verify your identity",
    "reset your password",
    "enter your",
    "authenticate",
]

PAYMENT_KEYWORDS = [
    "transfer",
    "payment",
    "invoice",
    "bank details",
    "wire",
    "gift card",
    "send money",
    "bitcoin",
    "crypto",
    "billing",
    "charge",
    "refund",
    "transaction",
    "wallet",
]

DANGEROUS_ATTACHMENT_TYPES = {
    "executable",
    "script",
    "archive",
    "spreadsheet_macro_enabled",
    "macro_enabled",
    "document_macro_enabled",
    "unknown",
}

SUSPICIOUS_TLDS = {
    ".ru", ".xyz", ".tk", ".top", ".ml", ".cf", ".gq", ".click", ".loan",
}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "ow.ly",
    "goo.gl",
    "rb.gy",
    "short.io",
    "is.gd",
    "buff.ly",
    "tiny.cc",
    "lnkd.in",
    "cutt.ly",
}

WEIGHTS = {
    "lookalike_domain": 30,
    "credential_request": 30,
    "payment_request": 25,
    "dangerous_attachment": 25,
    "authority_impersonation": 25,
    "suspicious_or_unknown_sender": 20,
    "urgent_language": 20,
    "suspicious_link": 20,
    "non_https_link": 20,
    "external_link_inconsistent": 20,
    "display_text_destination_mismatch": 20,
    "suspicious_phone_pattern": 15,
    "suspicious_shortening_service": 15,
}

THRESHOLDS = {
    "legitimate": 20,
    "suspicious": 50,
}
