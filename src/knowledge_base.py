TRUSTED_DOMAINS = {
    "polito.it",
    "students.polito.it",
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
    "dropbox.com",
    "adobe.com",
    "zoom.us",
}

TRUSTED_SENDER_IDS = {
    "PAYPAL",
    "AMAZON",
    "GOOGLE",
    "APPLE",
    "MSFT",
    "FEDEX",
    "UPS",
    "USPS",
    "AMZN",
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
    "dropbox": "dropbox.com",
    "adobe": "adobe.com",
    "zoom": "zoom.us",
}

URGENCY_KEYWORDS = [
    "urgent",
    "immediately",
    "right now",
    "within 24 hours",
    "within 10 minutes",
    "account will be disabled",
    "account suspended",
    "time-sensitive",
    "confirm now",
    "on hold",
    "as soon as possible",
    "asap",
    "act now",
    "last chance",
    "expires soon",
    "limited time",
    "deadline",
    "final notice",
    "action required",
    "respond immediately",
    "failure to act",
    "your account will be closed",
]

CREDENTIAL_KEYWORDS = [
    "password",
    "credentials",
    "login",
    "log in",
    "username",
    "verification code",
    "account confirmation",
    "sign in",
    "verify your identity",
    "reset your password",
    "enter your",
    "authenticate",
    "two-factor",
    "2fa",
    "one-time code",
    "otp",
    "security question",
    "confirm your account",
]

PAYMENT_KEYWORDS = [
    "transfer",
    "payment",
    "invoice",
    "bank details",
    "wire transfer",
    "gift card",
    "send money",
    "bitcoin",
    "crypto",
    "billing",
    "charge",
    "refund",
    "transaction",
    "wallet",
    "bank account",
    "routing number",
    "credit card",
    "debit card",
    "paypal",
    "venmo",
    "zelle",
]

DANGEROUS_ATTACHMENT_TYPES = {
    "executable",   
    "script",            
    "archive",           
    "macro_enabled",     
    "spreadsheet_macro_enabled",
    "document_macro_enabled",
    "unknown",           
}

SUSPICIOUS_TLDS = {
    ".ru", ".xyz", ".tk", ".top", ".ml", ".cf", ".gq",
    ".click", ".loan", ".win", ".work", ".bid", ".stream",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl",
    "rb.gy", "short.io", "is.gd", "buff.ly", "tiny.cc",
    "lnkd.in", "cutt.ly",
}

LOOKALIKE_PATTERNS = {
    "paypa1":     "paypal.com",
    "paypai":     "paypal.com",
    "micosoft":   "microsoft.com",
    "micros0ft":  "microsoft.com",
    "amaz0n":     "amazon.com",
    "arnazon":    "amazon.com",
    "g00gle":     "google.com",
    "gooogle":    "google.com",
    "app1e":      "apple.com",
    "netf1ix":    "netflix.com",
    "faceb00k":   "facebook.com",
    "1inkedin":   "linkedin.com",
    "linkedln":   "linkedin.com",
    "githud":     "github.com",
}

WEIGHTS = {
    "suspicious_or_unknown_sender":      20,
    "lookalike_domain":                  30,
    "urgent_language":                   20,
    "credential_request":                30,
    "payment_request":                   25,
    "suspicious_link":                   20,
    "non_https_link":                    20,
    "dangerous_attachment_type":         25,
    "authority_impersonation":           25,
    "external_link_inconsistent":        20,
    "display_text_destination_mismatch": 20,
    "suspicious_phone_pattern":          15,
    "suspicious_shortening_service":     15,
}

THRESHOLDS = {
    "legitimate": 20,  
    "suspicious":  50,  
}
