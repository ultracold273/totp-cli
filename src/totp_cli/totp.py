"""Validated TOTP enrollment data and platform-independent calculation."""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote, urlsplit

import pyotp

from totp_cli.errors import AppError

DIGESTS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}
PARAMETERS = {"secret", "issuer", "algorithm", "digits", "period"}
MAX_URI_LENGTH = 8192


def visible_text(value: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > 256 or not value.isprintable():
        if allow_empty and value == "":
            return value
        raise AppError("Account labels must be printable text of at most 256 characters.")
    value = value.strip()
    if not value and not allow_empty:
        raise AppError("The enrollment account label is empty.")
    return value


def normalize_secret(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z2-7]{2,512}={0,6}", value):
        raise AppError("The enrollment secret is not valid Base32.")
    raw = value.rstrip("=").upper()
    padded = raw + "=" * (-len(raw) % 8)
    if "=" in value and value.upper() != padded:
        raise AppError("The enrollment secret has invalid Base32 padding.")
    try:
        decoded = base64.b32decode(padded)
    except (ValueError, binascii.Error):
        raise AppError("The enrollment secret is not valid Base32.") from None
    # Reject noncanonical trailing bits; the same bytes have one stored representation.
    if not decoded or base64.b32encode(decoded).decode("ascii").rstrip("=") != raw:
        raise AppError("The enrollment secret is not valid Base32.")
    return raw


@dataclass(frozen=True)
class Enrollment:
    secret: str = field(repr=False)
    account: str
    issuer: str = ""
    algorithm: str = "SHA1"
    digits: int = 6
    period: int = 30

    def __post_init__(self) -> None:
        object.__setattr__(self, "secret", normalize_secret(self.secret))
        object.__setattr__(self, "account", visible_text(self.account))
        object.__setattr__(self, "issuer", visible_text(self.issuer, allow_empty=True))
        if self.algorithm not in DIGESTS:
            raise AppError("Supported TOTP algorithms are SHA1, SHA256 and SHA512.")
        if type(self.digits) is not int or self.digits not in (6, 8):
            raise AppError("Supported TOTP lengths are 6 and 8 digits.")
        if type(self.period) is not int or not 1 <= self.period <= 86400:
            raise AppError("The TOTP period must be an integer from 1 to 86400 seconds.")

    def code_at(self, timestamp: float) -> tuple[str, int]:
        if not math.isfinite(timestamp) or timestamp < 0:
            raise AppError("The system clock must be set to a valid time after the Unix epoch.")
        counter = math.floor(timestamp / self.period)
        if counter >= 2**64:
            raise AppError("The system clock is outside the supported range.")
        generator = pyotp.TOTP(
            self.secret, digits=self.digits, digest=DIGESTS[self.algorithm], interval=self.period
        )
        # Use the Unix time counter directly: no local-time or Windows mktime dependency.
        code = generator.generate_otp(counter)
        remaining = math.ceil(self.period - timestamp % self.period)
        return code, remaining


def parse_enrollment(uri: str) -> Enrollment:
    """Parse without including the URI or its secret in any error message."""
    if not isinstance(uri, str) or len(uri) > MAX_URI_LENGTH or not uri.isprintable():
        raise AppError("The QR payload is not a valid TOTP enrollment URI.")
    if re.search(r"%(?![0-9A-Fa-f]{2})", uri):
        raise AppError("The enrollment URI contains invalid percent encoding.")
    try:
        parts = urlsplit(uri)
        if parts.scheme != "otpauth" or parts.netloc != "totp":
            raise AppError(
                "Expected an otpauth://totp/ enrollment QR. "
                "Push, passkey, HOTP and migration QR codes are not supported."
            )
        if parts.fragment or not parts.path.startswith("/"):
            raise AppError("The enrollment URI has an unsupported structure.")
        label = visible_text(unquote(parts.path[1:], encoding="utf-8", errors="strict"))
        pairs = parse_qsl(
            parts.query,
            keep_blank_values=True,
            strict_parsing=True,
            encoding="utf-8",
            errors="strict",
            max_num_fields=16,
        )
    except (ValueError, UnicodeError):
        raise AppError("The QR payload is not a valid TOTP enrollment URI.") from None
    options: dict[str, str] = {}
    for key, value in pairs:
        if key not in PARAMETERS:
            raise AppError("The enrollment URI contains an unsupported parameter.")
        if key in options:
            raise AppError("The enrollment URI contains a repeated parameter.")
        options[key] = value
    if "secret" not in options:
        raise AppError("The enrollment QR does not contain a secret.")
    issuer = visible_text(options.get("issuer", ""), allow_empty=True)
    if ":" in label:
        prefix, label = label.split(":", 1)
        prefix = visible_text(prefix)
        if issuer and issuer != prefix:
            raise AppError("The enrollment issuer and account-label prefix do not match.")
        issuer = issuer or prefix
    algorithm = options.get("algorithm", "SHA1").upper()
    digits_text = options.get("digits", "6")
    period_text = options.get("period", "30")
    if not re.fullmatch(r"[0-9]{1,5}", period_text) or digits_text not in ("6", "8"):
        raise AppError("The enrollment has an invalid digit count or time period.")
    return Enrollment(
        secret=options["secret"],
        account=label,
        issuer=issuer,
        algorithm=algorithm,
        digits=int(digits_text),
        period=int(period_text),
    )
