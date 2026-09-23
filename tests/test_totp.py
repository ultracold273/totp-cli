import base64

import pytest
from conftest import SECRET, URI

from totp_cli.errors import AppError
from totp_cli.totp import Enrollment, normalize_secret, parse_enrollment

# RFC 6238 Appendix B, with the per-algorithm key lengths from its reference code.
VECTORS = [
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]


@pytest.mark.parametrize("timestamp,sha1,sha256,sha512", VECTORS)
@pytest.mark.parametrize("algorithm,size", [("SHA1", 20), ("SHA256", 32), ("SHA512", 64)])
def test_rfc_6238_vectors(timestamp, sha1, sha256, sha512, algorithm, size):
    secret = base64.b32encode((b"1234567890" * 7)[:size]).decode().rstrip("=")
    enrollment = Enrollment(secret, "rfc-test", algorithm=algorithm, digits=8)
    expected = {"SHA1": sha1, "SHA256": sha256, "SHA512": sha512}[algorithm]
    assert enrollment.code_at(timestamp)[0] == expected


def test_time_boundary_and_custom_period():
    standard = parse_enrollment(URI)
    assert standard.code_at(59.999) == ("287082", 1)
    assert standard.code_at(60) == ("359152", 30)
    custom = parse_enrollment(URI + "&period=60")
    assert custom.code_at(59) == ("755224", 1)
    assert custom.code_at(60) == ("287082", 60)


@pytest.mark.parametrize("timestamp", [-1, float("nan"), float("inf"), 30 * 2**64])
def test_invalid_system_clock(timestamp):
    with pytest.raises(AppError, match="clock"):
        parse_enrollment(URI).code_at(timestamp)


def test_defaults_unicode_label_and_hidden_repr():
    value = parse_enrollment(
        f"otpauth://totp/%E5%B7%A5%E4%BD%9C%3Aalice%2Btag%40example.com?secret={SECRET}"
    )
    assert value.issuer == "工作"
    assert value.account == "alice+tag@example.com"
    assert (value.algorithm, value.digits, value.period) == ("SHA1", 6, 30)
    assert SECRET not in repr(value)


def test_base32_case_and_padding():
    assert normalize_secret(SECRET.lower()) == SECRET
    assert normalize_secret("my======") == "MY"


@pytest.mark.parametrize("secret", ["", "M", "MZ", "MY=", "ABC01", "MY ABC", "MY\n"])
def test_invalid_base32(secret):
    with pytest.raises(AppError):
        normalize_secret(secret)


@pytest.mark.parametrize(
    "uri",
    [
        URI + "&digits=7",
        URI + "&period=0",
        URI + "&period=-1",
        URI + "&period=1.5",
        URI + "&period=86401",
        URI + "&algorithm=MD5",
        URI + "&counter=0",
        URI + "&unknown=1",
        URI + "&issuer=Example",
        URI + "&secret=MY",
        URI + "#fragment",
        URI + "&bad",
        URI.replace("Example:alice", "Other:alice"),
        URI.replace("alice", "%1Balice"),
        URI.replace("alice", "%FFalice"),
        URI.replace("alice", "%Z0alice"),
        URI.replace("totp/", "hotp/"),
        URI.replace("totp/", "user@totp/"),
        "https://example.com/push?secret=" + SECRET,
        "otpauth://totp/account",
        "otpauth://totp/?secret=" + SECRET,
    ],
)
def test_invalid_enrollment_errors_do_not_echo_payload(uri):
    with pytest.raises(AppError) as result:
        parse_enrollment(uri)
    assert SECRET not in str(result.value)
    assert uri not in str(result.value)
