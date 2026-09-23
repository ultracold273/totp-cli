import pytest
import qrcode
from conftest import SECRET, URI
from PIL import Image, ImageOps

from totp_cli.errors import AppError
from totp_cli.qr import read_enrollment


def test_reads_real_screenshot_with_unicode_path(qr_path):
    enrollment = read_enrollment(qr_path)
    assert enrollment.secret == SECRET
    assert enrollment.account == "alice@example.com"


@pytest.mark.parametrize(
    "rotation,inverted,extension",
    [
        (90, False, "png"),
        (180, True, "png"),
        (0, False, "jpg"),
    ],
)
def test_rotated_inverted_and_jpeg(tmp_path, rotation, inverted, extension):
    image = qrcode.make(URI).convert("RGB").rotate(rotation, expand=True)
    if inverted:
        image = ImageOps.invert(image)
    path = tmp_path / f"scan.{extension}"
    image.save(path)
    assert read_enrollment(path).secret == SECRET


def combined_qr(tmp_path, payloads):
    images = [qrcode.make(payload).convert("RGB") for payload in payloads]
    canvas = Image.new(
        "RGB", (sum(i.width + 80 for i in images), max(i.height for i in images)), "white"
    )
    offset = 0
    for image in images:
        canvas.paste(image, (offset, 0))
        offset += image.width + 80
    path = tmp_path / "combined.png"
    canvas.save(path)
    return path


def test_multiple_totp_codes_require_cropping(tmp_path):
    path = combined_qr(tmp_path, [URI, URI.replace("alice", "bob")])
    with pytest.raises(AppError, match="More than one"):
        read_enrollment(path)


def test_unrelated_qr_does_not_hide_a_totp_code(tmp_path):
    path = combined_qr(tmp_path, [URI, "https://example.com"])
    assert read_enrollment(path).secret == SECRET


@pytest.mark.parametrize(
    "payload", ["https://example.com/push", "otpauth-migration://offline?data=test"]
)
def test_unsupported_payload_is_not_echoed(tmp_path, payload):
    path = tmp_path / "unsupported.png"
    qrcode.make(payload).save(path)
    with pytest.raises(AppError, match="No TOTP enrollment") as result:
        read_enrollment(path)
    assert payload not in str(result.value)


def test_no_qr_and_invalid_image(tmp_path):
    path = tmp_path / "blank.png"
    Image.new("RGB", (150, 150), "white").save(path)
    with pytest.raises(AppError, match="No readable QR"):
        read_enrollment(path)
    path.write_bytes(b"not an image")
    with pytest.raises(AppError, match="Could not read"):
        read_enrollment(path)


def test_missing_image(tmp_path):
    with pytest.raises(AppError, match="existing local file"):
        read_enrollment(tmp_path / "missing.png")


def test_image_limits(qr_path, monkeypatch):
    monkeypatch.setattr("totp_cli.qr.MAX_IMAGE_BYTES", 10)
    with pytest.raises(AppError, match="size limit"):
        read_enrollment(qr_path)
    monkeypatch.setattr("totp_cli.qr.MAX_IMAGE_BYTES", 20 * 1024 * 1024)
    monkeypatch.setattr("totp_cli.qr.MAX_IMAGE_PIXELS", 100)
    with pytest.raises(AppError, match="megapixel"):
        read_enrollment(qr_path)
