"""Decode local screenshots only; no image or payload is transmitted."""

from __future__ import annotations

import io
import warnings
from pathlib import Path

from totp_cli.errors import AppError
from totp_cli.totp import Enrollment, parse_enrollment

MAX_IMAGE_BYTES = 20 * 1024 * 1024
MAX_IMAGE_PIXELS = 40_000_000


def read_enrollment(path: Path) -> Enrollment:
    # Lazy native imports keep --help, list and code independent of the image decoder.
    import zxingcpp
    from PIL import Image, ImageOps

    try:
        if not path.is_file():
            raise AppError("The QR image must be an existing local file.")
        with path.open("rb") as stream:
            data = stream.read(MAX_IMAGE_BYTES + 1)
        if len(data) > MAX_IMAGE_BYTES:
            raise AppError("The QR image exceeds the 20 MiB size limit.")
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as source:
                if source.format not in ("PNG", "JPEG"):
                    raise AppError("Use a PNG or JPEG screenshot.")
                if source.width * source.height > MAX_IMAGE_PIXELS:
                    raise AppError("The QR image exceeds the 40 megapixel limit. Crop it first.")
                oriented = ImageOps.exif_transpose(source)
                rgba = oriented.convert("RGBA")
                background = Image.new("RGBA", rgba.size, "white")
                gray = Image.alpha_composite(background, rgba).convert("L")
                results = zxingcpp.read_barcodes(
                    gray,
                    formats=zxingcpp.BarcodeFormat.QRCode,
                    text_mode=zxingcpp.TextMode.Plain,
                )
    except AppError:
        raise
    except (
        OSError,
        ValueError,
        RuntimeError,
        Image.DecompressionBombWarning,
        Image.DecompressionBombError,
    ):
        raise AppError("Could not read the QR image. Use a clear, readable PNG or JPEG.") from None
    payloads = {result.text for result in results if result.valid}
    if not payloads:
        raise AppError("No readable QR code found. Keep the full QR and its border in the image.")
    candidates = {text for text in payloads if text.startswith("otpauth://totp/")}
    if len(candidates) > 1:
        raise AppError("More than one TOTP QR found. Crop the image to one enrollment code.")
    if not candidates:
        raise AppError(
            "No TOTP enrollment QR found. Use an otpauth://totp/ code; "
            "push, passkey, HOTP and migration codes are not supported."
        )
    return parse_enrollment(candidates.pop())
