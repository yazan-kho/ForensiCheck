"""
entropy.py — Shannon entropy analysis for file bytes.
"""

import math


def calculate_entropy(data: bytes) -> float:
    """
    Calculate the Shannon entropy of a byte sequence.
    Returns a value between 0.0 (completely uniform) and 8.0 (perfectly random).
    """
    if not data:
        return 0.0

    # Count occurrences of each byte value (0-255)
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1

    # Entropy = − ∑ p(xᵢ) ⋅ log₂(p(xᵢ))
    # p(xᵢ) is the probability of byte value i appearing in the file
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            probability = count / length
            entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def interpret_entropy(value: float) -> dict:
    """
    Interpret a Shannon entropy value and return a human-readable assessment.

    Returns a dict with:
      level   : str  — one of: Low, Moderate, High, Very High
      message : str  — plain-English explanation
      color   : str  — CSS color hint for the UI
    """
    if value < 3.0:
        return {
            "level": "Low",
            "value": value,
            "message": (
                "Low entropy — file likely contains plain text, "
                "repetitive data, or is largely empty."
            ),
            "color": "#4ade80",   # green
        }
    elif value < 5.5:
        return {
            "level": "Moderate",
            "value": value,
            "message": (
                "Moderate entropy — typical of uncompressed structured binary "
                "formats such as BMP images or simple executables."
            ),
            "color": "#60a5fa",   # blue
        }
    elif value < 7.5:
        return {
            "level": "High",
            "value": value,
            "message": (
                "High entropy — consistent with compressed or encoded content. "
                "Common in PDFs, DOCX files, ZIP archives, JPEG images, and "
                "video formats. Not inherently suspicious."
            ),
            "color": "#fbbf24",   # amber
        }
    else:
        return {
            "level": "Very High",
            "value": value,
            "message": (
                "Very high entropy (\u2265 7.5) — the data appears nearly random. "
                "This strongly suggests encryption, obfuscation, or "
                "custom packing beyond standard compression. "
                "Warrants further investigation."
            ),
            "color": "#f87171",   # red
        }


EXPECTED_ENTROPY_RANGES = {
    # ── Compressed / Encrypted / Dense Media (Expect High to Very High) ──
    "pdf document": (7.5, 8.0),
    "zip archive": (7.8, 8.0),
    "microsoft word document (docx)": (7.8, 8.0),
    "microsoft excel spreadsheet (xlsx)": (7.8, 8.0),
    "microsoft powerpoint presentation (pptx)": (7.8, 8.0),
    "java archive (jar)": (7.8, 8.0),
    "android package (apk)": (7.8, 8.0),
    "epub ebook": (7.8, 8.0),
    "opendocument text (odt)": (7.8, 8.0),
    "opendocument spreadsheet (ods)": (7.8, 8.0),
    "opendocument presentation (odp)": (7.8, 8.0),
    "zip / office open xml / jar": (7.8, 8.0),
    "rar archive (v4)": (7.8, 8.0),
    "rar archive (v5)": (7.8, 8.0),
    "7-zip archive": (7.8, 8.0),
    "gzip archive": (7.8, 8.0),
    "bzip2 archive": (7.8, 8.0),
    "xz archive": (7.8, 8.0),
    "tar archive": (2.0, 6.0),  # TAR itself isn't compressed

    # ── Images & Media ──
    "png image": (7.3, 8.0),
    "jpeg image": (7.6, 8.0),
    "gif image": (7.0, 8.0),
    "bmp image": (1.0, 5.0),    # Uncompressed raster
    "tiff image (little-endian)": (4.0, 8.0),
    "tiff image (big-endian)": (4.0, 8.0),
    "mp3 audio": (7.5, 8.0),
    "mp3 audio (id3 tag)": (7.5, 8.0),
    "mp4 / mov video": (7.6, 8.0),
    "mkv / webm video": (7.6, 8.0),
    "ogg audio/video": (7.6, 8.0),
    "flac audio": (7.0, 8.0),
    "flash video": (7.5, 8.0),

    # ── Executables (Packed vs Unpacked) ──
    "windows executable / dll": (4.5, 6.8),   # Can be higher if UPX/packed
    "elf executable (linux/unix)": (4.5, 6.8),
    "java class file / mach-o fat binary": (4.0, 6.5),
    "mach-o executable (32-bit)": (4.5, 6.8),
    "mach-o executable (64-bit)": (4.5, 6.8),

    # ── Documents & Databases ──
    "sqlite database": (3.0, 6.0),
    "rtf document": (3.0, 5.5),
    "xml document": (2.0, 5.0),
    "html document": (2.0, 5.0),
    "utf-8 bom text": (2.0, 5.0),
    "pem certificate / key": (4.0, 6.0),
}


def get_expected_entropy(label: str) -> tuple[float, float] | None:
    """
    Return a tuple of (min_expected, max_expected) entropy for a given format
    label, or None if unknown.
    """
    if not label:
        return None
    return EXPECTED_ENTROPY_RANGES.get(label.lower())

