"""
analyzer.py — Core file signature analysis engine.
"""

from __future__ import annotations

import io
import os
import struct
import zipfile

from .signatures import SIGNATURES, ZIP_SUBTYPE_RULES, EXTENSION_LABELS
from .entropy import calculate_entropy, interpret_entropy, get_expected_entropy

# How many bytes to read from the start of the file for signature scanning.
# ISO needs 32769 + 5 = 32774 bytes minimum.
READ_SIZE = 64 * 1024  # 64 KB


# ---------------------------------------------------------------------------
# ZIP internal-path disambiguator
# ---------------------------------------------------------------------------

def _get_zip_entries(data: bytes) -> list[str]:
    """
    Return a list of internal file/directory names inside a ZIP archive,
    reading from an in-memory bytes object.
    Returns an empty list if the data is not a valid ZIP.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return zf.namelist()
    except Exception:
        return []


def _read_zip_mimetype(data: bytes) -> str:
    """
    Some ZIP containers (ODF) store a plain-text 'mimetype' entry as the first
    file. Attempt to read it and return its content.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            if "mimetype" in zf.namelist():
                return zf.read("mimetype").decode("utf-8", errors="ignore").strip()
    except Exception:
        pass
    return ""


def _disambiguate_zip(data: bytes) -> dict:
    """
    Given bytes that start with PK\x03\x04, try to determine the actual
    sub-format by inspecting the ZIP central directory.
    Returns the best-matching rule dict from ZIP_SUBTYPE_RULES.
    """
    entries = _get_zip_entries(data)
    entry_set = {e.lower() for e in entries}
    mimetype = _read_zip_mimetype(data).lower()

    for rule in ZIP_SUBTYPE_RULES:
        # Check mimetype first (ODF disambiguation)
        if rule.get("mimetype_contains") and rule["mimetype_contains"] not in mimetype:
            # Only skip if there IS a mimetype entry and it doesn't match
            if mimetype:
                continue

        # Check required internal paths
        required = [r.lower() for r in rule.get("requires_any", [])]
        if not required:
            # Fallback rule (plain ZIP)
            return rule
        if any(req in entry_set or any(e.startswith(req) for e in entry_set) for req in required):
            return rule

    # Should never reach here given the fallback rule, but just in case:
    return ZIP_SUBTYPE_RULES[-1]


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

def analyze_file(file_path: str, original_filename: str) -> dict:
    """
    Analyze a file and return a structured result dict.

    Parameters
    ----------
    file_path        : Absolute path to the uploaded temp file on disk.
    original_filename: The original filename as submitted by the user (used to
                       extract the declared extension).

    Returns
    -------
    dict with keys:
      filename         : str
      file_size        : int  (bytes)
      declared_ext     : str
      detected_types   : list[dict]  — all matching signatures
      primary_type     : dict | None — best/most specific match
      verdict          : str  — "MATCH", "MISMATCH", "SUSPICIOUS", "UNKNOWN"
      verdict_detail   : str  — plain-English explanation
      entropy          : dict — Shannon entropy result from entropy.py
      zip_detail       : dict | None — ZIP sub-type info if applicable
    """
    # ── 1. Basic file info ──────────────────────────────────────────────────
    file_size = os.path.getsize(file_path)
    declared_ext = os.path.splitext(original_filename)[1].lstrip(".").lower()

    # ── 2. Read file bytes ──────────────────────────────────────────────────
    with open(file_path, "rb") as fh:
        data = fh.read()  # read entire file for entropy; may be large

    header = data[:READ_SIZE] if len(data) > READ_SIZE else data

    # ── 3. Match signatures ─────────────────────────────────────────────────
    detected_types: list[dict] = []
    zip_detail = None

    for sig in SIGNATURES:
        offset = sig["offset"]
        magic = sig["magic"]
        # Ensure we have enough bytes at the given offset
        if offset + len(magic) > len(header):
            continue
        if header[offset: offset + len(magic)] == magic:
            entry = {
                "label": sig["label"],
                "extensions": sig["extensions"],
                "offset": offset,
                "magic_hex": magic.hex(" "),
            }
            detected_types.append(entry)

            # Special handling: ZIP family needs disambiguation
            if magic == b"PK\x03\x04":
                rule = _disambiguate_zip(data)
                zip_detail = {
                    "label": rule["label"],
                    "extensions": rule["extensions"],
                }
                # Replace the generic ZIP entry with the specific sub-type
                detected_types[-1] = {
                    "label": rule["label"],
                    "extensions": rule["extensions"],
                    "offset": offset,
                    "magic_hex": magic.hex(" "),
                    "note": "ZIP container disambiguated via internal directory inspection",
                }

    # ── 4. Pick primary (most specific) type ───────────────────────────────
    primary_type = detected_types[0] if detected_types else None

    # Fallback heuristics for files without magic bytes (e.g., plain text, empty)
    if primary_type is None:
        if file_size == 0:
            primary_type = {
                "label": "Empty File",
                "extensions": ["txt", "log", ""], # Empty files could be anything, often txt
                "offset": 0,
                "magic_hex": "N/A",
                "note": "File contains exactly 0 bytes."
            }
            detected_types.append(primary_type)
        else:
            # Try to decode the beginning as UTF-8 (which includes ASCII)
            sample = data[:8192]
            try:
                sample.decode("utf-8")
                # True plain text shouldn't have null bytes
                if b"\x00" not in sample:
                    # Try semantic keyword analysis
                    decoded_text = sample.decode("utf-8")
                    from .heuristics import identify_source_code
                    semantic_match = identify_source_code(decoded_text)
                    
                    if semantic_match:
                         primary_type = semantic_match
                    else:
                        primary_type = {
                            "label": "Plain Text Document",
                            "extensions": ["txt", "csv", "md", "json", "log", "ini", "cfg", "xml", "html", "py", "js", "css", "java", "c", "php", "cpp"],
                            "offset": 0,
                            "magic_hex": "N/A",
                            "note": "Detected via UTF-8/ASCII heuristic (no binary magic bytes found)."
                        }
                    detected_types.append(primary_type)
            except UnicodeDecodeError:
                pass

    # ── 5. Determine verdict ────────────────────────────────────────────────
    if primary_type is None:
        verdict = "UNKNOWN"
        verdict_detail = (
            "No known signature matched the beginning of this file. "
            "It may be a plain text file with unconventional encoding, an unknown binary format, "
            "or the file might be corrupted."
        )
    else:
        expected_labels = EXTENSION_LABELS.get(declared_ext, [])
        detected_label = primary_type["label"]
        detected_exts = primary_type["extensions"]

        # Check: does the detected type match the declared extension?
        ext_in_detected = declared_ext in detected_exts
        label_in_expected = any(
            detected_label.lower() in el.lower() or el.lower() in detected_label.lower()
            for el in expected_labels
        ) if expected_labels else False

        if not declared_ext:
            verdict = "SUSPICIOUS"
            verdict_detail = (
                f"No file extension declared. Detected signature: "
                f"<strong>{detected_label}</strong>. "
                "Files without extensions can be an attempt to obscure their true type."
            )
        elif ext_in_detected or label_in_expected:
            verdict = "MATCH"
            verdict_detail = (
                f"The file extension <strong>.{declared_ext}</strong> matches "
                f"the detected binary signature: <strong>{detected_label}</strong>."
            )
        else:
            verdict = "MISMATCH"
            verdict_detail = (
                f"The declared extension <strong>.{declared_ext}</strong> does NOT match "
                f"the detected signature. "
                f"The file's binary signature identifies it as: "
                f"<strong>{detected_label}</strong>. "
                f"This may indicate the file extension has been intentionally altered."
            )

    # ── 6. Entropy ──────────────────────────────────────────────────────────
    entropy_value = calculate_entropy(data)
    entropy_result = interpret_entropy(entropy_value)

    if primary_type:
        entropy_result["expected_range"] = get_expected_entropy(primary_type["label"])
    else:
        entropy_result["expected_range"] = None

    # Formats that are compressed by design — high entropy is expected and normal.
    # Do NOT escalate these to SUSPICIOUS based on entropy alone.
    _INHERENTLY_COMPRESSED_LABELS = {
        "pdf document",
        "jpeg image",
        "mp3 audio",
        "mp3 audio (id3 tag)",
        "mp4 / mov video",
        "mkv / webm video",
        "flash video",
        "flac audio",
        "ogg audio/video",
        "gzip archive",
        "bzip2 archive",
        "xz archive",
        "rar archive (v4)",
        "rar archive (v5)",
        "7-zip archive",
        # ZIP family - already compressed internally
        "zip archive",
        "microsoft word document (docx)",
        "microsoft excel spreadsheet (xlsx)",
        "microsoft powerpoint presentation (pptx)",
        "java archive (jar)",
        "android package (apk)",
        "epub ebook",
        "opendocument text (odt)",
        "opendocument spreadsheet (ods)",
        "opendocument presentation (odp)",
        "zip / office open xml / jar",
        # Images with built-in compression
        "png image",
        "adobe photoshop image",
        "tiff image (little-endian)",
        "tiff image (big-endian)",
    }

    detected_label_lower = (primary_type["label"].lower() if primary_type else "")
    is_inherently_compressed = detected_label_lower in _INHERENTLY_COMPRESSED_LABELS

    # Only escalate MATCH → SUSPICIOUS for truly non-compressed formats
    # showing very high (near-random) entropy.
    if verdict == "MATCH" and entropy_result["level"] == "Very High" and not is_inherently_compressed:
        verdict = "SUSPICIOUS"
        verdict_detail += (
            " However, the file has <strong>very high entropy</strong> "
            "(≥ 7.5 bits/byte), which is unusual for this format and may indicate "
            "the payload is encrypted or packed."
        )

    # ── 7. Build and return result ──────────────────────────────────────────
    return {
        "filename": original_filename,
        "file_size": file_size,
        "declared_ext": declared_ext or "(none)",
        "detected_types": detected_types,
        "primary_type": primary_type,
        "verdict": verdict,
        "verdict_detail": verdict_detail,
        "entropy": entropy_result,
        "zip_detail": zip_detail,
    }
