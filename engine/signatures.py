"""
signatures.py — Magic byte signature database.

Each entry is a dict with:
  offset : int    — byte offset where the magic bytes start
  magic  : bytes  — the magic byte sequence to match
  label  : str    — human-readable format name
  extensions : list[str] — common file extensions for this format
"""

# ---------------------------------------------------------------------------
# Main signature list
# ---------------------------------------------------------------------------
SIGNATURES = [
    # ── Images ───────────────────────────────────────────────────────────────
    {"offset": 0, "magic": b"\x89PNG\r\n\x1a\n",  "label": "PNG Image",             "extensions": ["png"]},
    {"offset": 0, "magic": b"\xff\xd8\xff",         "label": "JPEG Image",            "extensions": ["jpg", "jpeg"]},
    {"offset": 0, "magic": b"GIF87a",               "label": "GIF Image",             "extensions": ["gif"]},
    {"offset": 0, "magic": b"GIF89a",               "label": "GIF Image",             "extensions": ["gif"]},
    {"offset": 0, "magic": b"BM",                   "label": "BMP Image",             "extensions": ["bmp"]},
    {"offset": 0, "magic": b"RIFF",                 "label": "RIFF Container (WebP/WAV/AVI)", "extensions": ["webp", "wav", "avi"]},
    {"offset": 0, "magic": b"\x00\x00\x01\x00",     "label": "ICO Image",             "extensions": ["ico"]},
    {"offset": 0, "magic": b"8BPS",                 "label": "Adobe Photoshop Image", "extensions": ["psd"]},
    {"offset": 0, "magic": b"II*\x00",              "label": "TIFF Image (little-endian)", "extensions": ["tif", "tiff"]},
    {"offset": 0, "magic": b"MM\x00*",              "label": "TIFF Image (big-endian)",    "extensions": ["tif", "tiff"]},

    # ── Documents ────────────────────────────────────────────────────────────
    {"offset": 0, "magic": b"%PDF-",                "label": "PDF Document",          "extensions": ["pdf"]},
    {"offset": 0, "magic": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "label": "Microsoft Office 97-2003 (OLE)", "extensions": ["doc", "xls", "ppt", "msg"]},
    {"offset": 0, "magic": b"{\rtf1",               "label": "RTF Document",          "extensions": ["rtf"]},

    # ── ZIP family (disambiguated separately) ────────────────────────────────
    {"offset": 0, "magic": b"PK\x03\x04",           "label": "ZIP / Office Open XML / JAR", "extensions": ["zip", "docx", "xlsx", "pptx", "jar", "apk", "odt", "ods", "odp"]},

    # ── Archives / Compression ───────────────────────────────────────────────
    {"offset": 0, "magic": b"Rar!\x1a\x07\x00",     "label": "RAR Archive (v4)",      "extensions": ["rar"]},
    {"offset": 0, "magic": b"Rar!\x1a\x07\x01\x00", "label": "RAR Archive (v5)",      "extensions": ["rar"]},
    {"offset": 0, "magic": b"7z\xbc\xaf'\x1c",      "label": "7-Zip Archive",         "extensions": ["7z"]},
    {"offset": 0, "magic": b"\x1f\x8b",             "label": "GZIP Archive",          "extensions": ["gz", "tgz"]},
    {"offset": 0, "magic": b"BZh",                  "label": "BZIP2 Archive",         "extensions": ["bz2"]},
    {"offset": 0, "magic": b"\xfd7zXZ\x00",         "label": "XZ Archive",            "extensions": ["xz"]},
    {"offset": 0, "magic": b"ustar",                "label": "TAR Archive",           "extensions": ["tar"]},

    # ── Executables / Binaries ───────────────────────────────────────────────
    {"offset": 0, "magic": b"MZ",                   "label": "Windows Executable / DLL", "extensions": ["exe", "dll", "sys", "scr", "com"]},
    {"offset": 0, "magic": b"\x7fELF",              "label": "ELF Executable (Linux/Unix)", "extensions": ["elf", "so", "out"]},
    {"offset": 0, "magic": b"\xca\xfe\xba\xbe",     "label": "Java Class File / Mach-O Fat Binary", "extensions": ["class"]},
    {"offset": 0, "magic": b"\xfe\xed\xfa\xce",     "label": "Mach-O Executable (32-bit)", "extensions": ["macho", "dylib"]},
    {"offset": 0, "magic": b"\xfe\xed\xfa\xcf",     "label": "Mach-O Executable (64-bit)", "extensions": ["macho", "dylib"]},

    # ── Audio / Video ────────────────────────────────────────────────────────
    {"offset": 0, "magic": b"\xff\xfb",             "label": "MP3 Audio",             "extensions": ["mp3"]},
    {"offset": 0, "magic": b"\xff\xf3",             "label": "MP3 Audio",             "extensions": ["mp3"]},
    {"offset": 0, "magic": b"\xff\xf2",             "label": "MP3 Audio",             "extensions": ["mp3"]},
    {"offset": 0, "magic": b"ID3",                  "label": "MP3 Audio (ID3 tag)",   "extensions": ["mp3"]},
    {"offset": 0, "magic": b"OggS",                 "label": "OGG Audio/Video",       "extensions": ["ogg", "oga", "ogv"]},
    {"offset": 4,  "magic": b"ftyp",                "label": "MP4 / MOV Video",       "extensions": ["mp4", "mov", "m4v", "m4a"]},
    {"offset": 0, "magic": b"\x1aE\xdf\xa3",        "label": "MKV / WebM Video",      "extensions": ["mkv", "webm"]},
    {"offset": 0, "magic": b"FLV\x01",              "label": "Flash Video",           "extensions": ["flv"]},
    {"offset": 0, "magic": b"fLaC",                 "label": "FLAC Audio",            "extensions": ["flac"]},

    # ── Disk / Firmware images ────────────────────────────────────────────────
    # ISO 9660 — signature at byte 32769 (0x8001)
    {"offset": 32769, "magic": b"CD001",            "label": "ISO Disc Image",        "extensions": ["iso"]},

    # ── Databases ────────────────────────────────────────────────────────────
    {"offset": 0, "magic": b"SQLite format 3\x00",  "label": "SQLite Database",       "extensions": ["db", "sqlite", "sqlite3"]},

    # ── Scripts / Text (heuristic) ───────────────────────────────────────────
    {"offset": 0, "magic": b"\xef\xbb\xbf",         "label": "UTF-8 BOM Text",        "extensions": ["txt", "html", "xml", "csv"]},
    # {"offset": 0, "magic": b"\xff\xfe",             "label": "UTF-16 Little Endian Text",       "extensions": ["txt", "html", "xml", "csv"]},
    # {"offset": 0, "magic": b"\xfe\xff",             "label": "UTF-16 Big Endian Text",       "extensions": ["txt", "html", "xml", "csv"]},
    {"offset": 0, "magic": b"<?xml",                "label": "XML Document",          "extensions": ["xml", "svg", "xhtml"]},
    {"offset": 0, "magic": b"<!DOCTYPE",            "label": "HTML Document",         "extensions": ["html", "htm"]},
    {"offset": 0, "magic": b"<html",                "label": "HTML Document",         "extensions": ["html", "htm"]},

    # ── Crypto / Certs ───────────────────────────────────────────────────────
    {"offset": 0, "magic": b"-----BEGIN",           "label": "PEM Certificate / Key", "extensions": ["pem", "crt", "key", "csr"]},

    # ── Font ─────────────────────────────────────────────────────────────────
    {"offset": 0, "magic": b"\x00\x01\x00\x00\x00", "label": "TrueType Font",         "extensions": ["ttf"]},
    {"offset": 0, "magic": b"OTTO",                 "label": "OpenType Font",         "extensions": ["otf"]},
    {"offset": 0, "magic": b"wOFF",                 "label": "WOFF Font",             "extensions": ["woff"]},
    {"offset": 0, "magic": b"wOF2",                 "label": "WOFF2 Font",            "extensions": ["woff2"]},

    # ── Misc ─────────────────────────────────────────────────────────────────
    {"offset": 0, "magic": b"CWS",                  "label": "SWF Flash (compressed)", "extensions": ["swf"]},
    {"offset": 0, "magic": b"FWS",                  "label": "SWF Flash",             "extensions": ["swf"]},
    {"offset": 0, "magic": b"\x25\x21PS",           "label": "PostScript Document",   "extensions": ["ps", "eps"]},
    {"offset": 0, "magic": b"MSCF",                 "label": "Microsoft Cabinet File", "extensions": ["cab"]},
    {"offset": 0, "magic": b"ITSF",                 "label": "Microsoft HTML Help",   "extensions": ["chm"]},
    {"offset": 0, "magic": b"LZIP",                 "label": "LZIP Archive",          "extensions": ["lz"]},
    {"offset": 0, "magic": b"SZDD",                 "label": "MS-DOS Compressed",     "extensions": [""]},
]

# ---------------------------------------------------------------------------
# ZIP sub-type disambiguation
# Internal paths that distinguish specific ZIP-based containers.
# Order matters: more specific checks first.
# ---------------------------------------------------------------------------
ZIP_SUBTYPE_RULES = [
    # Office Open XML
    {
        "label": "Microsoft Word Document (DOCX)",
        "extensions": ["docx"],
        "requires_any": ["word/document.xml", "word/"],
    },
    {
        "label": "Microsoft Excel Spreadsheet (XLSX)",
        "extensions": ["xlsx"],
        "requires_any": ["xl/workbook.xml", "xl/"],
    },
    {
        "label": "Microsoft PowerPoint Presentation (PPTX)",
        "extensions": ["pptx"],
        "requires_any": ["ppt/presentation.xml", "ppt/"],
    },
    # OpenDocument
    {
        "label": "OpenDocument Text (ODT)",
        "extensions": ["odt"],
        "requires_any": ["content.xml", "META-INF/"],
        "mimetype_contains": "opendocument.text",
    },
    {
        "label": "OpenDocument Spreadsheet (ODS)",
        "extensions": ["ods"],
        "requires_any": ["content.xml"],
        "mimetype_contains": "opendocument.spreadsheet",
    },
    {
        "label": "OpenDocument Presentation (ODP)",
        "extensions": ["odp"],
        "requires_any": ["content.xml"],
        "mimetype_contains": "opendocument.presentation",
    },
    # Java / Android
    {
        "label": "Java Archive (JAR)",
        "extensions": ["jar"],
        "requires_any": ["META-INF/MANIFEST.MF"],
    },
    {
        "label": "Android Package (APK)",
        "extensions": ["apk"],
        "requires_any": ["AndroidManifest.xml", "classes.dex"],
    },
    # EPUB
    {
        "label": "EPUB eBook",
        "extensions": ["epub"],
        "requires_any": ["META-INF/container.xml", "OEBPS/"],
    },
    # Fallback
    {
        "label": "ZIP Archive",
        "extensions": ["zip"],
        "requires_any": [],
    },
]

# ---------------------------------------------------------------------------
# Extension → expected labels mapping  (lower-case extension → set of labels)
# ---------------------------------------------------------------------------
EXTENSION_LABELS: dict[str, list[str]] = {}

for _sig in SIGNATURES:
    for _ext in _sig["extensions"]:
        if _ext:
            EXTENSION_LABELS.setdefault(_ext, [])
            if _sig["label"] not in EXTENSION_LABELS[_ext]:
                EXTENSION_LABELS[_ext].append(_sig["label"])

# Add ZIP sub-type labels
for _rule in ZIP_SUBTYPE_RULES:
    for _ext in _rule["extensions"]:
        EXTENSION_LABELS.setdefault(_ext, [])
        if _rule["label"] not in EXTENSION_LABELS[_ext]:
            EXTENSION_LABELS[_ext].append(_rule["label"])
