import re

# Each language has a list of regex patterns and a weight (score) for matching it.
# We also track the expected extension to easily map it back if needed.
LANGUAGE_HEURISTICS = [
    {
        "label": "Python Source Code",
        "extensions": ["py"],
        "patterns": [
            (r"^import\s+[a-zA-Z0-9_]+", 3),
            (r"^from\s+[a-zA-Z0-9_]+\s+import\s+", 3),
            (r"def\s+[a-zA-Z0-9_]+\s*\(", 2),
            (r"class\s+[a-zA-Z0-9_]+\s*:", 2),
            (r"if\s+__name__\s*==\s*['\"]__main__['\"]:", 5),
            (r"print\(", 1),
            (r"^\s*#\s+", 1), # Python comment
        ]
    },
    {
        "label": "C/C++ Source Code",
        "extensions": ["c", "cpp", "h"],
        "patterns": [
            (r"#include\s+<[a-zA-Z0-9_.]+>", 5),
            (r"#include\s+\"[a-zA-Z0-9_.]+\"", 4),
            (r"int\s+main\s*\(\s*(void|int\s+argc)?", 4),
            (r"printf\(", 2),
            (r"std::cout", 3),
            (r"^#define\s+", 2),
            (r"^\s*//\s+", 1), # C++ style comment
            (r"/\*.*?\*/", 1), # C style comment
        ]
    },
    {
        "label": "Java Source Code",
        "extensions": ["java"],
        "patterns": [
            (r"import\s+java\.[a-zA-Z0-9_.]+;", 4),
            (r"public\s+class\s+[a-zA-Z0-9_]+\s*{", 3),
            (r"public\s+static\s+void\s+main\s*\(\s*String\[\]\s+args\s*\)", 5),
            (r"System\.out\.println\(", 3),
            (r"@Override", 2),
            (r"package\s+[a-zA-Z0-9_.]+;", 3),
        ]
    },
    {
        "label": "JavaScript Source Code",
        "extensions": ["js"],
        "patterns": [
            (r"console\.log\(", 2),
            (r"function\s+[a-zA-Z0-9_]*\s*\(", 2),
            (r"const\s+[a-zA-Z0-9_]+\s*=", 2),
            (r"let\s+[a-zA-Z0-9_]+\s*=", 2),
            (r"document\.getElementById\(", 3),
            (r"window\.", 2),
            (r"export\s+default\s+", 3),
            (r"import\s+.*?\s+from\s+['\"][a-zA-Z0-9_./-]+['\"]", 3),
            (r"require\(['\"][a-zA-Z0-9_./-]+['\"]\)", 3),
        ]
    },
    {
        "label": "PHP Source Code",
        "extensions": ["php"],
        "patterns": [
            (r"<\?php", 5),
            (r"echo\s+", 2),
            (r"\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*", 1), # PHP variable
            (r"public\s+function\s+[a-zA-Z0-9_]+\s*\(", 2),
            (r"require_once\s*\(", 3),
            (r"include\s+", 2),
        ]
    },
    {
        "label": "HTML Document",
        "extensions": ["html", "htm"],
        "patterns": [
            (r"<!DOCTYPE\s+html>", 5),
            (r"<html.*?>", 4),
            (r"<head.*?>", 2),
            (r"<body.*?>", 2),
            (r"<div.*?>", 1),
            (r"<script.*?>", 2),
            (r"<style.*?>", 2),
        ]
    },
    {
        "label": "CSS Stylesheet",
        "extensions": ["css"],
        "patterns": [
            (r"body\s*{", 2),
            (r"\.[a-zA-Z0-9_-]+\s*{", 2),
            (r"#[a-zA-Z0-9_-]+\s*{", 2),
            (r"color:\s*#[0-9a-fA-F]{3,6};", 2),
            (r"margin:\s*[0-9]+px;", 2),
            (r"padding:\s*[0-9]+px;", 2),
            (r"@media\s*\(", 3),
        ]
    },
    {
         "label": "JSON Document",
         "extensions": ["json"],
         "patterns": [
             (r"^\s*\{\s*$", 2),
             (r"^\s*\[\s*$", 2),
             (r"\"[a-zA-Z0-9_]+\"\s*:\s*(true|false|null|[0-9]+|\".*?\")", 3)
         ]
    },
    {
        "label": "XML Document",
        "extensions": ["xml", "svg"],
        "patterns": [
            (r"<\?xml\s+version=[\"'][0-9.]+[\"']", 5),
            (r"<svg.*?>", 4),
            (r"</[a-zA-Z0-9_-]+>", 1)
        ]
    },
    {
        "label": "Markdown Document",
        "extensions": ["md"],
        "patterns": [
             (r"^#\s+[a-zA-Z0-9]", 3),
             (r"^##\s+[a-zA-Z0-9]", 3),
             (r"^\*\s+[a-zA-Z0-9]", 1),
             (r"^-\s+[a-zA-Z0-9]", 1),
             (r"```[a-zA-Z0-9]*", 3)
        ]
    },
    {
        "label": "INI/Config File",
        "extensions": ["ini", "cfg"],
        "patterns": [
            (r"^\[[a-zA-Z0-9_.-]+\]\s*$", 4),
            (r"^[a-zA-Z0-9_.-]+\s*=\s*.*$", 1)
        ]
    }
]

# The threshold score required to confidently identify a file type.
CONFIDENCE_THRESHOLD = 5

def identify_source_code(text_content: str) -> dict | None:
    """
    Analyzes a block of text (typically the first few KB of a file) to determine
    if it matches known source code or structured text formats, using keyword
    and regex heuristics.

    Returns the best matching language dictionary (similar to SIGNATURES structure)
    or None if no format reached the confidence threshold.
    """
    best_match = None
    highest_score = 0

    # Test each language's patterns against the text content
    for lang in LANGUAGE_HEURISTICS:
        score = 0
        for pattern, weight in lang["patterns"]:
            # Use re.IGNORECASE for HTML/CSS, but typically keep case for exact code matching
            flags = re.MULTILINE 
            if lang["extensions"][0] in ("html", "css", "xml", "json"):
                 flags |= re.IGNORECASE
                 
            # Find all occurrences of the pattern
            matches = re.findall(pattern, text_content, flags=flags)
            score += len(matches) * weight

        if score > highest_score:
            highest_score = score
            best_match = lang

    # Only return a match if we hit the threshold
    if highest_score >= CONFIDENCE_THRESHOLD and best_match:
        return {
            "label": best_match["label"],
            "extensions": best_match["extensions"],
            "offset": 0,
            "magic_hex": "N/A (Heuristic)",
            "note": f"Detected via semantic keyword analysis (Confidence Score: {highest_score})."
        }

    return None
