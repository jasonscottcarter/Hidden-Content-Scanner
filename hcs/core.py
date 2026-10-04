"""Shared data model, text analysis (prompt injection / Unicode smuggling) and color helpers."""
from __future__ import annotations

import base64
import contextvars
import re
import unicodedata
from dataclasses import dataclass, field, asdict

HIGH, MEDIUM, LOW, INFO = "HIGH", "MEDIUM", "LOW", "INFO"
SEV_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3}

MAX_SNIPPET = 600


@dataclass
class Finding:
    severity: str
    category: str
    location: str
    detail: str
    snippet: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class Report:
    path: str
    file_type: str = "unknown"
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    children: list = field(default_factory=list)  # reports for attachments / embedded files
    _seen: set = field(default_factory=set, repr=False)

    def add(self, severity, category, location, detail, snippet=""):
        snippet = clip(snippet)
        key = (severity, category, location, detail, snippet)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(Finding(severity, category, location, detail, snippet))

    def error(self, msg):
        self.errors.append(msg)

    def counts(self, recursive=True):
        c = {HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0}
        for f in self.findings:
            c[f.severity] += 1
        if recursive:
            for ch in self.children:
                for k, v in ch.counts().items():
                    c[k] += v
        return c

    def sorted_findings(self):
        return sorted(self.findings, key=lambda f: SEV_ORDER[f.severity])

    def to_dict(self):
        return {
            "path": self.path,
            "file_type": self.file_type,
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "errors": self.errors,
            "children": [c.to_dict() for c in self.children],
        }


def clip(s, n=MAX_SNIPPET):
    if s is None:
        return ""
    s = str(s)
    return s if len(s) <= n else s[:n] + f" … [+{len(s) - n} chars]"


# --------------------------------------------------------------------------------------
# Invisible / deceptive Unicode
# --------------------------------------------------------------------------------------

ZERO_WIDTH = {
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x2060: "WORD JOINER",
    0x2061: "FUNCTION APPLICATION",
    0x2062: "INVISIBLE TIMES",
    0x2063: "INVISIBLE SEPARATOR",
    0x2064: "INVISIBLE PLUS",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE / BOM",
    0x180E: "MONGOLIAN VOWEL SEPARATOR",
    0x115F: "HANGUL CHOSEONG FILLER",
    0x1160: "HANGUL JUNGSEONG FILLER",
    0x3164: "HANGUL FILLER",
    0xFFA0: "HALFWIDTH HANGUL FILLER",
    0x034F: "COMBINING GRAPHEME JOINER",
    0x00AD: "SOFT HYPHEN",
    0x180B: "MONGOLIAN FREE VARIATION SELECTOR ONE",
    0x180C: "MONGOLIAN FREE VARIATION SELECTOR TWO",
    0x180D: "MONGOLIAN FREE VARIATION SELECTOR THREE",
    0xFFF9: "INTERLINEAR ANNOTATION ANCHOR",
    0xFFFA: "INTERLINEAR ANNOTATION SEPARATOR",
    0xFFFB: "INTERLINEAR ANNOTATION TERMINATOR",
}
ZERO_WIDTH.update({cp: "INVISIBLE MUSICAL FORMATTING CHARACTER" for cp in range(0x1D173, 0x1D17B)})
BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F, 0x061C}

INJECTION_PATTERNS = [
    (r"\b(ignore|disregard|forget|override|bypass)\b.{0,40}\b(previous|prior|above|earlier|preceding|all|any|your|system)\b.{0,30}\b(instructions?|prompts?|directions?|rules|guidelines|context|messages?)",
     "Instruction-override phrase"),
    (r"\b(you are|you're|act as|pretend (to be|you are)|roleplay as|from now on,? you)\b.{0,30}\b(an? )?(ai|assistant|chat ?bot|language model|llm|gpt|chatgpt|claude|gemini|copilot|bard|grok)\b",
     "Role reassignment addressed to an AI"),
    (r"\b(system|developer|hidden|secret)\s+(prompt|message|instructions?)\b", "References system/hidden prompt"),
    (r"\b(new|updated|additional|important|special)\s+instructions?\s*(:|for|to)", "Injected 'new instructions'"),
    (r"\b(note|message|instructions?)\s+(to|for)\s+(the\s+)?(ai|assistant|model|llm|chat ?bot|agent|reviewer bot|language model)\b",
     "Text addressed to an AI system"),
    (r"\b(if you are|as) an? (ai|large language model|llm|language model|assistant)\b", "Text addressed to an AI system"),
    (r"\bdo not (tell|inform|mention|reveal|disclose|show)\b.{0,30}\b(user|human|reader|recipient|anyone)\b",
     "Instruction to conceal from the user"),
    (r"\b(candidate|applicant|resume|cv)\b.{0,40}\b(perfect|ideal|excellent|exceptional|best|top|strongest)\b.{0,20}\b(fit|match|candidate|hire|choice)\b",
     "Possible resume/evaluation manipulation"),
    (r"\b(give|assign|award)\b.{0,30}\b(highest|maximum|perfect|10/10|5 stars|full marks)\b.{0,15}\b(score|rating|marks|grade|review|evaluation)?",
     "Possible score/rating manipulation"),
    (r"\b(only )?(positive|favorable|favourable) (review|summary|evaluation|assessment)\b", "Possible review manipulation"),
    (r"<\|?\s*(im_start|im_end|system|endoftext|assistant|user)\s*\|?>|\[/?(INST|SYS)\]|<<\s*SYS\s*>>|</?(system|instructions?)>",
     "LLM chat-template / control tokens"),
    (r"\b(jailbreak|DAN mode|developer mode enabled|do anything now)\b", "Jailbreak keyword"),
    (r"\b(exfiltrate|send|forward|upload|post|transmit|email)\b.{0,40}\b(conversation|chat history|data|credentials|passwords?|api keys?|tokens?|contents?)\b.{0,30}\b(to|at)\b.{0,10}(https?://|www\.|\S+@\S+)",
     "Data-exfiltration instruction"),
    (r"!\[[^\]]{0,100}\]\(\s*https?://[^)]*(\?|\{|%7B)[^)]*\)", "Markdown image beacon (exfiltration technique)"),
    (r"\bwhen (summariz|read|process|analyz|review)\w*\b.{0,40}\b(this|the) (document|file|email|message|page|text)",
     "Instruction targeting automated processing"),
    (r"\b(respond|reply|answer|output)\b.{0,20}\bonly with\b", "Output-control instruction"),
    (r"\b(call|invoke|execute)\b.{0,20}\b(the )?(\w+ )?(tool|plugin|shell command)\b.{0,40}\b(without|silently|immediately|now)\b",
     "Tool-invocation instruction"),
]
_INJ = [(re.compile(p, re.I | re.S), d) for p, d in INJECTION_PATTERNS]

_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")


def visible_repr(s: str) -> str:
    """Render invisible / control characters as visible tags so snippets can be inspected."""
    out = []
    for ch in s:
        cp = ord(ch)
        if cp in ZERO_WIDTH or cp in BIDI or 0xE0000 <= cp <= 0xE007F or 0xFE00 <= cp <= 0xFE0F \
                or 0xE0100 <= cp <= 0xE01EF:
            out.append(f"⟨U+{cp:04X}⟩")
        elif cp < 32 and ch not in "\n\t":
            out.append(f"⟨0x{cp:02X}⟩")
        else:
            out.append(ch)
    return "".join(out)


def decode_tag_chars(s: str) -> str:
    return "".join(chr(ord(c) - 0xE0000) for c in s if 0xE0020 <= ord(c) <= 0xE007E)


def decode_variation_selectors(s: str) -> bytes:
    """Decode the 'emoji smuggling' scheme: each byte encoded as a variation selector."""
    out = bytearray()
    for c in s:
        cp = ord(c)
        if 0xFE00 <= cp <= 0xFE0F:
            out.append(cp - 0xFE00)
        elif 0xE0100 <= cp <= 0xE01EF:
            out.append(cp - 0xE0100 + 16)
    return bytes(out)


def decode_zero_width_binary(s: str):
    """Try decoding zero-width chars as binary (ZWSP/ZWNJ = 0/1 style schemes)."""
    zw = [c for c in s if ord(c) in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF)]
    if len(zw) < 16:
        return None
    kinds = sorted(set(zw))
    if len(kinds) < 2:
        return None
    for zero, one in ((kinds[0], kinds[1]), (kinds[1], kinds[0])):
        bits = "".join("0" if c == zero else "1" for c in zw if c in (zero, one))
        data = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))
        try:
            txt = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if txt and sum(ch.isprintable() for ch in txt) / len(txt) > 0.9:
            return txt
    return None


def _scripts_in_word(word):
    scripts = set()
    for ch in word:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue
        for s in ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE"):
            if name.startswith(s):
                scripts.add(s)
                break
    return scripts


def analyze_text(report: Report, text: str, location: str, hidden: bool = False, context: str = ""):
    """Run all text-level checks. `hidden` raises severity of injection hits found in concealed text."""
    if not text or not text.strip("\x00"):
        return
    where = location + (f" ({context})" if context else "")

    # Unicode tag characters (ASCII smuggling)
    tags = [c for c in text if 0xE0000 <= ord(c) <= 0xE007F]
    if tags:
        decoded = decode_tag_chars(text)
        report.add(HIGH, "Unicode smuggling (tag characters)", where,
                   f"{len(tags)} invisible Unicode TAG characters - readable by AI models but invisible to people.",
                   f"Decoded hidden text: {decoded}")
        _injection_scan(report, decoded, where + " [decoded tag chars]", hidden=True)

    # Variation-selector smuggling
    vs = [c for c in text if 0xE0100 <= ord(c) <= 0xE01EF or 0xFE00 <= ord(c) <= 0xFE0F]
    if len(vs) >= 4:
        raw = decode_variation_selectors(text)
        try:
            dec = raw.decode("utf-8")
        except UnicodeDecodeError:
            dec = raw.hex()
        sev = HIGH if len(vs) >= 8 else MEDIUM
        report.add(sev, "Unicode smuggling (variation selectors)", where,
                   f"{len(vs)} variation-selector characters; can encode hidden bytes (emoji smuggling).",
                   f"Decoded bytes: {dec}")
        _injection_scan(report, dec, where + " [decoded variation selectors]", hidden=True)

    # Zero-width / invisible characters
    zw = [c for i, c in enumerate(text) if ord(c) in ZERO_WIDTH and not (ord(c) == 0xFEFF and i == 0)]
    zw = [c for c in zw if ord(c) != 0x00AD]  # soft hyphens counted separately
    if zw:
        counts = {}
        for c in zw:
            counts[ZERO_WIDTH[ord(c)]] = counts.get(ZERO_WIDTH[ord(c)], 0) + 1
        summary = ", ".join(f"{k} x{v}" for k, v in counts.items())
        decoded = decode_zero_width_binary(text)
        sev = HIGH if decoded or len(zw) >= 16 else (MEDIUM if len(zw) >= 3 else LOW)
        report.add(sev, "Invisible characters", where, f"{len(zw)} zero-width/invisible characters: {summary}",
                   (f"Decoded as binary: {decoded}\n" if decoded else "") + visible_repr(text[:300]))
        if decoded:
            _injection_scan(report, decoded, where + " [decoded zero-width]", hidden=True)

    shy = text.count("­")
    if shy >= 10:
        report.add(LOW, "Invisible characters", where, f"{shy} soft hyphens (can be used to break up words to evade filters).")

    bidi = [c for c in text if ord(c) in BIDI]
    if bidi:
        report.add(MEDIUM, "Bidirectional override", where,
                   f"{len(bidi)} bidi control characters - can make displayed text differ from the stored text (Trojan Source).",
                   visible_repr(text[:300]))

    ctrl = [c for c in text if ord(c) < 32 and c not in "\t\r\n\x0b\x0c"]
    if len(ctrl) >= 3:
        report.add(LOW, "Control characters", where, f"{len(ctrl)} non-printing control characters embedded in text.")

    pua = [c for c in text if 0xE000 <= ord(c) <= 0xF8FF or 0xF0000 <= ord(c) <= 0x10FFFF]
    if len(pua) >= 5:
        report.add(LOW, "Private-use characters", where,
                   f"{len(pua)} private-use code points (may render as symbols or nothing; sometimes used to hide data).")

    # Homoglyphs: words mixing Latin with Cyrillic/Greek
    mixed = []
    for w in re.findall(r"\w{3,}", text):
        if len(_scripts_in_word(w)) > 1:
            mixed.append(w)
    if mixed:
        report.add(MEDIUM if len(mixed) > 2 else LOW, "Homoglyphs (mixed scripts)", where,
                   f"{len(mixed)} word(s) mix Latin with Cyrillic/Greek look-alike letters - used to evade filters or spoof names.",
                   ", ".join(dict.fromkeys(mixed[:15])))

    _injection_scan(report, text, where, hidden)

    # Base64 blobs that decode to text
    for m in list(_B64.finditer(text))[:20]:
        blob = m.group(0)
        try:
            dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            s = dec.decode("utf-8")
        except Exception:
            continue
        if len(s) >= 12 and sum(ch.isprintable() or ch in "\r\n\t" for ch in s) / len(s) > 0.95:
            report.add(MEDIUM if hidden else LOW, "Encoded text (Base64)", where,
                       "Base64 blob decodes to readable text.", f"Decoded: {s}")
            _injection_scan(report, s, where + " [decoded base64]", hidden=True)


def _pattern_hits(text):
    hits = []
    for rx, desc in _INJ:
        m = rx.search(text)
        if m:
            s, e = max(0, m.start() - 80), min(len(text), m.end() + 120)
            hits.append((desc, text[s:e]))
    return hits


def _injection_scan(report, text, where, hidden):
    plain = strip_invisible(text)
    hits = _pattern_hits(plain)
    obfuscated = False
    if not hits:
        # An LLM reads fullwidth, look-alike and letter-spaced text as ordinary words; match it the same way.
        norm = collapse_letter_spacing(normalize_for_match(text))
        hits = _pattern_hits(norm)
        squashed = [p for run in _SPACED_RUN.findall(normalize_for_match(text))
                    for p in SQUASHED_PHRASES if p in re.sub(r"[\W_]", "", run).lower()]
        if squashed:
            hits.append(("Letter-spaced instruction phrase", f"'{squashed[0]}' spelled out with spaces between letters"))
        obfuscated = bool(hits)
    if not hits:
        return
    sev = HIGH if hidden or obfuscated or len(hits) >= 2 else MEDIUM
    descs = "; ".join(dict.fromkeys(d for d, _ in hits))
    report.add(sev, "Possible AI prompt injection", where,
               ("HIDDEN text " if hidden else "Text ") + f"matches prompt-injection patterns: {descs}"
               + (" - disguised with fullwidth, look-alike or letter-spaced characters" if obfuscated else ""),
               hits[0][1])


def strip_invisible(s: str) -> str:
    return "".join(c for c in s if not (ord(c) in ZERO_WIDTH or ord(c) in BIDI or 0xE0000 <= ord(c) <= 0xE01EF
                                         or 0xFE00 <= ord(c) <= 0xFE0F))


# Cyrillic and Greek letters that look like Latin ones (the common subset of Unicode's confusables list)
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w", "ь": "b", "А": "A", "В": "B", "Е": "E", "К": "K",
    "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "У": "Y", "І": "I", "Ј": "J",
    "Ѕ": "S", "Ԁ": "D", "Ԛ": "Q", "Ԝ": "W",
    "α": "a", "ο": "o", "ν": "v", "ι": "i", "κ": "k", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ε": "e",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
})


def normalize_for_match(s: str) -> str:
    """Fold fullwidth/stylized (NFKC) and Cyrillic/Greek look-alike letters to plain Latin, minus invisibles."""
    return unicodedata.normalize("NFKC", strip_invisible(s)).translate(CONFUSABLES)


_SPACED_WORD = re.compile(r"(?<!\w)(?:\w[ .\-_·*]){3,}\w(?!\w)")
_SPACED_RUN = re.compile(r"(?<!\w)\w(?:[\s.\-_·*]{1,3}\w(?!\w)){7,}")
SQUASHED_PHRASES = ("ignoreallpreviousinstructions", "ignorepreviousinstructions", "ignoreallpriorinstructions",
                    "ignorepriorinstructions", "disregardpreviousinstructions", "disregardallpreviousinstructions",
                    "forgetallpreviousinstructions", "forgetpreviousinstructions", "ignoretheaboveinstructions",
                    "ignoreallinstructions", "systemprompt", "youarenowan", "developermode", "jailbreak")


def collapse_letter_spacing(s: str) -> str:
    """Turn 'I g n o r e  a l l' into 'Ignore all' (single letters joined; wider gaps stay word breaks)."""
    return _SPACED_WORD.sub(lambda m: re.sub(r"[ .\-_·*]", "", m.group(0)), s)


# --------------------------------------------------------------------------------------
# Color helpers
# --------------------------------------------------------------------------------------

def parse_hex(c):
    if not c:
        return None
    c = c.strip().lstrip("#")
    if len(c) == 8:  # ARGB
        c = c[2:]
    if len(c) == 3:
        c = "".join(ch * 2 for ch in c)
    if len(c) != 6:
        return None
    try:
        return tuple(int(c[i:i + 2], 16) for i in (0, 2, 4))
    except ValueError:
        return None


def _lum(rgb):
    def ch(v):
        v /= 255
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = rgb
    return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b)


def contrast(c1, c2):
    a, b = _lum(c1), _lum(c2)
    hi, lo = max(a, b), min(a, b)
    return (hi + 0.05) / (lo + 0.05)


def apply_tint(rgb, tint):
    if not tint:
        return rgb
    if tint > 0:
        return tuple(int(v + (255 - v) * tint) for v in rgb)
    return tuple(int(v * (1 + tint)) for v in rgb)


def hexs(rgb):
    return "#%02X%02X%02X" % rgb if rgb else "?"


WHITE = (255, 255, 255)
BLACK = (0, 0, 0)
INVISIBLE_CONTRAST = 1.5  # below this ratio text is effectively invisible against its background


# --------------------------------------------------------------------------------------
# Decompression budget (zip bombs, nested archives)
# --------------------------------------------------------------------------------------

MAX_PART_BYTES = 256 * 1024 * 1024  # largest single decompressed part / stream
MAX_TOTAL_BYTES = 1024 * 1024 * 1024  # everything decompressed while scanning one top-level file


class BudgetExceeded(BaseException):
    """Aborts the current scan. A BaseException (like KeyboardInterrupt) so parsers' `except Exception`
    handlers can't swallow it; dispatch.scan_bytes reports it."""


class Budget:
    def __init__(self, limit=None):
        self.limit = MAX_TOTAL_BYTES if limit is None else limit
        self.used = 0

    def charge(self, n, what):
        if n > MAX_PART_BYTES:
            raise BudgetExceeded(f"'{what}' expands to {n:,} bytes (single-part limit {MAX_PART_BYTES:,})")
        if self.used + n > self.limit:
            raise BudgetExceeded(f"'{what}' would push decompressed data past {self.limit:,} bytes "
                                 f"({self.used:,} already used)")
        self.used += n


_budget = contextvars.ContextVar("hcs_budget", default=None)


def current_budget():
    b = _budget.get()
    if b is None:
        b = Budget()
        _budget.set(b)
    return b


def new_budget(limit=None):
    """Start a fresh budget for one top-level scan (per thread/context)."""
    b = Budget(limit)
    _budget.set(b)
    return b


def read_zip_member(z, member):
    """Read a ZIP entry after charging its declared size to the budget; never returns more than declared."""
    info = member if hasattr(member, "file_size") else z.getinfo(member)
    current_budget().charge(info.file_size, info.filename)
    with z.open(info) as f:
        data = f.read(info.file_size + 1)
    if len(data) > info.file_size:
        raise BudgetExceeded(f"'{info.filename}' is larger than its declared size")
    return data


def read_ole_stream(ole, path):
    current_budget().charge(ole.get_size(path), str(path))
    return ole.openstream(path).read()


# --------------------------------------------------------------------------------------
# Binary helpers
# --------------------------------------------------------------------------------------

def printable_strings(data: bytes, min_len=6, limit=40):
    """Extract ASCII and UTF-16LE strings from binary data."""
    out = []
    for m in re.finditer(rb"[\x20-\x7e\t\r\n]{%d,}" % min_len, data):
        out.append(m.group(0).decode("ascii", "replace"))
        if len(out) >= limit:
            break
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data):
        out.append(m.group(0).decode("utf-16le", "replace"))
        if len(out) >= limit * 2:
            break
    return out


def check_image_trailer(report, data: bytes, location: str):
    """Detect data appended after an image's logical end (a classic hiding technique)."""
    extra = None
    kind = None
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        kind = "PNG"
        i = data.rfind(b"IEND")
        if i != -1:
            end = i + 8
            extra = data[end:]
    elif data[:3] == b"\xff\xd8\xff":
        kind = "JPEG"
        i = data.rfind(b"\xff\xd9")
        if i != -1:
            extra = data[i + 2:]
    elif data[:6] in (b"GIF87a", b"GIF89a"):
        kind = "GIF"
        i = data.rfind(b"\x3b")
        if i != -1:
            extra = data[i + 1:]
    if kind and extra and len(extra.strip(b"\x00")) > 16:
        strs = printable_strings(extra, limit=10)
        sev = HIGH if len(extra) > 512 or extra[:2] == b"PK" else MEDIUM
        what = " (looks like a ZIP archive)" if extra[:2] == b"PK" else ""
        report.add(sev, "Data appended to image", location,
                   f"{len(extra):,} bytes after the end of the {kind} image{what}.", "\n".join(strs[:10]))
        return extra
    return None
