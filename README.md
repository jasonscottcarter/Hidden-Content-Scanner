# Hidden Content Scanner

Local, offline scanner that finds concealed content in documents: AI prompt injections, hidden or white or tiny text, smuggled Unicode, hidden sheets and slides, macros, embedded files, appended data, NTFS alternate data streams and file slack. Files are only read. Nothing is modified, uploaded or executed.

## Run
- **GUI:** double-click `Hidden Content Scanner.pyw`. Then drag files or folders onto the window, or use Browse.
- **CLI:** `python scan_cli.py <files/folders> [--html report.html] [--json report.json] [--slack]`
- **Install dependencies:** `python -m pip install -r requirements.txt`

## Supported formats
Word (.docx/.docm/.dotx, .doc, .rtf), Excel (.xlsx/.xlsm, .xls), PowerPoint (.pptx/.pptm/.ppsx, .ppt), PDF, email (.eml, .msg, .mht), OpenDocument (.odt/.ods/.odp), and text (.txt/.csv/.md/.html/.xml/.json). Attachments and embedded files are scanned recursively, up to 4 levels deep.

## What it checks
| Area | Checks |
|---|---|
| Prompt injection | Instruction-override phrases, text addressed to an AI, role hijacking, chat-template tokens, data-exfiltration and markdown-beacon patterns. Text is normalized first, so fullwidth, math-styled, Cyrillic/Greek look-alike and letter-spaced (`I g n o r e`) variants are caught. Severity is raised when the text is hidden or disguised. |
| Unicode smuggling | Unicode TAG characters (decoded), variation-selector "emoji smuggling" (decoded), zero-width binary (decoded), bidi overrides, interlinear annotation and other invisible format characters, homoglyphs |
| Word | White or low-contrast text (resolves styles, themes, shading, highlights), `vanish` hidden text, tiny, condensed or squeezed text, hidden or off-page drawings and text boxes, tracked deletions, comments, docVars, DDE/INCLUDETEXT fields, altChunks, remote templates |
| Excel | Hidden and *very hidden* sheets, hidden rows and columns, `;;;` and value-masking number formats, white-on-fill cells, data parked far away, hidden names, XLM macro sheets, DDE/WEBSERVICE formulas, data connections |
| PowerPoint | Off-slide, hidden, zero-size or covered shapes, white, transparent or no-fill text, hidden slides, orphan slides, speaker notes, unused layouts |
| PDF | Invisible render mode, white, tiny or transparent text, text covered by shapes or images, off-page text, hidden layers, JavaScript, Launch actions, attachments, hidden annotations, orphaned objects, text deleted in earlier revisions |
| Email | Hidden HTML (display:none, white, zero-size, off-screen), plain-text vs HTML part mismatch, HTML comments, tracking pixels, deceptive links, header anomalies, attachments |
| Containers | Data appended to or prepended before the file, hidden gaps between ZIP entries, orphaned package parts, ZIP comments, data appended to images, unallocated OLE sectors (internal "slack"), XXE/entity-bomb XML, decompression bombs |
| Windows | NTFS alternate data streams (and the Mark of the Web download source), plus **disk file slack**, which needs Administrator rights - see below |

## Administrator rights and file slack
Reading file slack means reading raw disk clusters, which Windows allows only for administrators. Tick **File slack (admin)** in the GUI (or pass `--slack` to the CLI) and Windows asks once per scan for permission to run a small helper (`hcs/slack_helper.py`). That helper only reads the slack bytes and hands them back; every document is still opened and parsed with your normal rights.

You can also start the scanner with **Run as administrator**, and the slack check then needs no prompt. It isn't recommended: the whole program, including the parsers that open untrusted files, would run with admin rights.

## Resource limits
To withstand decompression bombs, one scan of a file (including its attachments and embedded files) may decompress at most 1 GB in total and 256 MB for any single part. Hitting a limit stops that scan and is reported as a HIGH finding, since legitimate documents rarely expand that far.

## Limitations
- Prompt-injection detection is pattern-based. Novel wording can evade it, and benign text can occasionally match.
- Legacy binary .doc/.ppt formatting isn't fully parsed. Save as .docx/.pptx and rescan for complete hidden-text checks.
- Pixel-level image steganography and custom-font glyph remapping are not detected.
- Disk file slack belongs to *this* disk. It shows leftovers or hidden data on your drive, and it does not travel with copies of the file.

## License
This project's own code is MIT. See [LICENSE](LICENSE).

It relies on third-party libraries, installed separately through `requirements.txt`, that have their own licenses:

| Library | License | Used for |
|---|---|---|
| [PyMuPDF](https://pymupdf.readthedocs.io/) | AGPL-3.0, or a commercial license from Artifex | PDF analysis |
| [extract-msg](https://github.com/TeamMsgExtractor/msg-extractor) | GPL-3.0 | Outlook `.msg` files |
| oletools, olefile | BSD | Legacy Office files and macros |
| defusedxml | PSF | Safe XML parsing |
| tkinterdnd2 | MIT | Drag and drop in the GUI |

Using the scanner, or sharing this source code, is unaffected. But if you **distribute a bundled build** (for example a PyInstaller `.exe` that includes PyMuPDF and extract-msg), the bundle as a whole must meet the GPL/AGPL terms, including offering its full source code. Whether sharing a build inside a company counts as distribution depends on the circumstances, so check with whoever handles software licensing before deploying one at work. This is not legal advice.

## Tests
```
python -m pip install -r requirements-dev.txt
python -m pytest -q
```
The tests generate booby-trapped and clean documents (`tests/make_samples.py`, `tests/make_clean.py`), then check that every trap is flagged, every clean file passes, known evasion tricks are caught and decompression bombs are stopped. GitHub Actions runs them on every push.
