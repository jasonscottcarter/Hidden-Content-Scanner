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
| Prompt injection | Instruction-override phrases, text addressed to an AI, role hijacking, chat-template tokens, data-exfiltration and markdown-beacon patterns. Severity is raised when the text is also hidden. |
| Unicode smuggling | Unicode TAG characters (decoded), variation-selector "emoji smuggling" (decoded), zero-width binary (decoded), bidi overrides, homoglyphs |
| Word | White or low-contrast text (resolves styles, themes, shading, highlights), `vanish` hidden text, tiny, condensed or squeezed text, hidden or off-page drawings and text boxes, tracked deletions, comments, docVars, DDE/INCLUDETEXT fields, altChunks, remote templates |
| Excel | Hidden and *very hidden* sheets, hidden rows and columns, `;;;` and value-masking number formats, white-on-fill cells, data parked far away, hidden names, XLM macro sheets, DDE/WEBSERVICE formulas, data connections |
| PowerPoint | Off-slide, hidden, zero-size or covered shapes, white, transparent or no-fill text, hidden slides, orphan slides, speaker notes, unused layouts |
| PDF | Invisible render mode, white, tiny or transparent text, text covered by shapes or images, off-page text, hidden layers, JavaScript, Launch actions, attachments, hidden annotations, orphaned objects, text deleted in earlier revisions |
| Email | Hidden HTML (display:none, white, zero-size, off-screen), plain-text vs HTML part mismatch, HTML comments, tracking pixels, deceptive links, header anomalies, attachments |
| Containers | Data appended to or prepended before the file, hidden gaps between ZIP entries, orphaned package parts, ZIP comments, data appended to images, unallocated OLE sectors (internal "slack"), XXE/entity-bomb XML |
| Windows | NTFS alternate data streams (and the Mark of the Web download source), plus **disk file slack**, which requires Administrator rights (the GUI offers to restart elevated) |

## Limitations
- Prompt-injection detection is pattern-based. Novel wording can evade it, and benign text can occasionally match.
- Legacy binary .doc/.ppt formatting isn't fully parsed. Save as .docx/.pptx and rescan for complete hidden-text checks.
- Pixel-level image steganography and custom-font glyph remapping are not detected.
- Disk file slack belongs to *this* disk. It shows leftovers or hidden data on your drive, and it does not travel with copies of the file.

## Tests
`python tests/make_samples.py out_dir` creates booby-trapped samples. `python tests/make_clean.py out_dir` creates legitimate white-on-dark designs that should come back clean.
