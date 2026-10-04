"""Hidden Content Scanner - desktop GUI (drag & drop or browse)."""
from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hcs import __version__
from hcs.core import visible_repr
from hcs.dispatch import scan_path, expand_paths, SUPPORTED_EXT
from hcs.ntfs import is_admin, relaunch_as_admin
from hcs.report_export import to_html

try:
    from tkinterdnd2 import TkinterDnD, DND_FILES
    DND = True
except Exception:
    DND = False

if sys.platform == "win32":
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

SEV_COLORS = {"HIGH": "#fde2e2", "MEDIUM": "#fff1d6", "LOW": "#e3edff", "INFO": "#f1f2f4"}
SEV_FG = {"HIGH": "#a31515", "MEDIUM": "#8a5300", "LOW": "#1d4ed8", "INFO": "#555b66"}


class App:
    def __init__(self):
        self.root = TkinterDnD.Tk() if DND else tk.Tk()
        self.root.title(f"Hidden Content Scanner {__version__}" + ("  [Administrator]" if is_admin() else ""))
        try:
            self.root.state("zoomed")
        except tk.TclError:
            self.root.geometry("1280x820")
        self.root.minsize(900, 600)
        self.reports = {}  # tree iid -> Report
        self.top_reports = []
        self.jobs = queue.Queue()
        self.results = queue.Queue()
        self.pending = 0
        self.batch_total = 0
        self.var_slack = tk.BooleanVar(value=is_admin())
        self.var_ads = tk.BooleanVar(value=True)
        self.var_info = tk.BooleanVar(value=True)
        self.var_all = tk.BooleanVar(value=False)
        self._style()
        self._build()
        threading.Thread(target=self._worker, daemon=True).start()
        self.root.after(100, self._poll)
        if len(sys.argv) > 1:
            self.add_paths(sys.argv[1:])

    # ------------------------------------------------------------------ UI
    def _style(self):
        s = ttk.Style()
        try:
            s.theme_use("vista" if sys.platform == "win32" else "clam")
        except tk.TclError:
            pass
        s.configure("Title.TLabel", font=("Segoe UI Semibold", 16))
        s.configure("Sub.TLabel", foreground="#5d6675")
        s.configure("Treeview", rowheight=24)
        s.configure("Drop.TFrame", background="#f4f7fb")

    def _build(self):
        r = self.root
        top = ttk.Frame(r, padding=(14, 10, 14, 4))
        top.pack(fill="x")
        ttk.Label(top, text="Hidden Content Scanner", style="Title.TLabel").pack(anchor="w")
        ttk.Label(top, style="Sub.TLabel",
                  text="Finds AI prompt injections, hidden/white/tiny text, concealed sheets & slides, smuggled Unicode, "
                       "macros, embedded files, appended data, alternate data streams and file slack.").pack(anchor="w")

        # Drop zone
        self.drop = tk.Canvas(r, height=110, highlightthickness=0, bg="#f4f7fb", cursor="hand2")
        self.drop.pack(fill="x", padx=14, pady=8)
        self.drop.bind("<Configure>", self._draw_drop)
        self.drop.bind("<Button-1>", lambda e: self.browse_files())
        if DND:
            self.drop.drop_target_register(DND_FILES)
            self.drop.dnd_bind("<<DropEnter>>", lambda e: self._drop_hover(True))
            self.drop.dnd_bind("<<DropLeave>>", lambda e: self._drop_hover(False))
            self.drop.dnd_bind("<<Drop>>", self._on_drop)
        self._hover = False

        bar = ttk.Frame(r, padding=(14, 0, 14, 6))
        bar.pack(fill="x")
        ttk.Button(bar, text="Browse Files…", command=self.browse_files).pack(side="left")
        ttk.Button(bar, text="Browse Folder…", command=self.browse_folder).pack(side="left", padx=6)
        ttk.Button(bar, text="Export Report…", command=self.export).pack(side="left")
        ttk.Button(bar, text="Clear", command=self.clear).pack(side="left", padx=6)
        ttk.Checkbutton(bar, text="Show INFO", variable=self.var_info, command=self._refresh_findings).pack(side="right")
        ttk.Checkbutton(bar, text="Folder: all file types", variable=self.var_all).pack(side="right", padx=8)
        ttk.Checkbutton(bar, text="Alternate data streams", variable=self.var_ads).pack(side="right")
        ttk.Checkbutton(bar, text="File slack (admin)", variable=self.var_slack, command=self._slack_toggled).pack(side="right", padx=8)

        prog = ttk.Frame(r, padding=(14, 0, 14, 6))
        prog.pack(fill="x")
        self.pb = ttk.Progressbar(prog, mode="determinate")
        self.pb.pack(side="left", fill="x", expand=True)
        self.status = ttk.Label(prog, text="Ready", width=48, anchor="e")
        self.status.pack(side="right", padx=(10, 0))

        # Main panes
        pw = ttk.PanedWindow(r, orient="horizontal")
        pw.pack(fill="both", expand=True, padx=14, pady=(0, 12))

        left = ttk.Frame(pw)
        self.files = ttk.Treeview(left, columns=("verdict", "h", "m", "l"), selectmode="browse")
        self.files.heading("#0", text="File")
        for c, t, w in (("verdict", "Verdict", 110), ("h", "High", 50), ("m", "Med", 50), ("l", "Low", 50)):
            self.files.heading(c, text=t)
            self.files.column(c, width=w, anchor="center", stretch=False)
        self.files.column("#0", width=260)
        self.files.tag_configure("bad", foreground=SEV_FG["HIGH"])
        self.files.tag_configure("warn", foreground=SEV_FG["MEDIUM"])
        self.files.tag_configure("ok", foreground="#15803d")
        self.files.tag_configure("err", foreground="#6b7280")
        ys = ttk.Scrollbar(left, orient="vertical", command=self.files.yview)
        self.files.configure(yscrollcommand=ys.set)
        self.files.pack(side="left", fill="both", expand=True)
        ys.pack(side="right", fill="y")
        self.files.bind("<<TreeviewSelect>>", lambda e: self._refresh_findings())
        self.files.bind("<Button-3>", self._file_menu)
        pw.add(left, weight=1)

        right = ttk.PanedWindow(pw, orient="vertical")
        ftop = ttk.Frame(right)
        self.find = ttk.Treeview(ftop, columns=("sev", "cat", "loc", "detail"), show="headings", selectmode="browse")
        for c, t, w in (("sev", "Severity", 80), ("cat", "Category", 200), ("loc", "Location", 200), ("detail", "Detail", 420)):
            self.find.heading(c, text=t)
            self.find.column(c, width=w, stretch=(c == "detail"))
        for sev, bg in SEV_COLORS.items():
            self.find.tag_configure(sev, background=bg, foreground=SEV_FG[sev])
        fys = ttk.Scrollbar(ftop, orient="vertical", command=self.find.yview)
        self.find.configure(yscrollcommand=fys.set)
        self.find.pack(side="left", fill="both", expand=True)
        fys.pack(side="right", fill="y")
        self.find.bind("<<TreeviewSelect>>", lambda e: self._show_detail())
        right.add(ftop, weight=3)

        fbot = ttk.Frame(right)
        self.detail = tk.Text(fbot, wrap="word", font=("Consolas", 10), relief="flat", padx=10, pady=8, bg="#fbfbfc")
        dys = ttk.Scrollbar(fbot, orient="vertical", command=self.detail.yview)
        self.detail.configure(yscrollcommand=dys.set, state="disabled")
        self.detail.tag_configure("h", font=("Segoe UI Semibold", 11))
        self.detail.tag_configure("muted", foreground="#5d6675")
        self.detail.tag_configure("snip", background="#fff7e0")
        self.detail.pack(side="left", fill="both", expand=True)
        dys.pack(side="right", fill="y")
        right.add(fbot, weight=2)
        pw.add(right, weight=5)
        self._right = right
        def _sashes():
            right.sashpos(0, int(right.winfo_height() * 0.55))
            pw.sashpos(0, int(pw.winfo_width() * 0.3))
        self.root.after(300, _sashes)
        self._set_detail(self._welcome())

    def _welcome(self):
        return [("Drop files or folders onto the box above, or use Browse.\n\n", "h"),
                ("Supported: Word (.docx/.docm/.doc/.rtf), Excel (.xlsx/.xlsm/.xls), PowerPoint (.pptx/.ppt), PDF, "
                 "email (.eml/.msg/.mht), text (.txt/.csv/.md/.html/.xml/.json), OpenDocument (.odt/.ods/.odp). "
                 "Attachments and embedded files are opened and scanned recursively.\n\n", ""),
                ("Files are only read - nothing is modified, uploaded or executed.\n\n", "muted"),
                ("File slack: reading the unused tail of a file's last disk cluster needs Administrator rights. "
                 "Tick 'File slack (admin)' to restart elevated.", "muted")]

    def _draw_drop(self, e=None):
        c = self.drop
        c.delete("all")
        w, h = c.winfo_width(), c.winfo_height()
        col = "#2563eb" if self._hover else "#9aa8bd"
        c.configure(bg="#e6efff" if self._hover else "#f4f7fb")
        c.create_rectangle(6, 6, w - 6, h - 6, outline=col, width=2, dash=(6, 4))
        main = "Drop files or folders here" if DND else "Click to choose files (drag & drop unavailable)"
        c.create_text(w / 2, h / 2 - 12, text=main, font=("Segoe UI Semibold", 14), fill="#1d2330")
        c.create_text(w / 2, h / 2 + 16, text="or click to browse  ·  Office, PDF, email, text",
                      font=("Segoe UI", 10), fill="#5d6675")

    def _drop_hover(self, on):
        self._hover = on
        self._draw_drop()
        return "copy"

    def _on_drop(self, e):
        self._drop_hover(False)
        self.add_paths(self.root.tk.splitlist(e.data))
        return "copy"

    def _slack_toggled(self):
        if self.var_slack.get() and not is_admin():
            if messagebox.askyesno("Administrator required",
                                   "Reading file slack requires raw disk access.\n\nRestart the scanner as Administrator now?"):
                if relaunch_as_admin():
                    self.root.destroy()
                    return
            self.var_slack.set(False)

    def _file_menu(self, e):
        iid = self.files.identify_row(e.y)
        if not iid:
            return
        self.files.selection_set(iid)
        rep = self.reports.get(iid)
        m = tk.Menu(self.root, tearoff=0)
        if rep and os.path.exists(rep.path):
            m.add_command(label="Show in Explorer", command=lambda: subprocess.Popen(["explorer", "/select,", os.path.normpath(rep.path)]))
            m.add_command(label="Rescan", command=lambda: self.add_paths([rep.path]))
        m.add_command(label="Copy findings", command=lambda: self._copy(rep))
        m.tk_popup(e.x_root, e.y_root)

    def _copy(self, rep):
        if not rep:
            return
        lines = [f"{rep.path} [{rep.file_type}]"]
        for f in rep.sorted_findings():
            lines.append(f"[{f.severity}] {f.category} @ {f.location}: {f.detail}" + (f"\n    {visible_repr(f.snippet)}" if f.snippet else ""))
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(lines))

    # ------------------------------------------------------------------ actions
    def browse_files(self):
        exts = " ".join(f"*{e}" for e in sorted(SUPPORTED_EXT))
        paths = filedialog.askopenfilenames(title="Choose files to scan",
                                            filetypes=[("Supported documents", exts), ("All files", "*.*")])
        if paths:
            self.add_paths(paths)

    def browse_folder(self):
        p = filedialog.askdirectory(title="Choose a folder to scan")
        if p:
            self.add_paths([p])

    def add_paths(self, paths):
        files = expand_paths(paths, include_all=self.var_all.get())
        if not files:
            self.status.configure(text="No supported files found")
            return
        if self.pending == 0:  # new batch
            self.batch_total = 0
            self.pb["value"] = 0
        for f in files:
            self.jobs.put((f, self.var_ads.get(), self.var_slack.get() and is_admin()))
        self.pending += len(files)
        self.batch_total += len(files)
        self.pb.configure(maximum=self.batch_total)
        self.status.configure(text=f"Scanning… {self.pending} remaining")

    def clear(self):
        self.files.delete(*self.files.get_children())
        self.find.delete(*self.find.get_children())
        self.reports.clear()
        self.top_reports.clear()
        self._set_detail(self._welcome())
        self.status.configure(text="Ready")

    def export(self):
        if not self.top_reports:
            messagebox.showinfo("Export", "Nothing to export yet.")
            return
        p = filedialog.asksaveasfilename(title="Save report", defaultextension=".html",
                                         filetypes=[("HTML report", "*.html"), ("JSON", "*.json")],
                                         initialfile="hidden-content-report.html")
        if not p:
            return
        with open(p, "w", encoding="utf-8") as f:
            if p.lower().endswith(".json"):
                json.dump([r.to_dict() for r in self.top_reports], f, indent=2, ensure_ascii=False)
            else:
                f.write(to_html(self.top_reports))
        if p.lower().endswith(".html"):
            os.startfile(p) if sys.platform == "win32" else None
        self.status.configure(text=f"Saved {os.path.basename(p)}")

    # ------------------------------------------------------------------ worker
    def _worker(self):
        while True:
            path, ads, slack = self.jobs.get()
            try:
                rep = scan_path(path, check_ads=ads, check_slack=slack)
            except Exception as e:
                from hcs.core import Report
                rep = Report(path)
                rep.error(f"Scan failed: {e}")
            self.results.put(rep)

    def _poll(self):
        try:
            while True:
                rep = self.results.get_nowait()
                self.pending -= 1
                self.pb["value"] = self.pb["value"] + 1
                self._add_report(rep)
        except queue.Empty:
            pass
        if self.pending > 0:
            self.status.configure(text=f"Scanning… {self.pending} remaining")
        elif self.top_reports:
            bad = sum(1 for r in self.top_reports if r.counts()["HIGH"])
            self.status.configure(text=f"Done · {len(self.top_reports)} file(s) · {bad} with HIGH findings")
        self.root.after(100, self._poll)

    def _verdict(self, rep):
        c = rep.counts()
        if c["HIGH"]:
            return "Suspicious", "bad"
        if c["MEDIUM"]:
            return "Review", "warn"
        if rep.errors and not rep.findings:
            return "Partial", "err"
        return "Clean", "ok"

    def _insert(self, parent, rep, label):
        v, tag = self._verdict(rep)
        c = rep.counts()
        iid = self.files.insert(parent, "end", text=label, values=(v, c["HIGH"] or "", c["MEDIUM"] or "", c["LOW"] or ""),
                                tags=(tag,), open=True)
        self.reports[iid] = rep
        for ch in rep.children:
            self._insert(iid, ch, "↳ " + os.path.basename(ch.path))
        return iid

    def _add_report(self, rep):
        # replace an earlier scan of the same file
        for iid in self.files.get_children():
            if self.reports.get(iid) and self.reports[iid].path == rep.path:
                self.top_reports = [r for r in self.top_reports if r.path != rep.path]
                self.files.delete(iid)
        self.top_reports.append(rep)
        iid = self._insert("", rep, os.path.basename(rep.path))
        if len(self.files.get_children()) == 1 or not self.files.selection():
            self.files.selection_set(iid)

    # ------------------------------------------------------------------ findings pane
    def _refresh_findings(self):
        self.find.delete(*self.find.get_children())
        sel = self.files.selection()
        if not sel:
            return
        rep = self.reports.get(sel[0])
        if not rep:
            return
        self._rows = {}
        for f in rep.sorted_findings():
            if f.severity == "INFO" and not self.var_info.get():
                continue
            iid = self.find.insert("", "end", values=(f.severity, f.category, f.location, f.detail), tags=(f.severity,))
            self._rows[iid] = f
        summary = [(f"{os.path.basename(rep.path)}\n", "h"), (f"{rep.file_type}\n{rep.path}\n\n", "muted")]
        c = rep.counts(recursive=False)
        if not rep.findings:
            summary.append(("No hidden content found in this file.\n", ""))
        else:
            summary.append((f"{c['HIGH']} high · {c['MEDIUM']} medium · {c['LOW']} low · {c['INFO']} info\n", ""))
            summary.append(("Select a finding above to see the exact hidden content.\n", "muted"))
        if rep.children:
            summary.append((f"\n{len(rep.children)} attachment(s)/embedded file(s) with results are listed under this file.\n", "muted"))
        for e in rep.errors:
            summary.append((f"\nScanner note: {e.splitlines()[0]}\n", "muted"))
        self._set_detail(summary)
        kids = self.find.get_children()
        if kids:
            self.find.selection_set(kids[0])

    def _show_detail(self):
        sel = self.find.selection()
        if not sel or sel[0] not in getattr(self, "_rows", {}):
            return
        f = self._rows[sel[0]]
        parts = [(f"[{f.severity}] {f.category}\n", "h"), (f"Location: {f.location}\n\n", "muted"), (f.detail + "\n", "")]
        if f.snippet:
            parts += [("\nContent:\n", "muted"), (visible_repr(f.snippet) + "\n", "snip")]
        self._set_detail(parts)

    def _set_detail(self, parts):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        for text, tag in parts:
            self.detail.insert("end", text, tag or ())
        self.detail.configure(state="disabled")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    App().run()
