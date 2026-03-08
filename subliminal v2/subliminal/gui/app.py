"""
subliminal/gui/app.py — Tkinter GUI for SUBLIMINAL
"""

from __future__ import annotations

import asyncio
import queue
import threading
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk
from typing import Optional

from subliminal import __version__
from subliminal.modules.probe import ProbeResult
from subliminal.utils.config import PROFILES, SubliminalConfig


# ─── Colour palette ───────────────────────────────────────────────────────────
BG        = "#0d1117"
SURFACE   = "#161b22"
BORDER    = "#30363d"
TEXT      = "#c9d1d9"
ACCENT    = "#58a6ff"
GREEN     = "#3fb950"
YELLOW    = "#d29922"
RED       = "#f85149"
FONT_MONO = ("JetBrains Mono", 10) if True else ("Courier New", 10)


class SubliminalGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"SUBLIMINAL  v{__version__}")
        self.configure(bg=BG)
        self.geometry("1050x700")
        self.resizable(True, True)

        self._scan_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._result_queue: queue.Queue = queue.Queue()
        self._results: list[ProbeResult] = []

        self._build_ui()
        self.after(100, self._poll_results)

    # ── UI Construction ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self._build_header()
        pane = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        pane.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))
        pane.add(self._build_controls(pane), weight=1)
        pane.add(self._build_output(pane), weight=3)

    def _build_header(self) -> None:
        frame = tk.Frame(self, bg=BG, pady=12)
        frame.pack(fill=tk.X, padx=12)
        tk.Label(
            frame, text="▶ SUBLIMINAL", fg=ACCENT, bg=BG,
            font=("Courier New", 22, "bold"),
        ).pack(side=tk.LEFT)
        tk.Label(
            frame, text="  passive · precise · silent", fg="#8b949e", bg=BG,
            font=("Courier New", 11),
        ).pack(side=tk.LEFT, pady=(6, 0))

    def _build_controls(self, parent) -> tk.Frame:
        frame = tk.Frame(parent, bg=SURFACE, padx=14, pady=14)

        def _label(text):
            tk.Label(frame, text=text, fg="#8b949e", bg=SURFACE, font=FONT_MONO, anchor="w").pack(fill=tk.X, pady=(10, 2))

        def _entry():
            e = tk.Entry(frame, bg=BG, fg=TEXT, insertbackground=ACCENT, relief="flat",
                         font=FONT_MONO, bd=4)
            e.pack(fill=tk.X)
            return e

        _label("TARGET DOMAIN")
        self._domain_var = tk.StringVar()
        _entry().configure(textvariable=self._domain_var)

        _label("PROFILE")
        self._profile_var = tk.StringVar(value="deep")
        cb = ttk.Combobox(frame, textvariable=self._profile_var, values=list(PROFILES), state="readonly", font=FONT_MONO)
        cb.pack(fill=tk.X)
        self._profile_desc = tk.Label(frame, text=PROFILES["deep"]["description"], fg=YELLOW,
                                       bg=SURFACE, font=("Courier New", 9), wraplength=200, anchor="w", justify=tk.LEFT)
        self._profile_desc.pack(fill=tk.X, pady=(2, 0))
        self._profile_var.trace_add("write", self._on_profile_change)

        _label("CONCURRENCY")
        self._conc_var = tk.IntVar(value=150)
        tk.Scale(frame, from_=10, to=500, variable=self._conc_var, orient=tk.HORIZONTAL,
                 bg=SURFACE, fg=TEXT, troughcolor=BG, highlightthickness=0, font=FONT_MONO).pack(fill=tk.X)

        # Checkboxes
        self._active_var = tk.BooleanVar(value=False)
        self._bf_var     = tk.BooleanVar(value=False)
        self._probe_var  = tk.BooleanVar(value=True)
        for label, var in [("Enable TLS-SAN enrichment", self._active_var),
                            ("Enable DNS brute-force",    self._bf_var),
                            ("HTTP probe alive hosts",    self._probe_var)]:
            tk.Checkbutton(frame, text=label, variable=var, bg=SURFACE, fg=TEXT,
                           selectcolor=BG, activebackground=SURFACE, font=FONT_MONO).pack(anchor="w", pady=1)

        _label("OUTPUT FILE (optional)")
        self._out_var = tk.StringVar()
        out_frame = tk.Frame(frame, bg=SURFACE)
        out_frame.pack(fill=tk.X)
        tk.Entry(out_frame, textvariable=self._out_var, bg=BG, fg=TEXT,
                 insertbackground=ACCENT, relief="flat", font=FONT_MONO, bd=4).pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(out_frame, text="…", bg=BORDER, fg=TEXT, relief="flat",
                  font=FONT_MONO, command=self._browse_out).pack(side=tk.LEFT, padx=(4, 0))

        self._scan_btn = tk.Button(
            frame, text="▶  START SCAN", bg=ACCENT, fg=BG, font=("Courier New", 11, "bold"),
            relief="flat", padx=10, pady=8, cursor="hand2", command=self._toggle_scan,
        )
        self._scan_btn.pack(fill=tk.X, pady=(18, 4))

        self._status_var = tk.StringVar(value="Ready")
        tk.Label(frame, textvariable=self._status_var, fg="#8b949e", bg=SURFACE,
                 font=("Courier New", 9)).pack()

        return frame

    def _build_output(self, parent) -> tk.Frame:
        frame = tk.Frame(parent, bg=BG)

        # Stats bar
        stats = tk.Frame(frame, bg=SURFACE)
        stats.pack(fill=tk.X, pady=(0, 6))
        self._alive_var = tk.StringVar(value="0")
        self._total_var = tk.StringVar(value="0")
        for label_text, var, colour in [
            ("ALIVE", self._alive_var, GREEN),
            ("CANDIDATES", self._total_var, YELLOW),
        ]:
            sf = tk.Frame(stats, bg=SURFACE, padx=18, pady=8)
            sf.pack(side=tk.LEFT)
            tk.Label(sf, textvariable=var, fg=colour, bg=SURFACE, font=("Courier New", 22, "bold")).pack()
            tk.Label(sf, text=label_text, fg="#8b949e", bg=SURFACE, font=("Courier New", 8)).pack()

        # Results list
        list_frame = tk.Frame(frame, bg=BG)
        list_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("url", "status", "tls", "title")
        self._tree = ttk.Treeview(list_frame, columns=cols, show="headings", selectmode="browse")
        for col, w in [("url", 420), ("status", 70), ("tls", 50), ("title", 280)]:
            self._tree.heading(col, text=col.upper())
            self._tree.column(col, width=w, minwidth=40)
        sb = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.LEFT, fill=tk.Y)

        # Log pane
        tk.Label(frame, text="LOG", fg="#8b949e", bg=BG, font=("Courier New", 9), anchor="w").pack(fill=tk.X)
        self._log = scrolledtext.ScrolledText(
            frame, height=8, bg=SURFACE, fg="#8b949e", insertbackground=ACCENT,
            relief="flat", font=("Courier New", 9), state=tk.DISABLED,
        )
        self._log.pack(fill=tk.X, pady=(2, 0))

        # Export buttons
        btn_frame = tk.Frame(frame, bg=BG, pady=6)
        btn_frame.pack(fill=tk.X)
        for label, cmd in [("Export TXT", self._export_txt), ("Export JSON", self._export_json),
                            ("Export HTML", self._export_html), ("Clear", self._clear)]:
            tk.Button(btn_frame, text=label, bg=SURFACE, fg=TEXT, relief="flat",
                      font=FONT_MONO, padx=8, command=cmd).pack(side=tk.LEFT, padx=4)

        return frame

    # ── Callbacks ─────────────────────────────────────────────────────────────

    def _on_profile_change(self, *_):
        p = self._profile_var.get()
        self._profile_desc.configure(text=PROFILES[p]["description"])
        p_data = PROFILES[p]
        self._conc_var.set(p_data["concurrency"])
        self._active_var.set(p_data["active"])

    def _browse_out(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if path:
            self._out_var.set(path)

    def _toggle_scan(self):
        if self._scan_thread and self._scan_thread.is_alive():
            self._stop_event.set()
            self._scan_btn.configure(text="▶  START SCAN", bg=ACCENT)
            self._status_var.set("Stopping…")
        else:
            self._start_scan()

    def _start_scan(self):
        domain = self._domain_var.get().strip()
        if not domain:
            self._log_msg("[!] Please enter a target domain")
            return

        self._results.clear()
        self._tree.delete(*self._tree.get_children())
        self._alive_var.set("0")
        self._total_var.set("0")
        self._stop_event.clear()
        self._scan_btn.configure(text="■  STOP SCAN", bg=RED)
        self._status_var.set("Running…")

        cfg = SubliminalConfig.from_profile(self._profile_var.get(), domain=domain)
        cfg.concurrency = self._conc_var.get()
        cfg.active = self._active_var.get()
        cfg.bruteforce = self._bf_var.get()
        cfg.probe = self._probe_var.get()
        if self._out_var.get():
            cfg.output_txt = self._out_var.get()

        def _on_found(result: ProbeResult):
            self._result_queue.put(result)

        def _run():
            import asyncio as _asyncio
            _asyncio.run(self._run_scan_async(cfg, _on_found))

        self._scan_thread = threading.Thread(target=_run, daemon=True)
        self._scan_thread.start()

    async def _run_scan_async(self, cfg: SubliminalConfig, on_found):
        from subliminal.engine import run_scan
        import asyncio
        stop = asyncio.Event()

        def _watch():
            while not self._stop_event.is_set():
                import time; time.sleep(0.2)
            stop.set()

        t = threading.Thread(target=_watch, daemon=True)
        t.start()

        results = await run_scan(cfg, on_found=on_found, stop_event=stop)
        self._results = results
        self._result_queue.put(None)   # sentinel

    def _poll_results(self):
        try:
            while True:
                item = self._result_queue.get_nowait()
                if item is None:
                    # Scan finished
                    self._scan_btn.configure(text="▶  START SCAN", bg=ACCENT)
                    self._status_var.set(f"Done — {len(self._results)} alive")
                else:
                    self._results.append(item)
                    self._tree.insert("", tk.END, values=(
                        item.url,
                        item.status,
                        "🔒" if item.tls else "🔓",
                        item.title or "",
                    ))
                    self._alive_var.set(str(len(self._results)))
                    self._log_msg(f"[+] {item.url}  ({item.status})")
        except queue.Empty:
            pass
        finally:
            self.after(100, self._poll_results)

    def _log_msg(self, msg: str):
        self._log.configure(state=tk.NORMAL)
        self._log.insert(tk.END, msg + "\n")
        self._log.see(tk.END)
        self._log.configure(state=tk.DISABLED)

    def _clear(self):
        self._tree.delete(*self._tree.get_children())
        self._results.clear()
        self._alive_var.set("0")
        self._total_var.set("0")
        self._log.configure(state=tk.NORMAL)
        self._log.delete("1.0", tk.END)
        self._log.configure(state=tk.DISABLED)

    def _export_txt(self):
        if not self._results:
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
        if path:
            from subliminal.modules.report import save_txt
            save_txt(self._results, path)
            self._log_msg(f"[*] Saved TXT → {path}")

    def _export_json(self):
        if not self._results:
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if path:
            from subliminal.modules.report import save_json
            save_json(self._results, path)
            self._log_msg(f"[*] Saved JSON → {path}")

    def _export_html(self):
        if not self._results:
            return
        path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")])
        if path:
            from subliminal.modules.report import save_html
            domain = self._domain_var.get().strip()
            save_html(self._results, domain, path)
            self._log_msg(f"[*] Saved HTML → {path}")


def launch_gui() -> None:
    app = SubliminalGUI()
    app.mainloop()


if __name__ == "__main__":
    launch_gui()
