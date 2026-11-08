"""
CT-486 CCP - Cipher Lab: one window for encryption, decryption, attacks and results.
Run:  python3 gui.py      (needs only Python 3 with tkinter; no extra packages)
Uses: cipher.py (the cipher), attack.py (the attacks), benchmark.py (the measurements).
The whole window scrolls (mouse wheel / scrollbar / PageUp-PageDown); result boxes grow to fit their content.
"""
import os, queue, sys, threading, time
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, messagebox, filedialog
import cipher as cp
import attack as at
import benchmark as bm

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT = ("MEET ME AT THE OLD LIBRARY GATE BEFORE NOON AND BRING THE SECRET DOCUMENTS. "
           "IF ANYONE FOLLOWS YOU TAKE THE LONG ROAD HOME AND SEND WORD TO THE HARBOUR BEFORE DARK")

THEMES = {
    "light": dict(bg="#f3f4f8", card="#ffffff", panel="#f7f8fc", text="#1b2133", muted="#667085",
                  accent="#4f46e5", accent_h="#4338ca", accent_fg="#ffffff", border="#e3e6ee",
                  ok="#0f9d6a", bad="#d92d20", input="#ffffff", ghost="#eef0f6", ghost_h="#e1e4ef",
                  code="#eef1fb", sel="#c7d2fe"),
    "dark": dict(bg="#0e1424", card="#161e33", panel="#101729", text="#e6e9f2", muted="#8c97b2",
                 accent="#7c83ff", accent_h="#9399ff", accent_fg="#0e1424", border="#27314d",
                 ok="#34d399", bad="#f87171", input="#101729", ghost="#202a45", ghost_h="#2b3760",
                 code="#1c2745", sel="#33407a"),
}
T = dict(THEMES["light"])          # current palette (updated in place when the theme changes)


def pick_font(prefs, default):
    have = {f.lower() for f in tkfont.families()}
    return next((f for f in prefs if f.lower() in have), default)


# ------------------------------------------------------------------ matrix drawn with real brackets
class MatrixView(tk.Canvas):
    """An n x n matrix drawn on a canvas with proper [ ] brackets (no special font glyphs needed)."""

    def __init__(self, parent, fonts, bgkey="panel"):
        super().__init__(parent, highlightthickness=0, bd=0)
        self.fonts, self.bgkey, self.vals, self.n, self.caption = fonts, bgkey, None, 0, ""

    def set(self, vals, caption="", cols=None):
        self.vals = tuple(vals) if vals else None
        self.cols = cols or (cp._size(self.vals) if self.vals else 0)      # cols=1 draws a column vector
        self.n = (len(self.vals) // self.cols) if self.vals else 0         # number of rows
        self.caption = caption
        self.redraw()

    def redraw(self):
        self.delete("all")
        self.configure(bg=T[self.bgkey])
        mono, small = self.fonts["mono_big"], self.fonts["small"]
        cap_h = small.metrics("linespace") + 8 if self.caption else 0
        if not self.vals:
            w = max(150, small.measure(self.caption) + 12)
            self.configure(width=w, height=cap_h + 40)
            if self.caption:
                self.create_text(6, 4, anchor="nw", text=self.caption, font=small, fill=T["muted"])
            self.create_text(6, cap_h + 14, anchor="nw", text="(no valid matrix)", font=small, fill=T["bad"])
            return
        n, nc = self.n, self.cols
        cw = max(mono.measure("25"), mono.measure("00")) + (22 if nc > 1 else 16)
        rh = mono.metrics("linespace") + 10
        tick, th = 7, 2
        bw = nc * cw
        W = max(bw + 28, small.measure(self.caption) + 16)
        H = cap_h + n * rh + 16
        self.configure(width=W, height=H)
        if self.caption:
            self.create_text(6, 4, anchor="nw", text=self.caption, font=small, fill=T["muted"])
        x0 = (W - bw) // 2
        y0, y1 = cap_h + 6, cap_h + 10 + n * rh
        a = T["accent"]
        for x, d in ((x0 - 4, 1), (x0 + bw + 4, -1)):            # [ and ]
            self.create_line(x, y0, x, y1, fill=a, width=th)
            self.create_line(x, y0, x + d * tick, y0, fill=a, width=th)
            self.create_line(x, y1, x + d * tick, y1, fill=a, width=th)
        for i, v in enumerate(self.vals):
            r, c = divmod(i, nc)
            self.create_text(x0 + c * cw + cw // 2, cap_h + 8 + r * rh + rh // 2, text=str(v), font=mono, fill=T["text"])


# ------------------------------------------------------------------ read-only output pane (auto height)
class OutBox(tk.Text):
    """Styled read-only text that grows to fit its content, so the whole page scrolls instead of the box.
    Markup: '## ' heading, '> ' data line (monospace), lines starting ✓ / ✗ / '· ' are ok / bad / dim,
            '@@M caption|v1,v2,...;;caption|...' draws matrices with brackets."""

    def __init__(self, parent, fonts):
        super().__init__(parent, wrap="word", height=3, bd=0, highlightthickness=1, relief="flat",
                         padx=16, pady=12, cursor="arrow", takefocus=0, state="disabled")
        self.fonts, self.raw, self._lw, self._job, self.mviews = fonts, "", 0, None, []
        self.bind("<Configure>", self._on_conf)

    def style(self):
        f = self.fonts
        self.configure(bg=T["panel"], fg=T["text"], font=f["ui"], highlightbackground=T["border"],
                       highlightcolor=T["border"], selectbackground=T["sel"], selectforeground=T["text"],
                       insertbackground=T["panel"])
        self.tag_config("h", font=f["h2"], foreground=T["accent"], spacing1=14, spacing3=4)
        self.tag_config("ok", font=f["bold"], foreground=T["ok"], spacing1=6, spacing3=2)
        self.tag_config("bad", font=f["bold"], foreground=T["bad"], spacing1=6, spacing3=2)
        self.tag_config("dim", foreground=T["muted"], spacing3=2)
        self.tag_config("code", font=f["mono"], background=T["code"], lmargin1=10, lmargin2=10, rmargin=10,
                        spacing1=4, spacing3=4, wrap="char")
        self.tag_config("gap", font=f["tiny"])
        self.tag_config("op", font=f["h2"], foreground=T["muted"])
        self.tag_config("grid", font=f["mono"], background=T["code"], lmargin1=10, lmargin2=10, spacing1=0, spacing3=0, wrap="none")
        self.tag_config("mx", spacing1=4, spacing3=6, lmargin1=6)

    def set(self, text):
        self.raw = text
        self.style()
        self.config(state="normal")
        self.delete("1.0", "end")
        for mv in self.mviews:
            mv.destroy()
        self.mviews = []
        for line in text.split("\n"):
            if line == "":
                self.insert("end", "\n", "gap")
            elif line.startswith("## "):
                self.insert("end", line[3:] + "\n", "h")
            elif line.startswith("> "):
                self.insert("end", line[2:] + "\n", "code")
            elif line.startswith("@@M "):
                for part in line[4:].split(";;"):
                    if part.startswith("T:"):                       # operator / label between matrices
                        self.insert("end", " " + part[2:] + " ", "op"); continue
                    bits = part.split("|")
                    mv = MatrixView(self, self.fonts)
                    mv.set([int(x) for x in bits[1].split(",")], bits[0], int(bits[2]) if len(bits) > 2 else None)
                    self.window_create("end", window=mv, padx=2, align="center")
                    self.mviews.append(mv)
                self.insert("end", "\n", "mx")
            elif line.startswith("% "):
                self.insert("end", line[2:] + "\n", "grid")
            else:
                tag = "ok" if line.startswith("✓") else "bad" if line.startswith("✗") else "dim" if line.startswith("· ") else ""
                self.insert("end", line + "\n", tag)
        self.config(state="disabled")
        self.fit()

    def plain(self):
        out = []
        for line in self.raw.split("\n"):
            if line.startswith("@@M "):
                continue
            out.append(line[3:] if line.startswith("## ") else line[2:] if line[:2] in ("> ", "% ") else line)
        return "\n".join(out)

    def fit(self):
        self.update_idletasks()
        try:
            px = self.count("1.0", "end-1c", "ypixels")
            px = px[0] if px else 0
        except tk.TclError:
            return
        ls = max(1, self.fonts["ui"].metrics("linespace"))
        self.configure(height=max(3, int(px / ls) + 2))

    def _on_conf(self, e):
        if e.width != self._lw:
            self._lw = e.width
            if self._job:
                self.after_cancel(self._job)
            self._job = self.after(60, self.fit)


def mxs(*items):
    """Markup line of matrices: (caption, flat_tuple) = square matrix, (caption, tuple, 1) = column vector,
    a plain string = an operator such as '×' or '='."""
    out = []
    for it in items:
        if isinstance(it, str): out.append("T:" + it)
        else: out.append(f"{it[0]}|{','.join(str(x) for x in it[1])}" + (f"|{it[2]}" if len(it) > 2 else ""))
    return "@@M " + ";;".join(out)


def _rail_rows(n, rails):
    """Rail (0-based row) of each of n positions in the zig-zag."""
    rows, r, d = [], 0, 1
    for _ in range(n):
        rows.append(r)
        if r == 0: d = 1
        elif r == rails - 1: d = -1
        r += d
    return rows


def rail_grid(text_by_pos, rails, max_cols=40):
    """Zig-zag diagram: text_by_pos[i] is the letter written in column i. Returns markup lines ('% ...')."""
    n = len(text_by_pos); rows = _rail_rows(n, rails); shown = min(n, max_cols)
    lines = [f"% Rail {r + 1:<2} " + " ".join(text_by_pos[i] if rows[i] == r else "·" for i in range(shown)) for r in range(rails)]
    if n > shown: lines.append(f"· (first {shown} of {n} columns shown)")
    return "\n".join(lines)


def hill_block_lines(text, k, max_blocks=10, label="K"):
    """One line per block:  K × [block] = [K·block] ≡ [cipher block] (mod 26), drawn with matrices."""
    n = cp._size(k); nb = len(text) // n; out = []
    for b in range(min(nb, max_blocks)):
        blk = text[b * n:(b + 1) * n]; v = [ord(c) - 65 for c in blk]
        raw = [sum(k[r * n + c] * v[c] for c in range(n)) for r in range(n)]
        res = [x % 26 for x in raw]
        out.append(mxs((label, k), "×", (f"p = {blk}", v, 1), "=", (f"{label}·p", raw, 1), "≡ mod 26 →",
                       ("c = " + "".join(chr(x + 65) for x in res), res, 1)))
    if nb > max_blocks: out.append(f"· (first {max_blocks} of {nb} blocks shown)")
    if len(text) % n: out.append(f"· The last {len(text) % n} letter(s) do not fill a block and are left unchanged.")
    return "\n".join(out)


# ------------------------------------------------------------------ background (pure) report builder
def attack_report(p, h, v, r, mode, m_auto, m_manual):
    ct = cp.encrypt(p, h, v, r)
    n = cp.hill_size(h)
    key = cp.hill_key(h)
    need = at.min_known_letters(n, len(v))
    L = ["## What the attacker sees",
         f"> {ct[:160]}{'…' if len(ct) > 160 else ''}",
         f"· Ciphertext only ({len(ct)} letters). The attack code is never given the Hill matrix, its size, the rails or the Vigenère key."]
    if mode in ("kpa", "both"):
        m = min(need, len(p)) if m_auto else max(4, min(m_manual, len(p)))
        t0 = time.perf_counter(); res = at.known_plaintext_attack(ct, p[:m]); ms = 1e3 * (time.perf_counter() - t0)
        L += ["", f"## Known-plaintext attack  (attacker knows the first {m} plaintext letters)",
              f"> known: {p[:m][:60]}{'…' if m > 60 else ''}"]
        if res:
            r2, k2, H, pt = res
            n2 = cp._size(H)
            L += [f"> Hill size found:   {n2}×{n2}   (real: {n}×{n})",
                  f"> Rails found:       {r2}   (real: {r})",
                  f"> Vigenère key:      {k2}   (real: {cp.clean(v)})",
                  f"> Time:              {ms:.2f} ms",
                  mxs(("Recovered matrix H", H), ("Real matrix K", key)),
                  f"> Recovered text:    {pt[:100]}{'…' if len(pt) > 100 else ''}",
                  "✓ FULL PLAINTEXT RECOVERED: the cipher is broken." if pt == p else "✗ Recovered text differs from the message.",
                  *([] if pt == p else ["· Too little known text: a wrong guess fitted the few known letters by chance. Try more known letters."])]
        else:
            L += [f"✗ Attack FAILED with {m} known letters ({ms:.0f} ms).",
                  f"· For a {n}×{n} Hill matrix and a {len(v)}-letter key, about {need} known letters are needed (you gave {m}).",
                  *([f"· Your message has only {len(p)} letters, so it cannot supply {need}: type a longer message."] if len(p) < need else []),
                  "· Very repetitive known text (AAAA…) also fails: its blocks give no independent equations."]
    if mode in ("freq", "both"):
        ic = at.index_of_coincidence(ct)
        t0 = time.perf_counter(); r2, k2, pt = at.frequency_attack(ct); ms = 1e3 * (time.perf_counter() - t0)
        acc = 100 * sum(a == b for a, b in zip(pt, p)) / len(p)
        ct2 = cp.encrypt_2stage(p, v, r); r3, k3, pt3 = at.frequency_attack(ct2)
        acc3 = 100 * sum(a == b for a, b in zip(pt3, p)) / len(p)
        L += ["", "## Frequency attack  (ciphertext only: tries rails, Index of Coincidence, chi-squared)",
              f"> Ciphertext IC = {ic:.4f}   (English 0.066 · random 0.038)",
              f"> Best guess: rails {r2}, key {k2}   ({ms:.0f} ms)",
              f"> Letters correct: {acc:.1f}%",
              "✓ Frequency attack SUCCEEDED." if pt == p else "✗ Frequency attack FAILED: the Hill stage destroyed the letter statistics.",
              "", "## Comparison: same text WITHOUT the Hill stage (Vigenère + Rail Fence only)",
              f"> Letters correct: {acc3:.1f}%",
              "✓ That weaker cipher IS broken by frequency analysis." if pt3 == p else
              "✗ Not broken either (text too short? frequency analysis needs a few hundred letters)."]
    return "\n".join(L)


# ------------------------------------------------------------------ application
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cipher Lab · Hill + Vigenère + Rail Fence (CT-486)")
        self.geometry("1120x840"); self.minsize(900, 600)
        if sys.platform == "win32":
            try:
                import ctypes; ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except Exception:
                pass
        ui = pick_font(["Segoe UI", "SF Pro Text", "Helvetica Neue", "Inter", "Ubuntu", "Noto Sans", "DejaVu Sans"], "TkDefaultFont")
        mono = pick_font(["Cascadia Mono", "Consolas", "SF Mono", "Menlo", "JetBrains Mono", "DejaVu Sans Mono", "Liberation Mono"], "TkFixedFont")
        self.fonts = dict(
            ui=tkfont.Font(family=ui, size=10), bold=tkfont.Font(family=ui, size=10, weight="bold"),
            h2=tkfont.Font(family=ui, size=12, weight="bold"), title=tkfont.Font(family=ui, size=22, weight="bold"),
            small=tkfont.Font(family=ui, size=9), tiny=tkfont.Font(family=ui, size=3),
            mono=tkfont.Font(family=mono, size=11), mono_big=tkfont.Font(family=mono, size=13, weight="bold"),
            tab=tkfont.Font(family=ui, size=11, weight="bold"))
        self.theme = "light"; self.last_ct = ""; self.tkw = []; self.active = 0
        self.km_auto = tk.BooleanVar(value=True)
        self.style = ttk.Style(self)
        try: self.style.theme_use("clam")
        except tk.TclError: pass
        self.build_page()
        self.apply_theme()
        self.bind("<Control-Return>", lambda e: self.actions[self.active]())
        self.refresh()

    # ---------------- helpers ----------------
    def reg(self, w, **opts):
        self.tkw.append((w, opts)); return w

    def card(self, parent, **pack):
        outer = self.reg(tk.Frame(parent), bg="border")
        inner = ttk.Frame(outer, style="Card.TFrame", padding=18)
        inner.pack(fill="both", expand=True, padx=1, pady=1)
        outer.pack(**pack)
        return inner

    def apply_theme(self):
        T.clear(); T.update(THEMES[self.theme])
        s, f = self.style, self.fonts
        s.configure(".", background=T["bg"], foreground=T["text"], font=f["ui"], bordercolor=T["border"],
                    lightcolor=T["card"], darkcolor=T["card"], troughcolor=T["ghost"], focuscolor=T["card"])
        s.configure("TFrame", background=T["bg"]); s.configure("Card.TFrame", background=T["card"])
        s.configure("TLabel", background=T["bg"], foreground=T["text"])
        s.configure("Card.TLabel", background=T["card"], foreground=T["text"])
        s.configure("Title.TLabel", background=T["bg"], font=f["title"], foreground=T["text"])
        s.configure("Sub.TLabel", background=T["bg"], foreground=T["muted"])
        s.configure("Muted.TLabel", background=T["card"], foreground=T["muted"], font=f["small"])
        s.configure("Field.TLabel", background=T["card"], foreground=T["muted"], font=f["bold"])
        s.configure("H2.TLabel", background=T["card"], foreground=T["text"], font=f["h2"])
        s.configure("Ok.TLabel", background=T["card"], foreground=T["ok"], font=f["bold"])
        s.configure("Bad.TLabel", background=T["card"], foreground=T["bad"], font=f["bold"])
        for name in ("TEntry", "TSpinbox", "TCombobox"):
            s.configure(name, fieldbackground=T["input"], background=T["input"], foreground=T["text"], insertcolor=T["text"],
                        bordercolor=T["border"], lightcolor=T["input"], darkcolor=T["input"], arrowcolor=T["muted"],
                        padding=(8, 6), selectbackground=T["sel"], selectforeground=T["text"])
            s.map(name, bordercolor=[("focus", T["accent"])], lightcolor=[("focus", T["accent"])],
                  darkcolor=[("focus", T["accent"])], fieldbackground=[("readonly", T["input"]), ("disabled", T["ghost"])],
                  foreground=[("readonly", T["text"]), ("disabled", T["muted"])])
        self.option_add("*TCombobox*Listbox.background", T["input"]); self.option_add("*TCombobox*Listbox.foreground", T["text"])
        self.option_add("*TCombobox*Listbox.selectBackground", T["accent"]); self.option_add("*TCombobox*Listbox.selectForeground", T["accent_fg"])
        s.configure("Accent.TButton", background=T["accent"], foreground=T["accent_fg"], font=f["bold"], padding=(18, 8),
                    borderwidth=0, relief="flat", bordercolor=T["accent"], lightcolor=T["accent"], darkcolor=T["accent"])
        s.map("Accent.TButton", background=[("active", T["accent_h"]), ("pressed", T["accent_h"])],
              bordercolor=[("active", T["accent_h"])], lightcolor=[("active", T["accent_h"])], darkcolor=[("active", T["accent_h"])])
        s.configure("Ghost.TButton", background=T["ghost"], foreground=T["text"], padding=(14, 8), borderwidth=0, relief="flat",
                    bordercolor=T["ghost"], lightcolor=T["ghost"], darkcolor=T["ghost"])
        s.map("Ghost.TButton", background=[("active", T["ghost_h"])], bordercolor=[("active", T["ghost_h"])],
              lightcolor=[("active", T["ghost_h"])], darkcolor=[("active", T["ghost_h"])])
        for nm in ("Card.TRadiobutton", "Card.TCheckbutton"):
            s.configure(nm, background=T["card"], foreground=T["text"], indicatorbackground=T["input"],
                        indicatorforeground=T["accent"], padding=(2, 4))
            s.map(nm, background=[("active", T["card"])], indicatorbackground=[("selected", T["accent"])],
                  indicatorforeground=[("selected", T["accent_fg"])])
        s.layout("Vertical.TScrollbar", [("Vertical.Scrollbar.trough", {"sticky": "ns", "children": [
            ("Vertical.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})]})])
        s.configure("Vertical.TScrollbar", background=T["border"], troughcolor=T["bg"], borderwidth=0, relief="flat",
                    bordercolor=T["bg"], lightcolor=T["border"], darkcolor=T["border"], width=10)
        s.map("Vertical.TScrollbar", background=[("active", T["muted"])])
        self.configure(bg=T["bg"])
        for w, opts in self.tkw:
            try: w.configure(**{k: T[v] for k, v in opts.items()})
            except tk.TclError: pass
        for t in self.texts:
            t.configure(bg=T["input"], fg=T["text"], insertbackground=T["text"], highlightbackground=T["border"],
                        highlightcolor=T["accent"], selectbackground=T["sel"], selectforeground=T["text"])
        for o in self.outs:
            o.set(o.raw)
        self.preview.redraw(); self.paint_tabs()
        self.theme_btn.configure(text="Dark mode" if self.theme == "light" else "Light mode")

    def toggle_theme(self):
        self.theme = "dark" if self.theme == "light" else "light"; self.apply_theme()

    # ---------------- page (the whole window scrolls) ----------------
    def build_page(self):
        self.texts, self.outs = [], []
        wrap = ttk.Frame(self); wrap.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(wrap, highlightthickness=0, bd=0, yscrollincrement=24); self.reg(self.canvas, bg="bg")
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y"); self.canvas.pack(side="left", fill="both", expand=True)
        self.page = ttk.Frame(self.canvas, padding=(28, 22, 28, 28))
        win = self.canvas.create_window((0, 0), window=self.page, anchor="nw")
        self.page.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(win, width=e.width))
        self.bind_all("<MouseWheel>", self.on_wheel); self.bind_all("<Button-4>", self.on_wheel); self.bind_all("<Button-5>", self.on_wheel)
        self.bind_all("<Prior>", lambda e: self.canvas.yview_scroll(-1, "pages")); self.bind_all("<Next>", lambda e: self.canvas.yview_scroll(1, "pages"))

        head = ttk.Frame(self.page); head.pack(fill="x")
        left = ttk.Frame(head); left.pack(side="left")
        ttk.Label(left, text="Cipher Lab", style="Title.TLabel").pack(anchor="w")
        ttk.Label(left, text="Hill (n×n)  →  Vigenère  →  Rail Fence      ·      encrypt, decrypt and attack your own text",
                  style="Sub.TLabel").pack(anchor="w", pady=(2, 0))
        self.theme_btn = ttk.Button(head, text="Dark mode", style="Ghost.TButton", command=self.toggle_theme)
        self.theme_btn.pack(side="right")
        self.build_inputs(); self.build_tabs()

    def on_wheel(self, e):
        w = self.winfo_containing(e.x_root, e.y_root)
        if isinstance(w, tk.Text) and not isinstance(w, OutBox) and w.yview() != (0.0, 1.0):
            return                                              # a long message box scrolls itself
        if self.canvas.yview() == (0.0, 1.0):
            return
        if e.num == 4: d = -1
        elif e.num == 5: d = 1
        else: d = -1 if e.delta > 0 else 1
        self.canvas.yview_scroll(d * 3, "units")

    def autotext(self, parent, height=3):
        t = tk.Text(parent, wrap="word", height=height, bd=0, relief="flat", highlightthickness=1, padx=10, pady=8,
                    font=self.fonts["ui"], undo=True)
        self.texts.append(t); return t

    # ---------------- shared inputs ----------------
    def build_inputs(self):
        c = self.card(self.page, fill="x", pady=(18, 0))
        ttk.Label(c, text="Your message and keys", style="H2.TLabel").pack(anchor="w")
        ttk.Label(c, text="Everything below uses these values. Only the letters A–Z of the message are used.", style="Muted.TLabel").pack(anchor="w", pady=(0, 8))
        self.msg = self.autotext(c, 4); self.msg.pack(fill="x")
        self.msg.insert("1.0", DEFAULT); self.msg.bind("<KeyRelease>", lambda e: self.refresh())
        grid = ttk.Frame(c, style="Card.TFrame"); grid.pack(fill="x", pady=(14, 0))
        fields = ttk.Frame(grid, style="Card.TFrame"); fields.pack(side="left", fill="x", expand=True)
        self.hk, self.vk, self.rl = tk.StringVar(value="GYBNQKURP"), tk.StringVar(value="SECURITYKEY"), tk.StringVar(value="4")
        self.hs = tk.StringVar(value="3×3")

        def field(col, label, widget):
            ttk.Label(fields, text=label, style="Field.TLabel").grid(row=0, column=col, sticky="w", padx=(0, 12))
            widget.grid(row=1, column=col, sticky="w", padx=(0, 12), pady=(3, 0))
        field(0, "Hill key  (n×n letters)", ttk.Entry(fields, textvariable=self.hk, width=20, font=self.fonts["mono"]))
        field(1, "Vigenère key  (10+ letters)", ttk.Entry(fields, textvariable=self.vk, width=22, font=self.fonts["mono"]))
        field(2, "Rails", ttk.Spinbox(fields, from_=2, to=30, textvariable=self.rl, width=5, command=self.refresh))
        cb = ttk.Combobox(fields, textvariable=self.hs, values=[f"{n}×{n}" for n in range(2, 9)], width=6, state="readonly")
        field(3, "Matrix size", cb); cb.bind("<<ComboboxSelected>>", self.size_changed)
        for v in (self.hk, self.vk, self.rl): v.trace_add("write", lambda *a: self.refresh())
        btns = ttk.Frame(fields, style="Card.TFrame"); btns.grid(row=2, column=0, columnspan=4, sticky="w", pady=(14, 0))
        ttk.Button(btns, text="Random keys", style="Ghost.TButton", command=self.random_keys).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="Load sample text", style="Ghost.TButton", command=self.load_sample).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="Clear message", style="Ghost.TButton", command=lambda: (self.msg.delete("1.0", "end"), self.refresh())).pack(side="left")
        self.preview = MatrixView(grid, self.fonts, bgkey="card"); self.preview.pack(side="right", padx=(20, 0))
        self.status = ttk.Label(c, text="", style="Ok.TLabel"); self.status.pack(anchor="w", pady=(12, 0))

    def inputs(self):
        """Validate and return (plaintext, hill_key, vigenere_key, rails) or None."""
        try:
            p = cp.clean(self.msg.get("1.0", "end"))
            if not p: raise ValueError("Type a message (only letters A–Z are used).")
            k = cp.hill_key_checked(self.hk.get()); v = cp.clean(self.vk.get())
            try: r = int(self.rl.get())
            except ValueError: raise ValueError("Rails must be a whole number.")
            cp._check(v, r, len(p))
        except Exception as e:
            self.status.config(text=f"⚠  {e}", style="Bad.TLabel"); return None
        n = cp._size(k)
        self.status.config(text=f"✓  Ready: {len(p)} letters · Hill {n}×{n} · Vigenère key length {len(v)} · {r} rails", style="Ok.TLabel")
        return p, self.hk.get(), v, r

    def refresh(self):
        self.inputs()
        try:
            k = cp.hill_key(self.hk.get()); n = cp._size(k)
            self.preview.set(k, f"Hill matrix K  ·  det = {cp.hill_det(k)}"); self.hs.set(f"{n}×{n}")
        except ValueError:
            self.preview.set(None, "Hill matrix K")

    def size_changed(self, _=None):
        self.hk.set(bm.rand_hill(int(self.hs.get()[0])))

    def random_keys(self):
        h, v, r = bm.rand_keys(int(self.hs.get()[0])); self.hk.set(h); self.vk.set(v); self.rl.set(str(r))

    def load_sample(self):
        try: t = open(os.path.join(HERE, "sample_text.txt"), encoding="utf8").read()[:600]
        except OSError: return messagebox.showinfo("Sample", "sample_text.txt not found next to gui.py")
        self.msg.delete("1.0", "end"); self.msg.insert("1.0", t); self.refresh()

    # ---------------- tabs ----------------
    def build_tabs(self):
        bar = ttk.Frame(self.page); bar.pack(fill="x", pady=(22, 0))
        self.tabs = []
        for i, name in enumerate(["Encrypt", "Decrypt", "Attack", "Results"]):
            f = self.reg(tk.Frame(bar), bg="bg"); f.pack(side="left", padx=(0, 6))
            lab = tk.Label(f, text=name, font=self.fonts["tab"], padx=22, pady=9, cursor="hand2")
            ind = tk.Frame(f, height=3); lab.pack(); ind.pack(fill="x")
            lab.bind("<Button-1>", lambda e, i=i: self.select(i))
            self.tabs.append((f, lab, ind))
        c = self.card(self.page, fill="x")
        self.panels = panels = [ttk.Frame(c, style="Card.TFrame") for _ in range(4)]

        def mk(p):
            o = OutBox(p, self.fonts); self.outs.append(o); return o
        # Encrypt
        bar = ttk.Frame(panels[0], style="Card.TFrame"); bar.pack(fill="x")
        ttk.Button(bar, text="Encrypt  ▶", style="Accent.TButton", command=self.do_encrypt).pack(side="left")
        ttk.Button(bar, text="Copy ciphertext", style="Ghost.TButton", command=self.copy_ct).pack(side="left", padx=8)
        ttk.Label(bar, text="Shows the text after each of the three stages   (Ctrl+Enter = run)", style="Muted.TLabel").pack(side="left", padx=8)
        self.o_enc = mk(panels[0]); self.o_enc.pack(fill="x", pady=(12, 0))
        # Decrypt
        ttk.Label(panels[1], text="Ciphertext to decrypt  (filled automatically after Encrypt; paste another if you like)", style="Field.TLabel").pack(anchor="w")
        self.ct_box = self.autotext(panels[1], 3); self.ct_box.pack(fill="x", pady=(4, 10))
        bar = ttk.Frame(panels[1], style="Card.TFrame"); bar.pack(fill="x")
        ttk.Button(bar, text="Decrypt  ▶", style="Accent.TButton", command=self.do_decrypt).pack(side="left")
        ttk.Button(bar, text="Use last ciphertext", style="Ghost.TButton", command=self.use_last).pack(side="left", padx=8)
        ttk.Label(bar, text="Uses the keys entered at the top. Wrong keys give garbage.", style="Muted.TLabel").pack(side="left", padx=8)
        self.o_dec = mk(panels[1]); self.o_dec.pack(fill="x", pady=(12, 0))
        # Attack
        ttk.Label(panels[2], text="The attacker gets only the ciphertext (plus some known plaintext for the first attack). "
                  "The keys, the rail count and even the matrix size are never given to the attack code.",
                  style="Muted.TLabel", wraplength=900, justify="left").pack(anchor="w")
        bar = ttk.Frame(panels[2], style="Card.TFrame"); bar.pack(fill="x", pady=(8, 0))
        self.amode, self.km = tk.StringVar(value="kpa"), tk.StringVar(value="60")
        for t, v in [("Known-plaintext attack", "kpa"), ("Frequency attack", "freq"), ("Both", "both")]:
            ttk.Radiobutton(bar, text=t, variable=self.amode, value=v, style="Card.TRadiobutton").pack(side="left", padx=(0, 14))
        bar2 = ttk.Frame(panels[2], style="Card.TFrame"); bar2.pack(fill="x", pady=(6, 0))
        ttk.Label(bar2, text="Known letters:", style="Card.TLabel").pack(side="left")
        self.km_spin = ttk.Spinbox(bar2, from_=4, to=2000, textvariable=self.km, width=6); self.km_spin.pack(side="left", padx=(6, 10))
        ttk.Checkbutton(bar2, text="Auto (enough for my keys)", variable=self.km_auto, style="Card.TCheckbutton", command=self.km_toggle).pack(side="left", padx=(0, 14))
        ttk.Button(bar2, text="Run attack  ▶", style="Accent.TButton", command=self.do_attack).pack(side="left")
        self.km_spin.state(["disabled"])
        self.o_atk = mk(panels[2]); self.o_atk.pack(fill="x", pady=(12, 0))
        # Results
        ttk.Label(panels[3], text="Measures efficiency and attack success on YOUR text with random keys of your matrix size. "
                  "Longer text = more reliable frequency results.", style="Muted.TLabel", wraplength=900, justify="left").pack(anchor="w")
        bar = ttk.Frame(panels[3], style="Card.TFrame"); bar.pack(fill="x", pady=(8, 0))
        self.trials = tk.StringVar(value="10")
        ttk.Label(bar, text="Trials per row:", style="Card.TLabel").pack(side="left")
        ttk.Spinbox(bar, from_=3, to=100, textvariable=self.trials, width=5).pack(side="left", padx=(6, 12))
        ttk.Button(bar, text="Run analysis  ▶", style="Accent.TButton", command=self.do_results).pack(side="left")
        ttk.Button(bar, text="Save report…", style="Ghost.TButton", command=self.save_report).pack(side="left", padx=8)
        self.o_res = mk(panels[3]); self.o_res.pack(fill="x", pady=(12, 0))
        self.actions = [self.do_encrypt, self.do_decrypt, self.do_attack, self.do_results]
        for o, t in [(self.o_enc, "Press “Encrypt ▶” to see each stage."), (self.o_dec, "Press “Decrypt ▶” to undo the stages in reverse."),
                     (self.o_atk, "Choose an attack and press “Run attack ▶”."), (self.o_res, "Press “Run analysis ▶”.")]:
            o.set("· " + t)
        self.select(0)

    def select(self, i):
        self.active = i
        for j, p in enumerate(self.panels):
            p.pack_forget()
            if j == i: p.pack(fill="x")
        self.paint_tabs()
        self.after(30, lambda: [o.fit() for o in self.outs])

    def paint_tabs(self):
        for i, (f, lab, ind) in enumerate(self.tabs):
            on = i == self.active
            lab.configure(bg=T["bg"], fg=T["accent"] if on else T["muted"]); ind.configure(bg=T["accent"] if on else T["bg"])

    def km_toggle(self):
        self.km_spin.state(["disabled"] if self.km_auto.get() else ["!disabled"])

    # ---------------- actions ----------------
    def do_encrypt(self):
        i = self.inputs()
        if not i: self.select(0); return self.o_enc.set("✗ Fix the input at the top first.")
        p, h, v, r = i; k = cp.hill_key(h); n = cp._size(k)
        s1 = cp.hill_encrypt(p, k); s2 = cp.vigenere_encrypt(s1, v); s3 = cp.rail_fence_encrypt(s2, r)
        self.last_ct = s3; self.ct_box.delete("1.0", "end"); self.ct_box.insert("1.0", s3)
        self.o_enc.set(
            f"## Plaintext  (cleaned to A–Z, {len(p)} letters)\n> {p}\n\n"
            f"## Stage 1 · Hill  {n}×{n}\n{mxs(('Key matrix K', k), ('Inverse K⁻¹ (used to decrypt)', cp._inv(k)))}\n"
            f"· Each block of {n} letters (A=0…Z=25) is multiplied by K and reduced mod 26. Every block, one per line:\n"
            f"{hill_block_lines(p, k)}\n> {s1}\n\n"
            f"## Stage 2 · Vigenère  key {v}\n· Each letter is shifted by the repeating key letter\n> {s2}\n\n"
            f"## Stage 3 · Rail Fence  {r} rails\n· Write the letters in a zig-zag down and up the rails, then read rail 1, rail 2, … in order.\n"
            f"{rail_grid(s2, r)}\n\n· Output of Stage 3 (this is the ciphertext):\n> {s3}\n\n"
            f"✓ CIPHERTEXT = {s3}")

    def copy_ct(self):
        if self.last_ct: self.clipboard_clear(); self.clipboard_append(self.last_ct)

    def use_last(self):
        self.ct_box.delete("1.0", "end"); self.ct_box.insert("1.0", self.last_ct)

    def do_decrypt(self):
        i = self.inputs()
        if not i: return self.o_dec.set("✗ Fix the input at the top first.")
        p, h, v, r = i; ct = cp.clean(self.ct_box.get("1.0", "end"))
        if not ct: return self.o_dec.set("✗ Enter a ciphertext (or press Encrypt first).")
        k = cp.hill_key(h); n = cp._size(k); u = cp.rail_fence_decrypt(ct, r); w = cp.vigenere_decrypt(u, v); x = cp.hill_decrypt(w, k)
        ki = cp._inv(k)
        order = cp.rail_order(len(ct), r)               # ciphertext letter j belongs to column order[j]
        by_col = [""] * len(ct)
        for j, col in enumerate(order): by_col[col] = ct[j]
        self.o_dec.set(
            f"## Ciphertext  ({len(ct)} letters)\n> {ct}\n\n"
            f"## Undo Stage 3 · Rail Fence  ({r} rails)\n· The ciphertext is cut into rail 1, rail 2, … and the letters are put back into the zig-zag; reading the columns gives the text.\n"
            f"{rail_grid(by_col, r)}\n\n· Columns read left to right:\n> {u}\n\n"
            f"## Undo Stage 2 · Vigenère  (subtract key {v})\n> {w}\n\n"
            f"## Undo Stage 1 · Hill  ({n}×{n})\n{mxs(('Inverse matrix K⁻¹', ki), ('Original key K', k))}\n"
            f"· Each block is multiplied by K⁻¹ mod 26. Every block, one per line:\n{hill_block_lines(w, ki, label="K⁻¹")}\n> {x}\n\n"
            + ("✓ Recovered text matches the message at the top." if x == p else "· Differs from the message at the top (wrong keys or a different ciphertext)."))

    def do_attack(self):
        i = self.inputs()
        if not i: return self.o_atk.set("✗ Fix the input at the top first.")
        p, h, v, r = i
        try: m = int(self.km.get())
        except ValueError: m = 60
        mode, auto = self.amode.get(), self.km_auto.get()
        self.bg(lambda: attack_report(p, h, v, r, mode, auto, m), self.o_atk, "· Running the attack… (larger matrices take a moment)")

    def do_results(self):
        i = self.inputs()
        if not i: return self.o_res.set("✗ Fix the input at the top first.")
        try: n = max(3, min(int(self.trials.get()), 100))
        except ValueError: n = 10
        p, h, v, r = i
        self.bg(lambda: bm.full_report(p, h, v, r, n), self.o_res, f"· Running analysis on your {len(p)} letters ({n} trials per row). Please wait…")

    def bg(self, fn, widget, msg):
        widget.set(msg); q = queue.Queue()

        def work():
            try: q.put(("ok", fn()))
            except Exception as e: q.put(("err", str(e)))
        threading.Thread(target=work, daemon=True).start()

        def poll():
            try: k, val = q.get_nowait()
            except queue.Empty: return self.after(150, poll)
            widget.set(val if k == "ok" else "✗ Error: " + val)
        poll()

    def save_report(self):
        txt = self.o_res.plain().strip()
        f = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="results_report.txt")
        if f: open(f, "w", encoding="utf8").write(txt)


if __name__ == "__main__":
    App().mainloop()
