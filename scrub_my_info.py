"""scrub_my_info: redact secrets & personal info from text before feeding it to an AI.

GUI:        python scrub_my_info.py
Self-test:  python scrub_my_info.py --test
"""
import base64
import re
import sys
from collections import Counter
from pathlib import Path

VERSION = "0.1"


def luhn(s):
    d = [int(c) for c in s if c.isdigit()]
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, n in enumerate(reversed(d)):
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def b64_private_key(s):
    try:
        return b"PRIVATE KEY" in base64.b64decode(s + "=" * (-len(s) % 4))
    except ValueError:
        return False


# keys whose value is a secret when key and value are glued with no separator (e.g. "radius_secretXXX" in config dumps)
GLUED_KEYS = r"password|passwd|secret|token|api[_-]?key|userkey|privkey|private[_-]?key|[_-]key|community|psk|oinkcode|etprocode"

# (label, regex, group to replace, validator). Order matters: secrets first, so e.g. a URL password
# is caught before the IP/email rules chew up the rest of the URL.
# No \b on IP/MAC/UUID/key rules on purpose: config dumps glue values to keys ("ipaddr192.168.1.1"), which kills \b.
RULES = [
    ("PRIVATE_KEY", r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----", 0, None),
    ("PRIVATE_KEY", r"LS0tLS1CRUdJTi[A-Za-z0-9+/]+={0,2}", 0, b64_private_key),  # base64-wrapped PEM; public certs are kept
    ("PASSWORD_HASH", r"\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}|\$[56]\$[^$\s]+\$[./A-Za-z0-9]{40,}", 0, None),  # bcrypt / sha-crypt
    ("API_KEY", r"[\w~.-]{3}\dQ~[\w~.-]{31,34}", 0, None),  # Azure AD client secret
    ("JWT", r"\beyJ[\w-]+\.eyJ[\w-]+\.[\w-]+", 0, None),
    ("API_KEY", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", 0, None),  # AWS
    ("API_KEY", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_\w{60,})", 0, None),  # GitHub
    ("API_KEY", r"\bxox[abprs]-[\w-]{10,}", 0, None),  # Slack
    ("API_KEY", r"\bsk-[\w-]{20,}", 0, None),  # OpenAI / Anthropic
    ("API_KEY", r"\bAIza[\w-]{35}", 0, None),  # Google
    ("API_KEY", r"\b[sprk]k_(?:live|test)_[A-Za-z0-9]{16,}", 0, None),  # Stripe
    ("SECRET", r"(?i)\bbearer\s+([\w.~+/-]{16,}=*)", 1, None),
    ("SECRET", r"://[^\s:/@]+:([^\s@/]+)@", 1, None),  # password in URL / connection string
    ("SECRET", r"""(?i)(?<![\w.-])[\w.-]*(?:password|passwd|pwd|pass|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|credentials?)["']?\s*[:=]\s*["']?([^\s"',;]{3,})""", 1, None),
    # shortcut: glued form can't tell key from value, so "passwordencryptionX" over-redacts "encryptionX"; safer than leaking
    ("SECRET", rf"""(?im)^[ \t]*[\w.-]*?(?:{GLUED_KEYS})([^\s=:"'][^\s]{{2,}})[ \t]*$""", 1, None),
    ("PERSON", r"(?im)^[ \t]*(?:nome|cognome|nome e cognome|nominativo|referente|full[ _]?name|first[ _]?name|last[ _]?name|surname)[ \t]*(?::[ \t]*|\r?\n[ \t]*)([^\r\n]{2,60}?)[ \t]*$", 1, None),
    ("ORG", r"(?im)^[ \t]*(?:azienda|ragione sociale|società|company)[ \t]*(?::[ \t]*|\r?\n[ \t]*)([^\r\n]{2,60}?)[ \t]*$", 1, None),
    # shortcut: Italian street names only; add other formats if you need them
    ("ADDRESS", r"\b(?:[Vv]ia|[Vv]iale|[Pp]iazza(?:le)?|[Cc]orso|[Ll]argo|[Vv]icolo|[Ss]trada)\s+[A-ZÀ-Ý][\w'.]*(?:\s+[\w'.]+){0,4}?,?\s+\d{1,4}[a-zA-Z]?\b", 0, None),
    ("EMAIL", r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}\b", 0, None),
    ("IBAN", r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b", 0, None),
    ("CARD", r"\b\d(?:[ -]?\d){12,18}\b", 0, luhn),
    ("TAX_ID", r"\b[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z]\b", 0, None),  # Italian codice fiscale
    ("SSN", r"\b\d{3}-\d{2}-\d{4}\b", 0, None),
    ("IP", r"(?i)(?<![0-9a-f:])::ffff:(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]{1,4}:[0-9a-f]{1,4})(?![0-9a-f:])", 0, None),  # IPv4-mapped IPv6
    # a digit may precede ("dns_server1192.168.1.1"): leftmost match still wins for normal IPs, only "." is a hard stop
    ("IP", r"(?<!\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d|\.\d)", 0, None),
    ("IP", r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}(?![0-9A-Fa-f:])", 0, None),  # IPv6 full
    ("IP", r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){2,7}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?(?![0-9A-Fa-f:])", 0, None),  # IPv6 with ::
    ("MAC", r"(?<![:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f]|[:-][0-9A-Fa-f])", 0, None),
    ("ID", r"(?i)[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}(?![0-9a-f])", 0, None),  # UUIDs: tenant/subscription/object IDs
    ("PHONE", r"(?<![\w+])(?:\+|00)\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,4}){2,4}\b", 0, None),  # international
    ("PHONE", r"\b3\d{2}[\s.-]?\d{3}[\s.-]?\d{3,4}\b", 0, None),  # Italian mobile
    ("PHONE", r"(?<!\w)\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b", 0, None),  # US
    ("USER", r"(?i)(?:[A-Z]:\\Users\\|/home/|/Users/)([^\\/\s]+)", 1, None),  # username in paths
]
RULES = [(label, re.compile(rx), g, v) for label, rx, g, v in RULES]
PLACEHOLDER = re.compile(r"\[[A-Z_]+_\d+\]")


def redact(text, extra_terms=(), progress=None):
    """Return (redacted_text, {placeholder: original}). Same value -> same placeholder, so the AI can still follow references.
    progress(done, total) is called after each rule."""
    seen, mapping, counts = {}, {}, Counter()

    def tag(label, value):
        if (label, value) not in seen:
            counts[label] += 1
            ph = f"[{label}_{counts[label]}]"
            seen[(label, value)] = ph
            mapping[ph] = value
        return seen[(label, value)]

    # shortcut: regex can't spot names/companies, so the user lists them; upgrade to an NER model (spaCy/presidio) if that's not enough
    rules = RULES + [("TERM", re.compile(r"(?i)(?<!\w)" + re.escape(t) + r"(?!\w)"), 0, None) for t in extra_terms]
    for i, (label, rx, g, valid) in enumerate(rules, 1):
        def sub(m):
            value = m.group(g)
            if PLACEHOLDER.fullmatch(value) or (valid and not valid(value)):
                return m.group(0)
            s, e = m.start(g) - m.start(), m.end(g) - m.start()
            whole = m.group(0)
            return whole[:s] + tag(label, value.lower() if label == "TERM" else value) + whole[e:]
        text = rx.sub(sub, text)
        if progress:
            progress(i, len(rules))
    return text, mapping


def legend(mapping):
    """One '[IP_1]: 192.168.1.2' line per placeholder, sorted by type then number, so AI replies can be mapped back."""
    def key(ph):
        label, n = ph[1:-1].rsplit("_", 1)
        return label, int(n)
    def one_line(v):
        return v.replace("\r", "").replace("\n", "\\n")
    return "\n".join(f"{ph}: {one_line(mapping[ph])}" for ph in sorted(mapping, key=key))


def gui():
    import queue
    import threading
    import time
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext, ttk

    root = tk.Tk()
    root.title(f"scrub my info v{VERSION}")
    root.geometry("1500x760")
    state = {"path": None}

    bar = tk.Frame(root)
    bar.pack(fill="x", padx=6, pady=6)
    terms = tk.StringVar()
    panes = tk.PanedWindow(root, orient="horizontal", sashwidth=6)
    panes.pack(fill="both", expand=True, padx=6)

    def pane(title, width=80):
        f = tk.Frame(panes)
        tk.Label(f, text=title, anchor="w").pack(fill="x")
        t = scrolledtext.ScrolledText(f, wrap="word", undo=True, font=("Consolas", 10), width=width)
        t.pack(fill="both", expand=True)
        panes.add(f, stretch="always")
        return t

    inp = pane("input  (open a file or paste text)")
    out = pane("redacted output  (review before sending!)")
    legend_box = pane("legend  (has the real values: keep it local, never send it)", width=45)
    foot = tk.Frame(root)
    foot.pack(fill="x", padx=6, pady=(2, 6))
    prog = ttk.Progressbar(foot, mode="determinate", length=220)
    prog.pack(side="right")
    status = tk.Label(foot, anchor="w", text="open a file or paste text, then hit Redact")
    status.pack(side="left", fill="x", expand=True)

    def open_file():
        p = filedialog.askopenfilename(filetypes=[("Text", "*.txt *.log *.md *.csv *.json *.yaml *.yml *.env *.ini *.xml"), ("All", "*.*")])
        if not p:
            return
        state["path"] = Path(p)
        inp.delete("1.0", "end")
        inp.insert("1.0", state["path"].read_text(encoding="utf-8", errors="replace"))
        run()

    def run():
        if state.get("busy"):
            return
        state["busy"] = True
        buttons["Redact"].config(state="disabled")
        prog.config(value=0)
        status.config(text="redacting...")
        extra = [t.strip() for t in terms.get().split(",") if t.strip()]
        text = inp.get("1.0", "end-1c")
        q = queue.Queue()  # Tk isn't thread-safe: the worker only talks to the UI through this queue

        def step(i, n):
            q.put(("progress", i, n))
            time.sleep(0.005)  # regex holds the GIL; pause so the UI thread gets to repaint the bar

        def work():
            try:
                q.put(("done", *redact(text, extra, step)))
            except Exception as e:  # never leave the UI stuck in "busy"
                q.put(("error", e))

        def poll():
            try:
                while True:
                    msg = q.get_nowait()
                    if msg[0] == "progress":
                        prog.config(maximum=msg[2], value=msg[1])
                        continue
                    state["busy"] = False
                    buttons["Redact"].config(state="normal")
                    if msg[0] == "error":
                        status.config(text="redaction failed")
                        messagebox.showerror("redact failed", str(msg[1]))
                    else:
                        show(msg[1], msg[2])
                    return
            except queue.Empty:
                root.after(50, poll)

        threading.Thread(target=work, daemon=True).start()
        poll()

    def show(result, mapping):
        out.delete("1.0", "end")
        out.insert("1.0", result)
        legend_box.delete("1.0", "end")
        legend_box.insert("1.0", legend(mapping))
        by_label = Counter(ph[1:-1].rsplit("_", 1)[0] for ph in mapping)
        summary = ", ".join(f"{k}: {v}" for k, v in sorted(by_label.items())) or "nothing found"
        status.config(text=f"hidden {len(mapping)} unique values  ->  {summary}")

    def copy(widget, what):
        root.clipboard_clear()
        root.clipboard_append(widget.get("1.0", "end-1c"))
        status.config(text=f"{what} copied to clipboard")

    def save(widget, suffix, ext=None):
        p = state["path"]
        ext = ext or (p.suffix if p else ".txt")
        dest = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialdir=p.parent if p else None,
            initialfile=f"{p.stem if p else 'text'}_{suffix}{ext}",
        )
        if dest:
            Path(dest).write_text(widget.get("1.0", "end-1c"), encoding="utf-8")
            messagebox.showinfo("saved", dest)

    buttons = {}
    for label, cmd in [("Open file...", open_file), ("Redact", run),
                       ("Copy output", lambda: copy(out, "output")), ("Save as...", lambda: save(out, "redacted")),
                       ("Copy legend", lambda: copy(legend_box, "legend")), ("Save legend...", lambda: save(legend_box, "legend", ".txt"))]:
        buttons[label] = tk.Button(bar, text=label, command=cmd, padx=8)
        buttons[label].pack(side="left", padx=(0, 4))
    tk.Label(bar, text="  also hide (comma-separated names, companies...):").pack(side="left")
    entry = tk.Entry(bar, textvariable=terms)
    entry.pack(side="left", fill="x", expand=True)
    entry.bind("<Return>", lambda e: run())
    root.mainloop()


def selftest():
    sample = (
        "Contact mario.rossi@example.com or +39 345 678 9012, cell 347-1234567.\n"
        'password = hunter2\nconfig: {"api_key": "abc123xyz"}\nDB_PASS=topsecret\n'
        "db: postgres://admin:s3cr3t@10.0.0.5:5432/app\n"
        "keys AKIAIOSFODNN7EXAMPLE and sk-ant-abcdefghijklmnopqrstuvwxyz123\n"
        "Authorization: Bearer abcdefghijklmnop1234567890\n"
        "card 4111 1111 1111 1111, order no 1234 5678 9012 3457\n"
        "IBAN IT60 X054 2811 1010 0000 0123 456\nCF RSSMRA85T10A562S\n"
        "path C:\\Users\\mario\\Desktop\\file.txt\n"
        "again mario.rossi@example.com -- signed, Mario Rossi of ACME Srl. author: Luca\n"
    )
    out, mapping = redact(sample, ["Mario Rossi", "ACME Srl"])
    print(out)
    for leak in ["mario.rossi@", "345 678", "1234567", "hunter2", "abc123xyz", "topsecret", "s3cr3t", "10.0.0.5",
                 "AKIAIOSF", "sk-ant", "abcdefghijklmnop", "4111", "X054", "RSSMRA", "\\mario\\", "Mario Rossi", "ACME"]:
        assert leak not in out, f"leaked: {leak}"
    assert "1234 5678 9012 3457" in out, "non-luhn number should be kept"
    assert "author: Luca" in out, "'author' is not a secret key"
    assert out.count("[EMAIL_1]") == 2, "same value should reuse placeholder"
    assert mapping["[EMAIL_1]"] == "mario.rossi@example.com"
    leg = legend(mapping).splitlines()
    assert "[EMAIL_1]: mario.rossi@example.com" in leg and len(leg) == len(mapping)
    assert leg.index("[PHONE_1]: +39 345 678 9012") < leg.index("[PHONE_2]: 347-1234567"), "sorted by number"

    # config-dump style: keys and values glued, keys base64-wrapped (all values fake)
    key_b64 = base64.b64encode(b"-----BEGIN RSA PRIVATE KEY-----\nMIIfakefake\n-----END RSA PRIVATE KEY-----\n").decode()
    crt_b64 = base64.b64encode(b"-----BEGIN CERTIFICATE-----\nMIIpublic\n-----END CERTIFICATE-----\n").decode()
    dump = (
        "▶user\nnameadmin\nbcrypt-hash$2y$10$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ01234\n"
        "radius_secretmysecret1\nvarclientsharedsecretmysecret1\nvaruserspasswordQx7!pL9#zR2m\n"
        "rocommunityhunter3\npasswordTmV2ZXJHb25uYUdpdmU=\nusernameab12cd34-1111-2222-3333-444455556666\n"
        "ipaddr192.168.50.2\nsubnet24\nspoofmac02:00:5e:10:00:01\nfromfd00:1234:abcd::1000\n"
        f"prv{key_b64}\ncrt{crt_b64}\nsecret abc8Q~FAKEfakeFAKEfakeFAKEfakeFAKEfake12\n"
        "Nome\nMario Bianchi\nAzienda\nFoo Srl\nVia\nvia Garibaldi 12\nversion23.3\n"
        "dns_server1192.168.77.1\naddress::ffff:c0a8:0101\nmapped ::ffff:10.1.2.3\noid1.2.3.4.5\n"
    )
    out, mapping = redact(dump)
    print(out)
    for leak in ["$2y$10$abc", "mysecret1", "Qx7!pL9", "hunter3", "TmV2ZXJH", "ab12cd34", "192.168.50.2",
                 "02:00:5e", "fd00:1234", key_b64[:30], "abc8Q~", "Mario Bianchi", "Foo Srl", "Garibaldi 12",
                 "192.168.77.1", "c0a8:0101", "10.1.2.3"]:
        assert leak not in out, f"leaked: {leak}"
    assert crt_b64 in out, "public cert should be kept"
    for keep in ["nameadmin", "radius_secret[", "subnet24", "version23.3", "dns_server1[IP_", "address[IP_", "oid1.2.3.4.5"]:
        assert keep in out, f"over-redacted: {keep}"
    assert out.count("[SECRET_1]") == 2, "same secret should reuse placeholder"
    assert len(legend(mapping).splitlines()) == len(mapping), "multi-line values (keys) must stay on one legend line"
    print("self-test ok")


if __name__ == "__main__":
    selftest() if "--test" in sys.argv else gui()
