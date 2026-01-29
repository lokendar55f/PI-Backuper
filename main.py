import os, sys, time, gzip, queue, threading, hashlib, subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

__title__ = "PI-Backuper"
__version__ = "1.0.2"
__author__ = "cFunkz"
__license__ = "MIT"
__url__ = "https://github.com/cfunkz/PI-Backuper"
__description__ = "Win11 raw USB/SD backup/restore/clone."

CHUNK = 8 * 1024 * 1024
QUEUE_MAX = 16
ICON_FILE = "favicon.ico"

FSCTL_LOCK_VOLUME = 0x00090018
FSCTL_DISMOUNT_VOLUME = 0x00090020

ERROR_IO_PENDING = 997


# ---------- imports (lazy, so app starts) ----------
def _win():
    # returns (wmi, win32file, win32con, pywintypes, win32event)
    try:
        import wmi
        import win32file, win32con
        import pywintypes, win32event
        return wmi, win32file, win32con, pywintypes, win32event
    except Exception as e:
        # show error even if called early
        try:
            messagebox.showerror(
                "Missing dependency",
                "Required Windows modules not available.\n\n"
                "Install:\n"
                "  pip install pywin32 wmi\n\n"
                f"Error: {e}"
            )
        except Exception:
            pass
        raise


# ---------- tiny helpers ----------
def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def resource_path(rel: str) -> Path:
    return Path(sys._MEIPASS) / rel if hasattr(sys, "_MEIPASS") else Path(rel)  # type: ignore[attr-defined]


def fmt_bytes(n: float) -> str:
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.2f} {u}"
        n /= 1024
    return f"{n:.2f} PB"


def fmt_eta(sec):
    if sec is None:
        return "ETA …"
    if sec <= 0:
        return "ETA —"
    m, s = divmod(int(sec), 60)
    h, m = divmod(m, 60)
    if h:
        return f"ETA {h}h {m:02d}m"
    if m:
        return f"ETA {m}m {s:02d}s"
    return f"ETA {s}s"


def disk_rescan():
    try:
        subprocess.run(["diskpart"], input="rescan\nexit\n", text=True, capture_output=True, check=False)
    except Exception:
        pass


def make_hasher(name: str):
    name = (name or "").lower()
    if name == "sha256":
        return hashlib.sha256()
    if name == "md5":
        return hashlib.md5()
    return None


def sidecar(img: str) -> str:
    return img + ".hash.txt"


def write_sidecar(path: str, algo: str, nbytes: int, hexd: str):
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"{algo.lower()} {int(nbytes)} {hexd.lower()}\n")
    except Exception:
        pass


def read_sidecar(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            parts = f.readline().strip().split()
        if len(parts) == 3:
            algo, nbytes, hexd = parts
            return algo.lower(), int(nbytes), hexd.lower()
    except Exception:
        pass
    return None


# ---------- raw disk I/O ----------
def open_disk(path: str, write: bool = False):
    _wmi, win32file, win32con, _pywintypes, _win32event = _win()
    access = win32con.GENERIC_READ | (win32con.GENERIC_WRITE if write else 0)
    share = win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE
    flags = win32con.FILE_FLAG_SEQUENTIAL_SCAN | (win32con.FILE_FLAG_OVERLAPPED if write else 0)
    return win32file.CreateFile(path, access, share, None, win32con.OPEN_EXISTING, flags, None)


def open_volume(letter: str):
    _wmi, win32file, win32con, _pywintypes, _win32event = _win()
    return win32file.CreateFile(
        rf"\\.\{letter}",
        win32con.GENERIC_READ | win32con.GENERIC_WRITE,
        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
        None,
        win32con.OPEN_EXISTING,
        0,
        None,
    )


def lock_dismount(letters):
    _wmi, win32file, _win32con, pywintypes, _win32event = _win()
    hs = []
    for l in sorted(set([x for x in letters if x and x.endswith(":")])):
        h = None
        try:
            h = open_volume(l)
            win32file.DeviceIoControl(int(h), FSCTL_LOCK_VOLUME, None, 0)
            win32file.DeviceIoControl(int(h), FSCTL_DISMOUNT_VOLUME, None, 0)
            hs.append(h)
        except pywintypes.error:
            if h:
                try: win32file.CloseHandle(int(h))
                except Exception: pass
            for hh in hs:
                try: win32file.CloseHandle(int(hh))
                except Exception: pass
            raise RuntimeError(f"Could not lock/dismount {l}. Close Explorer/anything using it and retry.")
    return hs


def close_handles(hs):
    _wmi, win32file, _win32con, _pywintypes, _win32event = _win()
    for h in hs:
        try:
            win32file.CloseHandle(int(h))
        except Exception:
            pass


def write_at_cancel(h, cancel_evt: threading.Event, off: int, data: bytes):
    _wmi, win32file, win32con, pywintypes, win32event = _win()
    CancelIoEx = getattr(win32file, "CancelIoEx", None)

    ov = pywintypes.OVERLAPPED()
    ov.hEvent = win32event.CreateEvent(None, True, False, None)
    ov.Offset = off & 0xFFFFFFFF
    ov.OffsetHigh = (off >> 32) & 0xFFFFFFFF
    try:
        try:
            win32file.WriteFile(int(h), data, ov)
        except pywintypes.error as e:
            if e.winerror != ERROR_IO_PENDING:
                raise

        while True:
            if cancel_evt.is_set():
                if CancelIoEx:
                    try: CancelIoEx(int(h), ov)
                    except Exception: pass
                raise InterruptedError("Cancelled")
            if win32event.WaitForSingleObject(ov.hEvent, 200) == win32con.WAIT_OBJECT_0:
                break

        win32file.GetOverlappedResult(int(h), ov, True)
    finally:
        try:
            win32file.CloseHandle(int(ov.hEvent))
        except Exception:
            pass


# ---------- disk detection ----------
def list_usb_disks():
    wmi, _win32file, _win32con, _pywintypes, _win32event = _win()
    c = wmi.WMI()
    out = []
    for d in c.Win32_DiskDrive():
        if (d.InterfaceType or "").upper() != "USB":
            continue
        letters = []
        try:
            for p in d.associators("Win32_DiskDriveToDiskPartition"):
                for l in p.associators("Win32_LogicalDiskToPartition"):
                    if l.DeviceID:
                        letters.append(str(l.DeviceID))
        except Exception:
            pass
        out.append(dict(
            idx=int(d.Index),
            phys=rf"\\.\PhysicalDrive{d.Index}",
            size=int(d.Size),
            model=(d.Model or "USB device").strip(),
            letters=letters,
        ))
    out.sort(key=lambda x: x["idx"])
    return out


# ---------- UI ----------
class App(ttk.Frame):
    def __init__(self, root: tk.Tk):
        super().__init__(root)
        self.root = root
        self.pack(fill="both", expand=True, padx=12, pady=12)

        self.q = queue.Queue()
        self.cancel = threading.Event()
        self.busy = False
        self.disks = []

        self.disk_var = tk.StringVar()
        self.src_var = tk.StringVar()
        self.dst_var = tk.StringVar()

        self.hash_var = tk.StringVar(value="sha256")
        self.compress_var = tk.BooleanVar(value=True)

        self.backup_path = tk.StringVar()
        self.restore_path = tk.StringVar()

        self.progress = tk.DoubleVar(value=0)
        self.status = tk.StringVar(value="Ready")
        self.speed = tk.StringVar(value="")
        self.eta = tk.StringVar(value="ETA —")

        self._ui()
        self.refresh()
        self.after(100, self._poll)

    def _ui(self):
        menubar = tk.Menu(self.root)
        h = tk.Menu(menubar, tearoff=0)
        h.add_command(label="About", command=self._about)
        menubar.add_cascade(label="Help", menu=h)
        self.root.config(menu=menubar)

        dev = ttk.LabelFrame(self, text="USB device (Backup/Restore)")
        dev.pack(fill="x", pady=(0, 6))
        self.disk_box = ttk.Combobox(dev, textvariable=self.disk_var, state="readonly")
        self.disk_box.pack(side="left", fill="x", expand=True, padx=6, pady=6)
        ttk.Button(dev, text="Refresh", command=self.refresh).pack(side="right", padx=6, pady=6)

        row = ttk.Frame(self); row.pack(fill="x", pady=(0, 6))

        b = ttk.LabelFrame(row, text="Backup"); b.pack(side="left", fill="both", expand=True, padx=(0, 5))
        ttk.Entry(b, textvariable=self.backup_path).pack(fill="x", padx=6, pady=4)
        rb = ttk.Frame(b); rb.pack(fill="x", padx=6, pady=(0, 6))
        ttk.Button(rb, text="Choose output", command=self.pick_backup).pack(side="left")
        ttk.Button(rb, text="Start backup", command=self.start_backup).pack(side="right")

        r = ttk.LabelFrame(row, text="Restore"); r.pack(side="left", fill="both", expand=True, padx=(5, 0))
        ttk.Entry(r, textvariable=self.restore_path).pack(fill="x", padx=6, pady=4)
        rr = ttk.Frame(r); rr.pack(fill="x", padx=6, pady=(0, 6))
        ttk.Button(rr, text="Choose image", command=self.pick_restore).pack(side="left")
        ttk.Button(rr, text="Start restore (erases)", command=self.start_restore).pack(side="right")

        c = ttk.LabelFrame(self, text="Clone (Live A → B, erases B)")
        c.pack(fill="x", pady=(0, 6))
        ttk.Label(c, text="A:").pack(side="left", padx=(6, 4), pady=6)
        self.src_box = ttk.Combobox(c, textvariable=self.src_var, state="readonly", width=34)
        self.src_box.pack(side="left", fill="x", expand=True, padx=(0, 10), pady=6)
        ttk.Label(c, text="B:").pack(side="left", padx=(0, 4), pady=6)
        self.dst_box = ttk.Combobox(c, textvariable=self.dst_var, state="readonly", width=34)
        self.dst_box.pack(side="left", fill="x", expand=True, padx=(0, 10), pady=6)
        ttk.Button(c, text="Start clone", command=self.start_clone).pack(side="right", padx=(0, 6), pady=6)

        opt = ttk.LabelFrame(self, text="Options")
        opt.pack(fill="x", pady=(0, 6))
        for txt, val in (("SHA256", "sha256"), ("MD5", "md5"), ("None", "none")):
            ttk.Radiobutton(opt, text=txt, variable=self.hash_var, value=val).pack(side="left", padx=6, pady=2)
        ttk.Checkbutton(opt, text="Gzip compress", variable=self.compress_var).pack(side="right", padx=6, pady=2)

        prog = ttk.LabelFrame(self, text="Progress"); prog.pack(fill="x")
        ttk.Progressbar(prog, variable=self.progress, maximum=100).pack(fill="x", padx=6, pady=(4, 2))
        lines = ttk.Frame(prog); lines.pack(fill="x", padx=6, pady=(0, 4))
        ttk.Label(lines, textvariable=self.status).pack(anchor="w")
        ttk.Label(lines, textvariable=self.speed).pack(anchor="w")
        er = ttk.Frame(lines); er.pack(fill="x")
        ttk.Label(er, textvariable=self.eta).pack(side="left")
        self.cancel_btn = ttk.Button(er, text="Cancel", command=self._cancel, state="disabled")
        self.cancel_btn.pack(side="right")

    def _about(self):
        messagebox.showinfo(
            "About",
            f"{__title__} v{__version__}\n{__description__}\n\nAuthor: {__author__}\nLicense: {__license__}\n{__url__}",
        )

    def refresh(self):
        try:
            self.disks = list_usb_disks()
        except Exception:
            self.disks = []

        vals = []
        for d in self.disks:
            letters = ",".join(d["letters"]) if d["letters"] else "—"
            vals.append(f"{letters} | {fmt_bytes(d['size'])} | Disk {d['idx']} | {d['model']}")

        for box in (self.disk_box, self.src_box, self.dst_box):
            box["values"] = vals
            if vals and box.current() < 0:
                box.current(0)

        if vals:
            self.disk_var.set(vals[self.disk_box.current()])
            self.src_var.set(vals[self.src_box.current()])
            self.dst_var.set(vals[self.dst_box.current()])

    def _disk(self, box: ttk.Combobox):
        if not self.disks or box.current() < 0:
            raise RuntimeError("No disk selected.")
        return self.disks[box.current()]

    def pick_backup(self):
        ext = ".img.gz" if self.compress_var.get() else ".img"
        p = filedialog.asksaveasfilename(defaultextension=ext, filetypes=[("Image", "*.img *.img.gz"), ("All", "*.*")])
        if p:
            self.backup_path.set(p)

    def pick_restore(self):
        p = filedialog.askopenfilename(filetypes=[("Image", "*.img *.img.gz"), ("All", "*.*")])
        if p:
            self.restore_path.set(p)

    def _set_busy(self, on: bool):
        self.busy = on
        self.cancel_btn.config(state="normal" if on else "disabled")

    def _cancel(self):
        self.cancel.set()
        self.status.set("Cancelling…")

    def _run(self, worker):
        self.progress.set(0)
        self.status.set("Starting…")
        self.speed.set("")
        self.eta.set("ETA …")
        self.cancel.clear()
        self._set_busy(True)
        threading.Thread(target=worker, daemon=True).start()

    def _stream(self, read_fn, write_fn, total, hasher=None, limit=None):
        qd = queue.Queue(maxsize=QUEUE_MAX)
        done, start, last = 0, time.time(), time.time()
        err: list[object] = [None]

        def prod():
            try:
                while not self.cancel.is_set():
                    b = read_fn()
                    if not b:
                        break
                    qd.put(b)
            except BaseException as e:
                err[0] = e
            finally:
                qd.put(None)

        threading.Thread(target=prod, daemon=True).start()

        while True:
            b = qd.get()
            if b is None:
                break
            if self.cancel.is_set():
                break
            if limit:
                limit(len(b))
            if hasher:
                hasher.update(b)
            write_fn(b)
            done += len(b)

            now = time.time()
            if now - last >= 0.2:
                dt = max(now - start, 1e-6)
                spd = done / dt
                eta = (total - done) / spd if spd > 0 else None
                self.q.put(("p", done, total, spd, eta))
                last = now

        if isinstance(err[0], BaseException):
            raise err[0]

        dt = max(time.time() - start, 1e-6)
        spd = done / dt
        eta = (total - done) / spd if spd > 0 else None
        self.q.put(("p", done, total, spd, eta))
        return done

    # ---------- buttons ----------
    def start_backup(self):
        if self.busy:
            return messagebox.showwarning("Busy", "Operation running.")
        if not self.backup_path.get().strip():
            return messagebox.showerror("Error", "No output file.")
        self._run(self._backup)

    def start_restore(self):
        if self.busy:
            return messagebox.showwarning("Busy", "Operation running.")
        if not self.restore_path.get().strip():
            return messagebox.showerror("Error", "No image selected.")
        d = self._disk(self.disk_box)
        if not messagebox.askyesno("WARNING", f"THIS ERASES:\n\nDisk {d['idx']} ({fmt_bytes(d['size'])})\n\nContinue?"):
            return
        self._run(self._restore)

    def start_clone(self):
        if self.busy:
            return messagebox.showwarning("Busy", "Operation running.")
        a = self._disk(self.src_box)
        b = self._disk(self.dst_box)
        if a["idx"] == b["idx"]:
            return messagebox.showerror("Error", "A and B must be different.")
        if b["size"] < a["size"]:
            return messagebox.showerror("Error", f"Target smaller.\nA: {fmt_bytes(a['size'])}\nB: {fmt_bytes(b['size'])}")
        if not messagebox.askyesno(
            "WARNING",
            "CLONE ERASES B.\n\n"
            f"A: Disk {a['idx']} ({fmt_bytes(a['size'])})\n"
            f"B: Disk {b['idx']} ({fmt_bytes(b['size'])})\n\nContinue?"
        ):
            return
        self._run(self._clone)

    # ---------- workers ----------
    def _backup(self):
        _wmi, win32file, _win32con, _pywintypes, _win32event = _win()
        rd = raw = gz = None
        try:
            d = self._disk(self.disk_box)
            out = self.backup_path.get().strip()
            tmp = out + ".partial"
            try: os.remove(tmp)
            except Exception: pass

            algo = self.hash_var.get().lower()
            hasher = make_hasher(algo)

            rd = open_disk(d["phys"], write=False)
            raw = open(tmp, "wb", buffering=16 * 1024 * 1024)
            gz = gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=1) if self.compress_var.get() else raw

            total = d["size"]
            remaining = total

            def r():
                nonlocal remaining
                if remaining <= 0:
                    return b""
                if self.cancel.is_set():
                    raise InterruptedError()
                to_read = min(CHUNK, remaining)
                _hr, data = win32file.ReadFile(int(rd), to_read)
                remaining -= len(data)
                return data

            def w(b: bytes):
                gz.write(b)

            self._stream(r, w, total, hasher=hasher)

            try: gz.close()
            except Exception: pass
            try:
                raw.flush()
                os.fsync(raw.fileno())
            except Exception:
                pass

            if self.cancel.is_set():
                try: os.remove(tmp)
                except Exception: pass
                return self.q.put(("done", "Backup cancelled"))

            os.replace(tmp, out)
            if hasher:
                write_sidecar(sidecar(out), algo, total, hasher.hexdigest())
            self.q.put(("done", "Backup complete"))

        except InterruptedError:
            self.q.put(("done", "Backup cancelled"))
        except Exception as e:
            self.q.put(("err", str(e)))
        finally:
            try:
                if gz and gz is not raw: gz.close()
            except Exception: pass
            try:
                if raw: raw.close()
            except Exception: pass
            try:
                if rd: win32file.CloseHandle(int(rd))
            except Exception: pass

    def _restore(self):
        _wmi, win32file, _win32con, _pywintypes, _win32event = _win()
        hs = []
        dst = src = None
        try:
            d = self._disk(self.disk_box)
            img = self.restore_path.get().strip()

            meta = read_sidecar(sidecar(img))
            hasher = make_hasher(meta[0]) if meta else None
            expect_bytes = meta[1] if meta else None
            expect_hex = meta[2] if meta else None

            hs = lock_dismount(d["letters"])
            dst = open_disk(d["phys"], write=True)
            src = gzip.open(img, "rb") if img.lower().endswith(".gz") else open(img, "rb")

            written = 0
            off = 0
            total_prog = expect_bytes if expect_bytes else d["size"]

            def r():
                if self.cancel.is_set():
                    raise InterruptedError()
                return src.read(CHUNK)

            def limit(n):
                nonlocal written
                if written + n > d["size"]:
                    raise RuntimeError("Image larger than target device.")

            def w(b: bytes):
                nonlocal written, off
                write_at_cancel(dst, self.cancel, off, b)
                off += len(b)
                written += len(b)

            self._stream(r, w, total_prog, hasher=hasher, limit=limit)

            try: win32file.FlushFileBuffers(int(dst))
            except Exception: pass

            if self.cancel.is_set():
                return self.q.put(("done", "Restore cancelled"))

            if hasher and expect_hex:
                if expect_bytes is not None and written != expect_bytes:
                    raise RuntimeError(f"Size mismatch (expected {expect_bytes}, got {written})")
                if hasher.hexdigest().lower() != expect_hex.lower():
                    raise RuntimeError("Hash verify FAILED")

            disk_rescan()
            self.q.put(("done", "Restore complete"))

        except InterruptedError:
            self.q.put(("done", "Restore cancelled"))
        except Exception as e:
            self.q.put(("err", str(e)))
        finally:
            try:
                if src: src.close()
            except Exception: pass
            try:
                if dst: win32file.CloseHandle(int(dst))
            except Exception: pass
            close_handles(hs)

    def _clone(self):
        _wmi, win32file, _win32con, _pywintypes, _win32event = _win()
        hs = []
        src = dst = None
        try:
            a = self._disk(self.src_box)
            b = self._disk(self.dst_box)

            hs = lock_dismount(b["letters"])
            src = open_disk(a["phys"], write=False)
            dst = open_disk(b["phys"], write=True)

            total = a["size"]
            remaining = total
            off = 0

            def r():
                nonlocal remaining
                if remaining <= 0:
                    return b""
                if self.cancel.is_set():
                    raise InterruptedError()
                to_read = min(CHUNK, remaining)
                _hr, data = win32file.ReadFile(int(src), to_read)
                remaining -= len(data)
                return data

            def w(buf: bytes):
                nonlocal off
                write_at_cancel(dst, self.cancel, off, buf)
                off += len(buf)

            self._stream(r, w, total)

            try: win32file.FlushFileBuffers(int(dst))
            except Exception: pass

            if self.cancel.is_set():
                return self.q.put(("done", "Clone cancelled"))

            disk_rescan()
            self.q.put(("done", "Clone complete"))

        except InterruptedError:
            self.q.put(("done", "Clone cancelled"))
        except Exception as e:
            self.q.put(("err", str(e)))
        finally:
            try:
                if src: win32file.CloseHandle(int(src))
            except Exception: pass
            try:
                if dst: win32file.CloseHandle(int(dst))
            except Exception: pass
            close_handles(hs)

    def _poll(self):
        try:
            while True:
                msg = self.q.get_nowait()
                if msg[0] == "p":
                    _, done, total, spd, eta = msg
                    total = max(int(total), 1)
                    self.progress.set(min(done / total * 100, 100))
                    self.status.set(f"{fmt_bytes(done)} / {fmt_bytes(total)}")
                    self.speed.set(f"{fmt_bytes(spd)}/s" if spd else "")
                    self.eta.set(fmt_eta(eta))
                elif msg[0] == "done":
                    self._set_busy(False)
                    self.status.set(msg[1])
                    self.speed.set("")
                    self.eta.set("ETA —")
                elif msg[0] == "err":
                    self._set_busy(False)
                    self.status.set("Error")
                    self.speed.set("")
                    self.eta.set("ETA —")
                    messagebox.showerror("Error", msg[1])
        except queue.Empty:
            pass
        self.after(100, self._poll)


def install_exception_box():
    def _hook(exctype, value, tb):
        import traceback
        msg = "".join(traceback.format_exception(exctype, value, tb))
        try:
            messagebox.showerror("Fatal error", msg)
        except Exception:
            pass
        raise SystemExit(1)
    sys.excepthook = _hook


def main():
    root = tk.Tk()
    install_exception_box()

    try:
        root.iconbitmap(resource_path(ICON_FILE))
    except Exception:
        pass

    root.title(f"{__title__} v{__version__}")
    root.geometry("860x500")
    root.minsize(780, 460)

    if not is_admin():
        messagebox.showerror("Admin required", "Run as Administrator.")
        root.destroy()
        return

    _win()

    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
