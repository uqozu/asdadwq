#!/usr/bin/env python3
"""Простой читатель почты по IMAP на tkinter.

Вводишь  адрес:пароль  (например zlrdtwet@fmze.net:мойпароль),
сервер определяется автоматически: mail.<домен после @>, порт 993 (SSL).
Только стандартная библиотека Python.
"""

import email
import html
import imaplib
import queue
import re
import threading
import tkinter as tk
from email import policy
from email.header import decode_header, make_header
from email.utils import parsedate_to_datetime
from tkinter import messagebox, ttk

LOAD_LIMIT = 50  # сколько последних писем показывать


def dec(value):
    """Декодирует заголовок (=?utf-8?...?=) в обычную строку."""
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return str(value)


def fmt_date(value):
    try:
        return parsedate_to_datetime(value).strftime("%d.%m.%Y %H:%M")
    except Exception:
        return value or ""


def html_to_text(src):
    src = re.sub(r"(?is)<(script|style).*?>.*?</\1>", "", src)
    src = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>", "\n", src)
    src = re.sub(r"<[^>]+>", "", src)
    src = html.unescape(src)
    return re.sub(r"\n{3,}", "\n\n", src).strip()


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("IMAP-читатель")
        self.root.geometry("1000x600")
        self.imap = None
        self.lock = threading.Lock()  # одно соединение — один запрос за раз
        self.q = queue.Queue()
        self.root.after(100, self.poll_queue)
        self.show_login()

    # ---------- работа в фоне ----------
    def run_async(self, func, on_done):
        """Выполняет func в потоке, затем on_done(result, error) в GUI-потоке."""
        def worker():
            try:
                res, err = func(), None
            except Exception as e:
                res, err = None, e
            self.q.put((on_done, res, err))
        threading.Thread(target=worker, daemon=True).start()

    def poll_queue(self):
        try:
            while True:
                cb, res, err = self.q.get_nowait()
                cb(res, err)
        except queue.Empty:
            pass
        self.root.after(100, self.poll_queue)

    def clear(self):
        for w in self.root.winfo_children():
            w.destroy()

    # ---------- экран входа ----------
    def show_login(self):
        self.clear()
        frame = ttk.Frame(self.root, padding=30)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(frame, text="Адрес:пароль", font=("", 11, "bold")).pack(anchor="w")
        self.cred_var = tk.StringVar()
        cred = ttk.Entry(frame, textvariable=self.cred_var, width=45, show="•")
        cred.pack(pady=(2, 4))
        cred.focus()

        self.show_pw = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            frame, text="Показать", variable=self.show_pw,
            command=lambda: cred.config(show="" if self.show_pw.get() else "•"),
        ).pack(anchor="w")

        ttk.Label(frame, text="IMAP-сервер (пусто = mail.<домен>)").pack(anchor="w", pady=(10, 0))
        self.server_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.server_var, width=45).pack(pady=2)

        self.status = ttk.Label(frame, text="", foreground="gray")
        self.status.pack(pady=8)

        self.login_btn = ttk.Button(frame, text="Войти", command=self.do_login)
        self.login_btn.pack()
        self.root.bind("<Return>", lambda e: self.do_login())

    def do_login(self):
        cred = self.cred_var.get().strip()
        if ":" not in cred:
            messagebox.showerror("Ошибка", "Формат: адрес:пароль")
            return
        # делим по первому ':' — в пароле двоеточия допустимы
        user, _, password = cred.partition(":")
        if "@" not in user:
            messagebox.showerror("Ошибка", "В адресе нет @")
            return
        domain = user.rsplit("@", 1)[1]
        server = self.server_var.get().strip() or f"mail.{domain}"

        self.login_btn.config(state="disabled")
        self.status.config(text=f"Подключаюсь к {server}...")

        def connect():
            conn = imaplib.IMAP4_SSL(server, 993, timeout=30)
            conn.login(user, password)
            return conn

        def done(conn, err):
            if err:
                self.login_btn.config(state="normal")
                self.status.config(text="")
                messagebox.showerror("Не удалось войти", f"{server}\n\n{err}")
                return
            self.imap = conn
            self.user = user
            self.show_mailbox()

        self.run_async(connect, done)

    # ---------- экран почты ----------
    def show_mailbox(self):
        self.clear()
        self.root.unbind("<Return>")

        top = ttk.Frame(self.root, padding=5)
        top.pack(fill="x")
        ttk.Label(top, text=self.user, font=("", 10, "bold")).pack(side="left")
        ttk.Button(top, text="Выйти", command=self.logout).pack(side="right")
        ttk.Button(top, text="Обновить", command=self.load_list).pack(side="right", padx=5)

        paned = ttk.PanedWindow(self.root, orient="horizontal")
        paned.pack(fill="both", expand=True)

        # список писем
        left = ttk.Frame(paned)
        cols = ("from", "subject", "date")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", selectmode="browse")
        for c, title, w in (("from", "От", 160), ("subject", "Тема", 220), ("date", "Дата", 110)):
            self.tree.heading(c, text=title)
            self.tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        paned.add(left, weight=1)

        # просмотр письма
        right = ttk.Frame(paned)
        self.header_lbl = ttk.Label(right, text="", justify="left", wraplength=450)
        self.header_lbl.pack(fill="x", padx=5, pady=5)
        self.text = tk.Text(right, wrap="word", state="disabled")
        tsb = ttk.Scrollbar(right, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=tsb.set)
        tsb.pack(side="right", fill="y")
        self.text.pack(fill="both", expand=True)
        paned.add(right, weight=2)

        self.statusbar = ttk.Label(self.root, text="", anchor="w", relief="sunken")
        self.statusbar.pack(fill="x")

        self.load_list()

    def set_status(self, text):
        self.statusbar.config(text=text)

    def set_text(self, text):
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", text)
        self.text.config(state="disabled")

    def load_list(self):
        self.set_status("Загружаю список писем...")
        self.tree.delete(*self.tree.get_children())

        def fetch():
            rows = []
            with self.lock:
                self.imap.select("INBOX", readonly=True)
                typ, data = self.imap.uid("search", None, "ALL")
                uids = data[0].split()[-LOAD_LIMIT:]
                for uid in reversed(uids):  # новые сверху
                    typ, d = self.imap.uid(
                        "fetch", uid, "(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])"
                    )
                    if typ != "OK" or not d or not isinstance(d[0], tuple):
                        continue
                    msg = email.message_from_bytes(d[0][1])
                    rows.append((
                        uid.decode(),
                        dec(msg["From"]),
                        dec(msg["Subject"]) or "(без темы)",
                        fmt_date(msg["Date"]),
                    ))
            return rows

        def done(rows, err):
            if err:
                self.set_status("")
                messagebox.showerror("Ошибка", str(err))
                return
            for uid, frm, subj, date in rows:
                self.tree.insert("", "end", iid=uid, values=(frm, subj, date))
            self.set_status(f"Писем: {len(rows)} (последние {LOAD_LIMIT})")

        self.run_async(fetch, done)

    def on_select(self, _event):
        sel = self.tree.selection()
        if not sel:
            return
        uid = sel[0]
        self.set_text("Загрузка...")
        self.header_lbl.config(text="")

        def fetch():
            with self.lock:
                self.imap.select("INBOX", readonly=True)
                typ, d = self.imap.uid("fetch", uid, "(BODY.PEEK[])")
                return d[0][1]

        def done(raw, err):
            if self.tree.selection() != (uid,):
                return  # пользователь уже выбрал другое письмо
            if err:
                self.set_text(f"Ошибка: {err}")
                return
            msg = email.message_from_bytes(raw, policy=policy.default)
            self.header_lbl.config(text=(
                f"От: {dec(msg['From'])}\n"
                f"Кому: {dec(msg['To'])}\n"
                f"Тема: {dec(msg['Subject'])}\n"
                f"Дата: {fmt_date(msg['Date'])}"
            ))
            self.set_text(self.extract_body(msg))

        self.run_async(fetch, done)

    @staticmethod
    def extract_body(msg):
        body = msg.get_body(preferencelist=("plain", "html"))
        if body is None:
            text = "(нет текста)"
        else:
            try:
                text = body.get_content()
            except Exception:
                text = body.get_payload(decode=True).decode("utf-8", "replace")
            if body.get_content_type() == "text/html":
                text = html_to_text(text)
        names = [p.get_filename() for p in msg.iter_attachments() if p.get_filename()]
        if names:
            text += "\n\n— Вложения: " + ", ".join(dec(n) for n in names)
        return text

    def logout(self):
        try:
            with self.lock:
                self.imap.logout()
        except Exception:
            pass
        self.imap = None
        self.show_login()


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()