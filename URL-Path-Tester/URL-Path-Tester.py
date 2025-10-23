# -*- coding: utf-8 -*-
"""
url_tester_v5.py
支持：自定义请求方法、请求体、请求头、Repeater（可重复发送/编辑），逐条顺序请求、关键字检测、CSV 导出等。
在请求头输入区旁边注释：请把 Burp 的请求体完整复制到请求体框中（包含请求头与 body）
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import threading, time, csv, re
from urllib.parse import urlsplit, urlunsplit
import requests

DEFAULT_KEYWORDS = [
    "success", "成功", "key", "flag", "token", "admin",
    "password", "pwd", "login", "error", "ok", "登录成功"
]
HTTP_METHODS = ["GET","POST","PUT","DELETE","HEAD","OPTIONS","PATCH"]

# --------- 辅助函数 ----------
def normalize_base_url(url: str) -> str:
    parts = urlsplit(url.strip())
    return urlunsplit((parts.scheme or "http", parts.netloc, parts.path or "/", "", ""))

def try_parse_raw_request(raw: str):
    """
    尝试解析 raw HTTP request（例如从 Burp 复制过来的）
    返回 (method, url, headers_dict, body_str)
    如果解析失败，返回 None
    """
    if not raw:
        return None
    lines = raw.splitlines()
    # 找到第一行像: "POST /path HTTP/1.1" 或 "GET /path HTTP/1.1" 或完整URL "GET http://host/path HTTP/1.1"
    first = lines[0].strip()
    m = re.match(r'([A-Z]+)\s+(\S+)\s+HTTP/\d+\.\d+', first)
    if not m:
        return None
    method = m.group(1).upper()
    url_part = m.group(2)
    # 如果 url_part 是相对路径，需要从 Host header 补全
    headers = {}
    body = ""
    idx = 1
    # parse headers until blank line
    while idx < len(lines):
        line = lines[idx]
        idx += 1
        if line.strip() == "":
            break
        sp = line.split(":", 1)
        if len(sp) == 2:
            headers[sp[0].strip()] = sp[1].strip()
    # rest is body
    body = "\n".join(lines[idx:]) if idx < len(lines) else ""
    if url_part.startswith("http://") or url_part.startswith("https://"):
        full_url = url_part
    else:
        host = headers.get("Host", "")
        scheme = "https" if raw.lower().find("https://")!=-1 else "http"
        if host:
            # ensure host doesn't have schema
            host = host.strip()
            full_url = scheme + "://" + host.rstrip("/") + "/" + url_part.lstrip("/")
        else:
            full_url = url_part  # leave as-is
    return method, full_url, headers, body

# --------- 主应用 ----------
class URLTesterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("URL Path Tester v5 (with Repeater)")
        self.root.geometry("1200x780")

        # ----- Top: base URL, method selector, custom headers area -----
        top_frame = tk.Frame(root)
        top_frame.pack(fill=tk.X, padx=8, pady=6)

        tk.Label(top_frame, text="基础 URL:").pack(side=tk.LEFT)
        self.url_entry = tk.Entry(top_frame, width=45)
        self.url_entry.pack(side=tk.LEFT, padx=6)

        tk.Label(top_frame, text="  Method:").pack(side=tk.LEFT, padx=(8,0))
        self.method_var = tk.StringVar(value="GET")
        self.method_combo = ttk.Combobox(top_frame, textvariable=self.method_var, values=HTTP_METHODS, width=8, state="readonly")
        self.method_combo.pack(side=tk.LEFT, padx=6)

        # 简单 headers 输入（单行：User-Agent, Cookie, Authorization）
        headers_frame = tk.Frame(top_frame)
        headers_frame.pack(side=tk.LEFT, padx=8)
        tk.Label(headers_frame, text="User-Agent:").grid(row=0,column=0,sticky="e")
        self.ua_entry = tk.Entry(headers_frame, width=28)
        self.ua_entry.grid(row=0,column=1, padx=4)
        tk.Label(headers_frame, text="Cookie:").grid(row=1,column=0,sticky="e")
        self.cookie_entry = tk.Entry(headers_frame, width=28)
        self.cookie_entry.grid(row=1,column=1, padx=4)
        tk.Label(headers_frame, text="Authorization:").grid(row=2,column=0,sticky="e")
        self.auth_entry = tk.Entry(headers_frame, width=28)
        self.auth_entry.grid(row=2,column=1, padx=4)

        # 注释提示（关于 Burp）
        hint = tk.Label(top_frame, text="（Burp复制请求,粘贴到下方Repeater的Raw Request即可）", fg="#555")
        hint.pack(side=tk.RIGHT)

        # ----- Middle left: paths input & control buttons -----
        left_frame = tk.Frame(root)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=8, pady=4)

        tk.Label(left_frame, text="Paths（每行一个）:").pack(anchor="w")
        self.path_text = ScrolledText(left_frame, width=50, height=18)
        self.path_text.pack(padx=4, pady=4)

        btns = tk.Frame(left_frame)
        btns.pack(pady=4)
        tk.Button(btns, text="开始顺序请求", command=self.start_requests, bg="#4CAF50", fg="white", width=14).pack(side=tk.LEFT, padx=4)
        tk.Button(btns, text="停止", command=self.stop_requests, bg="#E53935", fg="white", width=8).pack(side=tk.LEFT, padx=4)
        tk.Button(btns, text="请求一条(手动)", command=self.request_one_manual, width=14).pack(side=tk.LEFT, padx=4)
        tk.Button(btns, text="打开 Repeater", command=self.open_repeater, width=12).pack(side=tk.LEFT, padx=4)

        # keywords and filters
        tk.Label(left_frame, text="关键字(逗号分隔):").pack(anchor="w", pady=(6,0))
        self.keyword_entry = tk.Entry(left_frame, width=40)
        self.keyword_entry.pack()
        self.keyword_entry.insert(0, ",".join(DEFAULT_KEYWORDS))

        # CSV export & clear
        tk.Button(left_frame, text="导出 CSV", command=self.export_csv, width=20).pack(pady=(8,2))
        tk.Button(left_frame, text="清空结果", command=self.clear_table, width=20).pack()

        # ----- Right: results table with scrollbars -----
        right_frame = tk.Frame(root)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=8, pady=4)

        filter_frame = tk.Frame(right_frame)
        filter_frame.pack(fill=tk.X, pady=2)
        tk.Label(filter_frame, text="筛选 Status:").pack(side=tk.LEFT)
        self.status_filter = ttk.Combobox(filter_frame, width=12, values=["全部","200","301","302","403","404","500","Error"])
        self.status_filter.current(0)
        self.status_filter.pack(side=tk.LEFT, padx=6)
        tk.Button(filter_frame, text="应用筛选", command=self.apply_filter).pack(side=tk.LEFT, padx=6)

        # columns include Method
        columns = ("Method","URL","Status","Time(ms)","Length","Matches")
        self.tree = ttk.Treeview(right_frame, columns=columns, show="headings", selectmode="browse")
        for col in columns:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_tree(c, False))
            self.tree.column(col, width=320 if col=="URL" else 90, anchor="w")
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # scrollbars
        yscroll = ttk.Scrollbar(right_frame, orient="vertical", command=self.tree.yview)
        xscroll = ttk.Scrollbar(right_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscroll=yscroll.set, xscroll=xscroll.set)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)
        xscroll.pack(side=tk.BOTTOM, fill=tk.X)

        # context menu: send selected to repeater
        self.menu = tk.Menu(self.root, tearoff=0)
        self.menu.add_command(label="Send to Repeater", command=self.menu_send_to_repeater)
        self.tree.bind("<Button-3>", self.show_context_menu)

        # double click to show detail
        self.tree.bind("<Double-1>", self.show_detail)

        # tags (match/error)
        self.tree.tag_configure("match", background="#cfe9ff")
        self.tree.tag_configure("error", background="#ffd6d6")

        # status bar
        self.status_label = tk.Label(root, text="等待中...", anchor="w")
        self.status_label.pack(fill=tk.X, padx=6, pady=4)

        # internal state
        self.responses = {}  # full_url -> (headers, body, status, method)
        self.all_rows = []   # store rows: (method,url,status,time,len,matches)
        self.filtered_rows = []
        self.stop_flag = False
        self._manual_queue = []
        self.manual_mode = False
        self._worker_thread = None

        # Repeater window ref
        self.repeater_win = None

    # ---------- 主流程：顺序请求 / 单条请求 ----------
    def start_requests(self):
        self.stop_flag = False
        base_raw = self.url_entry.get().strip()
        if not base_raw:
            messagebox.showwarning("警告", "请先输入基础 URL")
            return
        base_url = normalize_base_url(base_raw)
        method = self.method_var.get().upper()
        paths = [p.strip() for p in self.path_text.get("1.0", tk.END).splitlines() if p.strip()]
        if not paths:
            messagebox.showwarning("警告", "请在 Paths 区输入至少一行 path")
            return

        # build queue of (method, full_url, body, headers)
        self._manual_queue.clear()
        # prepare headers from simple inputs
        base_headers = {}
        if self.ua_entry.get().strip():
            base_headers["User-Agent"] = self.ua_entry.get().strip()
        if self.cookie_entry.get().strip():
            base_headers["Cookie"] = self.cookie_entry.get().strip()
        if self.auth_entry.get().strip():
            base_headers["Authorization"] = self.auth_entry.get().strip()

        for p in paths:
            full = base_url.rstrip("/") + "/" + p.lstrip("/")
            self._manual_queue.append((method, full, "", dict(base_headers)))  # body empty here; user can send to repeater to modify

        # clear table before running
        self.clear_table()
        # start thread to run sequentially
        self._worker_thread = threading.Thread(target=self._run_sequential, args=(self._manual_queue.copy(),))
        self._worker_thread.daemon = True
        self._worker_thread.start()

    def _run_sequential(self, queue):
        total = len(queue)
        for idx, (method, full_url, body, headers) in enumerate(queue, start=1):
            if self.stop_flag:
                break
            self.status_label.config(text=f"请求中 ({idx}/{total}): {full_url}")
            self.root.update_idletasks()
            # perform single request
            self._do_request_and_insert(method, full_url, headers, body)
            time.sleep(0.25)
        if not self.stop_flag:
            self.status_label.config(text="所有请求完成 ✅")

    def stop_requests(self):
        self.stop_flag = True
        self.status_label.config(text="已停止。")

    def request_one_manual(self):
        # generate queue if empty
        if not self._manual_queue:
            base_raw = self.url_entry.get().strip()
            if not base_raw:
                messagebox.showwarning("警告", "请先输入基础 URL")
                return
            base_url = normalize_base_url(base_raw)
            # just take first path
            paths = [p.strip() for p in self.path_text.get("1.0", tk.END).splitlines() if p.strip()]
            if not paths:
                messagebox.showwarning("警告", "请在 Paths 区输入至少一行 path")
                return
            method = self.method_var.get().upper()
            headers = {}
            if self.ua_entry.get().strip():
                headers["User-Agent"] = self.ua_entry.get().strip()
            if self.cookie_entry.get().strip():
                headers["Cookie"] = self.cookie_entry.get().strip()
            if self.auth_entry.get().strip():
                headers["Authorization"] = self.auth_entry.get().strip()
            self._manual_queue = [(method, base_url.rstrip("/") + "/" + p.lstrip("/"), "", dict(headers)) for p in paths]
            self.manual_mode = True

        if self._manual_queue:
            item = self._manual_queue.pop(0)
            threading.Thread(target=self._do_request_and_insert, args=item, daemon=True).start()
            self.status_label.config(text=f"手动请求：{item[1]}")
        else:
            messagebox.showinfo("提示", "无更多项可请求")

    # ---------- 单次请求逻辑 ----------
    def _do_request_and_insert(self, method, full_url, headers=None, body=""):
        try:
            headers = headers or {}
            start = time.time()
            # use requests.request for generic method support
            resp = requests.request(method=method, url=full_url, headers=headers, data=body.encode("utf-8") if isinstance(body,str) else body, timeout=10)
            elapsed = int((time.time() - start) * 1000)
            status = resp.status_code
            length = len(resp.content)
            text = resp.text or ""
            # check keywords
            keywords = [k.strip().lower() for k in self.keyword_entry.get().split(",") if k.strip()]
            matches = [k for k in keywords if k in (text.lower())]
            tag = "match" if matches else ""
            row = (method, full_url, status, elapsed, length, ",".join(matches))
            # insert into UI via main thread
            self.root.after(0, self._insert_row_ui, row, tag)
            self.responses[full_url] = (resp.headers, resp.text, status, method)
        except Exception as e:
            row = (method, full_url, "Error", "-", "-", str(e))
            self.root.after(0, self._insert_row_ui, row, "error")
            self.responses[full_url] = ({}, str(e), "Error", method)

    def _insert_row_ui(self, row, tag):
        self.all_rows.append(row)
        self.tree.insert("", tk.END, values=row, tags=(tag,))
        self.filtered_rows = list(self.all_rows)

    # ---------- Repeater 窗口 ----------
    def open_repeater(self, prefilled=None):
        # prefilled: optional dict {method,url,headers,body}
        if self.repeater_win and tk.Toplevel.winfo_exists(self.repeater_win):
            self.repeater_win.lift()
            return
        w = tk.Toplevel(self.root)
        w.title("Repeater - 临时请求编辑与重放")
        w.geometry("900x700")
        self.repeater_win = w

        top = tk.Frame(w)
        top.pack(fill=tk.X, pady=4, padx=6)
        tk.Label(top, text="Method:").pack(side=tk.LEFT)
        method_var = tk.StringVar(value=(prefilled.get("method") if prefilled else self.method_var.get()))
        method_combo = ttk.Combobox(top, textvariable=method_var, values=HTTP_METHODS, width=8, state="readonly")
        method_combo.pack(side=tk.LEFT, padx=6)
        tk.Label(top, text="URL:").pack(side=tk.LEFT, padx=(8,0))
        url_entry = tk.Entry(top, width=70)
        url_entry.pack(side=tk.LEFT, padx=6)
        if prefilled and prefilled.get("url"):
            url_entry.insert(0, prefilled["url"])
        elif prefilled is None and self.url_entry.get().strip():
            url_entry.insert(0, self.url_entry.get().strip())

        # headers area and body area
        tk.Label(w, text="Raw Request (可直接粘贴 Burp 的 raw 请求，包括请求行、Headers、Body)：").pack(anchor="w", padx=6)
        raw_box = ScrolledText(w, height=12)
        raw_box.pack(fill=tk.X, padx=6, pady=4)
        if prefilled and prefilled.get("raw"):
            raw_box.insert(tk.END, prefilled["raw"])

        # parsed headers fields (editable)
        h_frame = tk.Frame(w)
        h_frame.pack(fill=tk.X, padx=6)
        tk.Label(h_frame, text="Headers (一行一个：Key: Value)").pack(anchor="w")
        headers_box = ScrolledText(h_frame, height=6)
        headers_box.pack(fill=tk.X, pady=4)
        if prefilled and prefilled.get("headers"):
            headers_box.insert(tk.END, "\n".join([f"{k}: {v}" for k,v in prefilled["headers"].items()]))

        tk.Label(w, text="Body:").pack(anchor="w", padx=6)
        body_box = ScrolledText(w, height=12)
        body_box.pack(fill=tk.BOTH, expand=False, padx=6, pady=4)
        if prefilled and prefilled.get("body"):
            body_box.insert(tk.END, prefilled["body"])

        # response display
        resp_label = tk.Label(w, text="Response (按 Send 后显示)：")
        resp_label.pack(anchor="w", padx=6)
        resp_box = ScrolledText(w, height=12)
        resp_box.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        # helper to parse raw into fields
        def parse_raw_to_fields():
            raw = raw_box.get("1.0", tk.END).strip()
            parsed = try_parse_raw_request(raw)
            if not parsed:
                messagebox.showwarning("提示", "无法解析为标准 raw HTTP 请求，请确保包含请求行（例如 'POST /path HTTP/1.1'）和 Host header")
                return
            m, full_url, headers, body = parsed
            method_var.set(m)
            url_entry.delete(0, tk.END)
            url_entry.insert(0, full_url)
            headers_box.delete("1.0", tk.END)
            headers_box.insert(tk.END, "\n".join([f"{k}: {v}" for k,v in headers.items()]))
            body_box.delete("1.0", tk.END)
            body_box.insert(tk.END, body)

        def send_request_to_server(save_to_main=False):
            method = method_var.get().upper()
            url = url_entry.get().strip()
            # parse headers area
            header_lines = headers_box.get("1.0", tk.END).splitlines()
            headers = {}
            for line in header_lines:
                if ":" in line:
                    k,v = line.split(":",1)
                    headers[k.strip()] = v.strip()
            body = body_box.get("1.0", tk.END)
            resp_box.delete("1.0", tk.END)
            resp_box.insert(tk.END, "Sending...\n")
            def do_send():
                try:
                    start = time.time()
                    r = requests.request(method=method, url=url, headers=headers, data=body.encode("utf-8"), timeout=15)
                    elapsed = int((time.time() - start)*1000)
                    out = []
                    out.append(f"Status: {r.status_code}    Time(ms): {elapsed}    Length: {len(r.content)}\n")
                    out.append("---- Response Headers ----")
                    for hk,hv in r.headers.items():
                        out.append(f"{hk}: {hv}")
                    out.append("\n---- Body ----")
                    try:
                        out.append(r.text)
                    except:
                        out.append("[binary content]")
                    self.repeater_win.after(0, lambda: resp_box.delete("1.0", tk.END))
                    self.repeater_win.after(0, lambda: resp_box.insert(tk.END, "\n".join(out)))
                    # optionally save result back to main table
                    if save_to_main:
                        # keyword match detection
                        keywords = [k.strip().lower() for k in self.keyword_entry.get().split(",") if k.strip()]
                        textlow = (r.text or "").lower()
                        matches = [k for k in keywords if k in textlow]
                        tag = "match" if matches else ""
                        row = (method, url, r.status_code, elapsed, len(r.content), ",".join(matches))
                        self.root.after(0, lambda: self._insert_row_ui(row, tag))
                        self.responses[url] = (r.headers, r.text, r.status_code, method)
                except Exception as e:
                    self.repeater_win.after(0, lambda: resp_box.delete("1.0", tk.END))
                    self.repeater_win.after(0, lambda: resp_box.insert(tk.END, f"Error: {str(e)}"))
            threading.Thread(target=do_send, daemon=True).start()

        # buttons: parse raw, send, send->save, repeat send
        ctrl = tk.Frame(w)
        ctrl.pack(pady=6)
        tk.Button(ctrl, text="Parse Raw -> Fill", command=parse_raw_to_fields).pack(side=tk.LEFT, padx=6)
        tk.Button(ctrl, text="Send", command=lambda: send_request_to_server(False)).pack(side=tk.LEFT, padx=6)
        tk.Button(ctrl, text="Send & Save to Main", command=lambda: send_request_to_server(True)).pack(side=tk.LEFT, padx=6)

        # Repeater supports repeated sending: user can click Send repeatedly as needed

    def menu_send_to_repeater(self):
        sel = self.tree.selection()
        if not sel:
            return
        rowvals = self.tree.item(sel, "values")
        method, url = rowvals[0], rowvals[1]
        # try to fill headers/body from stored response if available
        rec = self.responses.get(url)
        pre = {"method": method, "url": url}
        if rec:
            headers, body_text, status, m = rec if len(rec)>=4 else (rec[0], rec[1], rec[2], "")
            pre["headers"] = headers if isinstance(headers, dict) else {}
            pre["body"] = ""
            pre["raw"] = ""
        self.open_repeater(prefilled=pre)

    def show_context_menu(self, event):
        try:
            iid = self.tree.identify_row(event.y)
            if iid:
                self.tree.selection_set(iid)
                self.menu.post(event.x_root, event.y_root)
        finally:
            self.menu.grab_release()

    # ---------- UI utilities: filter, sort, export, clear ----------
    def apply_filter(self):
        sel = self.status_filter.get()
        self.tree.delete(*self.tree.get_children())
        if sel == "全部" or not sel:
            rows = self.all_rows
        else:
            rows = [r for r in self.all_rows if str(r[2]) == sel]
        self.filtered_rows = rows
        for row in rows:
            tag = "match" if row[-1] else ""
            self.tree.insert("", tk.END, values=row, tags=(tag,))

    def sort_tree(self, col, reverse):
        # col is header name, map to column index
        cols = ("Method","URL","Status","Time(ms)","Length","Matches")
        idx = cols.index(col)
        data = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        def try_num(x):
            try:
                return float(x)
            except:
                return str(x).lower()
        data.sort(key=lambda t: try_num(t[0]), reverse=reverse)
        for pos, (val, k) in enumerate(data):
            self.tree.move(k, "", pos)
        self.tree.heading(col, command=lambda: self.sort_tree(col, not reverse))

    def export_csv(self):
        if not self.all_rows:
            messagebox.showinfo("提示", "没有可导出的结果")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV 文件", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["Method","URL","Status","Time(ms)","Length","Matches"])
            rows = self.filtered_rows or self.all_rows
            w.writerows(rows)
        messagebox.showinfo("导出完成", f"已导出 {path}")

    def clear_table(self):
        self.tree.delete(*self.tree.get_children())
        self.all_rows.clear()
        self.filtered_rows.clear()
        self.responses.clear()

    def show_detail(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel, "values")
        method, url, status = vals[0], vals[1], vals[2]
        rec = self.responses.get(url)
        if not rec:
            messagebox.showinfo("提示", "暂无该请求的响应详情")
            return
        headers, body, st, m = rec if len(rec)>=4 else (rec[0], rec[1], rec[2], "")
        win = tk.Toplevel(self.root)
        win.title(f"Details - {url}")
        win.geometry("900x600")
        info = tk.Label(win, text=f"Method: {method}    Status: {status}", anchor="w")
        info.pack(fill=tk.X, padx=6, pady=4)
        hbox = ScrolledText(win, height=10)
        hbox.pack(fill=tk.X, padx=6, pady=4)
        if isinstance(headers, dict):
            hbox.insert(tk.END, "\n".join([f"{k}: {v}" for k,v in headers.items()]))
        else:
            hbox.insert(tk.END, str(headers))
        bbox = ScrolledText(win)
        bbox.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)
        try:
            bbox.insert(tk.END, body if isinstance(body, str) else str(body))
        except:
            bbox.insert(tk.END, "[无法以文本显示响应体]")

# ---------- run ----------
if __name__ == "__main__":
    root = tk.Tk()
    app = URLTesterApp(root)
    root.mainloop()
