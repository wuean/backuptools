# -*- coding: utf-8 -*-
"""
BackupTool —— 系统自带压缩备份工具（ZIP，无需 WinRAR）v2
作者：乐福学长    网站：https://lefuo.com    仓库：https://github.com/wuean/backuptools

改进（相对 v1）：
  - 保留策略可设置：保留天数 + 最多条数 双上限（默认 30 天 / 10 条）
  - 备份进度条 + 当前文件显示，失败多重提醒
  - 备份后自动校验 zip 完整性，损坏包删除重报
  - 运行日志 backup_log.txt（超 1MB 轮转）
  - 密码不落盘：界面输入不保存，留空 = 默认密码 123456

命令行：
  BackupTool.exe           正常打开图形界面
  BackupTool.exe --silent  读取已保存配置，无人值守执行备份
"""

import os
import sys
import json
import struct
import zlib
import fnmatch
import subprocess
from datetime import datetime, timedelta

CONFIG_NAME = "backup_config.json"
LOG_NAME = "backup_log.txt"
LOG_MAX = 1024 * 1024
DEFAULT_PASSWORD = "123456"

# ---------------- 路径 ----------------

def app_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def config_path():
    return os.path.join(app_dir(), CONFIG_NAME)

# ---------------- 配置 ----------------

DEFAULT_CFG = {
    "source_dir": "",
    "backup_dir": "",
    "pattern": "*.GTJ",
    "retain_days": 30,
    "retain_count": 10,
    "run_on_logon": False,
    "run_daily": False,
    "daily_time": "03:00",
}


def load_config():
    cfg = dict(DEFAULT_CFG)
    try:
        with open(config_path(), "r", encoding="utf-8-sig") as f:
            saved = json.load(f)
        if isinstance(saved, dict):
            cfg.update({k: v for k, v in saved.items() if k in DEFAULT_CFG})
    except Exception:
        pass
    # v1 配置里的 password 字段忽略不读、不回写（密码不落盘）
    return cfg


def save_config(cfg):
    clean = {k: cfg.get(k, DEFAULT_CFG[k]) for k in DEFAULT_CFG}
    with open(config_path(), "w", encoding="utf-8") as f:
        json.dump(clean, f, ensure_ascii=False, indent=2)

# ---------------- 日志 ----------------

def log_path():
    return os.path.join(app_dir(), LOG_NAME)


def write_log(msg):
    """追加一行带时间戳的运行日志；超 1MB 轮转只留最近一份。"""
    try:
        fp = log_path()
        try:
            if os.path.exists(fp) and os.path.getsize(fp) > LOG_MAX:
                os.replace(fp, fp + ".old")
        except Exception:
            pass
        with open(fp, "a", encoding="utf-8") as f:
            f.write("[%s] %s\r\n" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg))
    except Exception:
        pass

# ---------------- 文件收集 ----------------

def collect_files(source_dir, pattern):
    """递归收集匹配文件。pattern 为空 / * / *.* 时收集全部文件。"""
    pat = (pattern or "").strip()
    if pat in ("", "*", "*.*"):
        pat = None
    files = []
    for root, _dirs, fnames in os.walk(source_dir):
        for fn in fnames:
            if pat is None or fnmatch.fnmatch(fn.lower(), pat.lower()):
                files.append(os.path.join(root, fn))
    return files

# ---------------- 旧备份清理 ----------------

def clean_old(backup, retain_days, retain_count, log_fn=None):
    """删除 backup*.zip 中早于 retain_days 天的文件；再按条数上限删最旧的。
    retain_days<=0 表示不限天数；retain_count<=0 表示不限条数。"""
    def log(msg):
        write_log(msg)
        if log_fn:
            log_fn(msg)

    zips = []
    try:
        for fn in os.listdir(backup):
            low = fn.lower()
            if low.startswith("backup") and low.endswith(".zip"):
                fp = os.path.join(backup, fn)
                try:
                    zips.append((os.path.getmtime(fp), fn, fp))
                except OSError:
                    continue
    except Exception as e:
        log("清理旧备份出错：" + str(e))
        return

    deleted = 0
    # 规则一：超期即删
    if retain_days and retain_days > 0:
        cutoff = datetime.now() - timedelta(days=retain_days)
        for mtime, fn, fp in list(zips):
            if datetime.fromtimestamp(mtime) < cutoff:
                try:
                    os.remove(fp)
                    zips.remove((mtime, fn, fp))
                    deleted += 1
                    log("已删除过期备份：" + fn)
                except Exception as e:
                    log("删除失败 %s: %s" % (fn, e))

    # 规则二：条数上限，从最旧删起
    if retain_count and retain_count > 0 and len(zips) > retain_count:
        zips.sort()
        for mtime, fn, fp in zips[: len(zips) - retain_count]:
            try:
                os.remove(fp)
                deleted += 1
                log("已删除超量旧备份：" + fn)
            except Exception as e:
                log("删除失败 %s: %s" % (fn, e))

    if deleted:
        log("共清理 %d 个旧备份（保留 %d 天 / 最多 %d 条）" % (deleted, retain_days, retain_count))

# ---------------- ZipCrypto（与 v1 相同的手写实现）----------------

def _crc32_step(c, b):
    """PKZIP 单字节 CRC 更新：(c>>8) ^ table[(c^b)&0xFF]。"""
    return zlib.crc32(bytes([b]), c ^ 0xFFFFFFFF) ^ 0xFFFFFFFF


class _ZipCrypto:
    """PKWARE ZipCrypto 流密码（Windows 资源管理器原生支持）。"""

    def __init__(self, pwd):
        self.keys = [0x12345678, 0x23456789, 0x34567890]
        for b in pwd:
            self._update(b)

    def _update(self, b):
        k = self.keys
        k[0] = _crc32_step(k[0], b)
        k[1] = ((k[1] + (k[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k[2] = _crc32_step(k[2], (k[1] >> 24) & 0xFF)

    def encrypt(self, b):
        out = bytearray()
        for ch in b:
            k = self.keys
            temp = (k[2] | 2) & 0xFFFF
            out.append(ch ^ (((temp * (temp ^ 1)) >> 8) & 0xFF))
            self._update(ch)
        return bytes(out)


def _dos_dt(dt):
    y = max(dt.year, 1980)
    d = ((y - 1980) << 9) | (dt.month << 5) | dt.day
    t = (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)
    return t, d

# ---------------- 压缩（带进度回调）----------------

def build_backup_zip(zip_path, source, files, password, progress=None):
    """手写标准 ZIP（deflate 流式压缩），可选 ZipCrypto 密码。返回 (写入文件数, 字节数, 跳过列表)。
    progress(done_bytes, total_bytes, current_name) 按已压缩字节回调，进度条实时推进。
    单个文件读失败：跳过并记日志，不中断整体。"""
    pwd = password.encode("utf-8") if password else None
    central = []
    written = 0
    skipped = []
    CHUNK = 1024 * 1024
    sizes = []
    for fp in files:
        try:
            sizes.append(os.path.getsize(fp))
        except OSError:
            sizes.append(0)
    total_bytes = sum(sizes) or 1
    done_bytes = 0
    with open(zip_path, "wb") as out:
        offset = 0
        for idx, fp in enumerate(files):
            name = os.path.relpath(fp, source).replace(os.sep, "/")
            try:
                crc = 0
                co = zlib.compressobj(9, zlib.DEFLATED, -15)
                parts = []
                size = 0
                with open(fp, "rb") as f:
                    while True:
                        buf = f.read(CHUNK)
                        if not buf:
                            break
                        crc = zlib.crc32(buf, crc)
                        parts.append(co.compress(buf))
                        size += len(buf)
                        done_bytes += len(buf)
                        parts.append(co.flush(zlib.Z_SYNC_FLUSH))
                        if progress:
                            progress(done_bytes, total_bytes, name)
                parts.append(co.flush(zlib.Z_FINISH))
                comp = b"".join(parts)
                crc &= 0xFFFFFFFF
            except Exception as e:
                msg = "跳过无法读取的文件 %s: %s" % (fp, e)
                write_log(msg)
                skipped.append(fp)
                done_bytes += sizes[idx]
                if progress:
                    progress(min(done_bytes, total_bytes), total_bytes, name + "（跳过）")
                continue

            dt = datetime.fromtimestamp(os.path.getmtime(fp))
            t, d = _dos_dt(dt)
            method = 8
            flag = 0
            data = comp
            if pwd:
                cipher = _ZipCrypto(pwd)  # 每个文件重新初始化（标准要求）
                flag |= 1
                header = bytearray(os.urandom(11))
                header.append((crc >> 24) & 0xFF)
                stream = bytes(header) + comp
                data = cipher.encrypt(stream)
            name_b = name.encode("utf-8")
            lh = struct.pack("<IHHHHHIIIHH", 0x04034b50, 20, flag, method, t, d,
                             crc, len(data), size, len(name_b), 0)
            out.write(lh)
            out.write(name_b)
            out.write(data)
            cd = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014b50, 20, 20, flag, method,
                             t, d, crc, len(data), size, len(name_b),
                             0, 0, 0, 0, 0, offset)
            central.append((cd, name_b))
            offset += len(lh) + len(name_b) + len(data)
            written += 1

        cd_offset = offset
        cd_size = 0
        for cd, name_b in central:
            out.write(cd)
            out.write(name_b)
            cd_size += len(cd) + len(name_b)
        eocd = struct.pack("<IHHHHIIH", 0x06054b50, 0, 0, len(central),
                           len(central), cd_size, cd_offset, 0)
        out.write(eocd)
        expected_size = offset + cd_size + len(eocd)
    return written, os.path.getsize(zip_path), skipped, expected_size

# ---------------- 完整性校验 ----------------

def verify_zip(zip_path, password, expected_size=None):
    """轻量校验 zip 可用性：文件大小一致、中央目录可解析、每个条目密码头与
    deflate 流开头可解。不全量逐字节解密（大加密包会耗时数分钟）。返回 (ok, err)。"""
    try:
        from zipfile import ZipFile
        pwd = password.encode("utf-8") if password else None
        # 1. 大小一致：能发现写到一半中断/磁盘满导致的截断
        if expected_size is not None:
            real = os.path.getsize(zip_path)
            if real != expected_size:
                return False, "文件大小异常：期望 %d 字节，实际 %d 字节（可能写入中断）" % (
                    expected_size, real)
        # 2. 结构：中央目录可解析（能发现 EOCD/目录损坏）
        with ZipFile(zip_path) as zf:
            infos = zf.infolist()
            if not infos:
                return False, "备份包内没有任何文件"
            # 3. 密码头 + 流开头：抽样读每个条目前 64KB
            for info in infos:
                if info.compress_size == 0:
                    continue
                with zf.open(info, pwd=pwd) as f:
                    if f.read(65536) is None:
                        return False, "无法读取条目：%s" % info.filename
        return True, ""
    except Exception as e:
        return False, str(e)

# ---------------- 备份主流程 ----------------

def run_backup(cfg, log_fn=None, password="", progress=None):
    """执行一次备份。返回 (success: bool, summary: str)。"""
    def log(msg):
        write_log(msg)
        if log_fn:
            log_fn(msg)

    source = cfg.get("source_dir", "")
    backup = cfg.get("backup_dir", "")
    pattern = cfg.get("pattern", "*.GTJ")
    pwd = (password or "").strip() or DEFAULT_PASSWORD
    try:
        retain_days = int(cfg.get("retain_days", 30))
    except Exception:
        retain_days = 30
    try:
        retain_count = int(cfg.get("retain_count", 10))
    except Exception:
        retain_count = 10

    if not source or not os.path.isdir(source):
        log("错误：源目录不存在：" + str(source))
        return False, "源目录不存在，请检查设置。"
    if not backup:
        log("错误：备份目录未设置")
        return False, "备份目录未设置。"

    os.makedirs(backup, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_path = os.path.join(backup, "backup%s.zip" % ts)

    log("=== 开始备份：%s -> %s（类型 %s）===" % (source, zip_path, pattern or "全部"))
    log("正在扫描源目录…")
    files = collect_files(source, pattern)
    if not files:
        msg = "未找到匹配文件（%s），跳过本次备份。" % (pattern or "全部")
        log(msg)
        clean_old(backup, retain_days, retain_count, log_fn)
        return False, msg
    log("扫描完成：找到 %d 个匹配文件，共 %.1f MB" %
        (len(files), sum(os.path.getsize(f) for f in files if os.path.exists(f)) / 1048576))

    log("开始压缩 %d 个文件 -> %s（ZipCrypto 密码保护）" % (len(files), os.path.basename(zip_path)))
    try:
        written, size, skipped, expected_size = build_backup_zip(
            zip_path, source, files, pwd, progress)
    except Exception as e:
        log("压缩失败：" + str(e))
        try:
            if os.path.exists(zip_path):
                os.remove(zip_path)
                log("已删除损坏的备份包：" + os.path.basename(zip_path))
        except Exception:
            pass
        return False, "压缩失败：" + str(e)

    log("压缩完成：%s (%.2f MB，%d 个文件，跳过 %d 个)" %
        (os.path.basename(zip_path), size / 1024 / 1024, written, len(skipped)))

    # 完整性校验（轻量：结构 + 大小一致 + 密码头，避免大加密包全量解密卡死）
    ok, err = verify_zip(zip_path, pwd, expected_size)
    if not ok:
        log("校验失败，已删除损坏备份包 %s：%s" % (os.path.basename(zip_path), err))
        try:
            os.remove(zip_path)
        except Exception:
            pass
        return False, "备份包校验失败已删除：%s" % err

    log("校验通过：备份包结构、大小、密码均正常")

    clean_old(backup, retain_days, retain_count, log_fn)
    summary = "备份完成：%s（%d 个文件，%.2f MB）" % (
        os.path.basename(zip_path), len(files), size / 1024 / 1024)
    if skipped:
        summary += "（注意：%d 个文件被跳过，详见 backup_log.txt）" % len(skipped)
    log(summary)
    return True, summary

# ---------------- 系统弹窗 ----------------

def popup(title, msg, error=False):
    """系统级弹窗（无需 GUI 主窗口也能显示）。"""
    try:
        import ctypes
        style = 0x40 if not error else 0x10
        ctypes.windll.user32.MessageBoxW(0, msg, title, style)
    except Exception:
        pass

# ---------------- 计划任务 ----------------

def register_tasks(cfg, log_fn=None):
    """注册任务计划：开机自动备份 + 每日定时备份。"""
    exe = os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__)
    tr = '"%s" --silent' % exe
    created = []
    if cfg.get("run_on_logon"):
        cmd = ["schtasks", "/create", "/tn", "BackupTool_Logon",
               "/tr", tr, "/sc", "onlogon", "/f"]
        created.append(("开机自动备份", subprocess.run(cmd, capture_output=True, text=True)))
    if cfg.get("run_daily"):
        st = cfg.get("daily_time", "03:00")
        cmd = ["schtasks", "/create", "/tn", "BackupTool_Daily",
               "/tr", tr, "/sc", "daily", "/st", st, "/f"]
        created.append(("每日定时备份(%s)" % st, subprocess.run(cmd, capture_output=True, text=True)))
    for name, r in created:
        out = (r.stderr or r.stdout or "").strip()
        if r.returncode == 0:
            if log_fn:
                log_fn("已创建计划任务：%s" % name)
            write_log("已创建计划任务：%s" % name)
        else:
            if log_fn:
                log_fn("创建计划任务失败（%s）：%s" % (name, out))
                log_fn("提示：创建开机/定时任务通常需要以【管理员身份】运行本程序。")
            write_log("创建计划任务失败（%s）：%s" % (name, out))


def remove_tasks(log_fn=None):
    for tn in ("BackupTool_Logon", "BackupTool_Daily"):
        r = subprocess.run(["schtasks", "/delete", "/tn", tn, "/f"],
                           capture_output=True, text=True)
        if r.returncode == 0:
            if log_fn:
                log_fn("已删除计划任务：%s" % tn)
            write_log("已删除计划任务：%s" % tn)
        else:
            if log_fn:
                log_fn("计划任务 %s 不存在或删除失败（可忽略）。" % tn)


# ---------------- GUI ----------------

def build_gui():
    import threading
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    cfg = load_config()

    root = tk.Tk()
    root.title("BackupTool 备份工具 - 乐福学长")
    root.geometry("680x560")

    v_source = tk.StringVar(value=cfg["source_dir"])
    v_backup = tk.StringVar(value=cfg["backup_dir"])
    v_pattern = tk.StringVar(value=cfg["pattern"])
    v_days = tk.StringVar(value=str(cfg["retain_days"]))
    v_count = tk.StringVar(value=str(cfg["retain_count"]))
    v_pwd = tk.StringVar(value="")
    v_logon = tk.BooleanVar(value=cfg["run_on_logon"])
    v_daily = tk.BooleanVar(value=cfg["run_daily"])
    v_time = tk.StringVar(value=cfg["daily_time"])

    frm = ttk.Frame(root, padding=10)
    frm.pack(fill="both", expand=True)

    def log_fn(msg):
        # 备份在后台线程执行，tkinter 控件只能在主线程更新，
        # 必须经 root.after 调度，否则跨线程操作会死锁卡死界面。
        def _append():
            log_text.configure(state="normal")
            log_text.insert("end", msg + "\n")
            log_text.see("end")
            log_text.configure(state="disabled")
        try:
            root.after(0, _append)
        except Exception:
            pass

    def pick_source():
        d = filedialog.askdirectory(title="选择源目录")
        if d:
            v_source.set(d.replace("/", "\\"))

    def pick_backup():
        d = filedialog.askdirectory(title="选择备份目录")
        if d:
            v_backup.set(d.replace("/", "\\"))

    busy = {"on": False}

    def on_progress(done_bytes, total_bytes, name):
        mb = 1024 * 1024
        def _u():
            progress_var.set(done_bytes * 100 / max(total_bytes, 1))
            status_var.set("正在压缩 %.1f/%.1f MB：%s" %
                           (done_bytes / mb, total_bytes / mb, name))
        try:
            root.after(0, _u)
        except Exception:
            pass

    def do_backup():
        if busy["on"]:
            return
        cfg_now = collect()
        busy["on"] = True
        btn_backup.configure(state="disabled")
        progress_var.set(0)
        status_var.set("开始备份…")
        log_fn("=== 开始备份 ===")

        def job():
            try:
                ok, summary = run_backup(cfg_now, log_fn, password=v_pwd.get(),
                                         progress=on_progress)
            except Exception as e:
                ok, summary = False, "备份出错：" + str(e)
            def _done():
                progress_var.set(100 if ok else 0)
                status_var.set("完成" if ok else "失败")
                log_fn(summary)
                log_fn("=== 结束 ===")
                btn_backup.configure(state="normal")
                busy["on"] = False
                if ok:
                    popup("备份完成 - 乐福学长", summary)
                else:
                    popup("备份失败 - 乐福学长", summary + "\n\n详见程序目录 backup_log.txt。", error=True)
            root.after(0, _done)

        threading.Thread(target=job, daemon=True).start()

    def collect():
        return {
            "source_dir": v_source.get().strip(),
            "backup_dir": v_backup.get().strip(),
            "pattern": v_pattern.get().strip(),
            "retain_days": v_days.get().strip() or "30",
            "retain_count": v_count.get().strip() or "10",
            "run_on_logon": v_logon.get(),
            "run_daily": v_daily.get(),
            "daily_time": v_time.get().strip() or "03:00",
        }

    def save():
        save_config(collect())
        log_fn("配置已保存（密码不保存）。")

    def apply_schedule():
        log_fn("=== 应用计划任务 ===（如需修改，先点“取消计划”再重新应用）")
        save()
        register_tasks(collect(), log_fn)

    def cancel_schedule():
        log_fn("=== 取消计划任务 ===")
        remove_tasks(log_fn)

    def show_about():
        messagebox.showinfo(
            "关于 BackupTool",
            "BackupTool 备份工具\n"
            "作者：乐福学长\n"
            "网站：https://lefuo.com\n"
            "源码仓库：https://github.com/wuean/backuptools\n\n"
            "功能说明：\n"
            "本软件采用系统自带 ZIP 压缩，无需安装 WinRAR 等外部工具。\n"
            "支持源/备份目录选择、文件类型过滤、定时与开机自动备份、\n"
            "备份进度显示、完成后自动校验、运行日志（backup_log.txt）、\n"
            "以及压缩包密码保护。\n\n"
            "压缩密码：在界面输入，不保存；留空时使用默认密码 123456。\n"
            "备份保留策略：默认保留 30 天、最多 10 条，可自行修改。\n\n"
            "Copyright © 乐福学长. All rights reserved.")

    # ---- 布局 ----
    row = 0
    ttk.Label(frm, text="源目录：").grid(row=row, column=0, sticky="e", padx=5, pady=4)
    ttk.Entry(frm, textvariable=v_source, width=52).grid(row=row, column=1, padx=5)
    ttk.Button(frm, text="浏览…", command=pick_source).grid(row=row, column=2, padx=5)

    row += 1
    ttk.Label(frm, text="备份目录：").grid(row=row, column=0, sticky="e", padx=5, pady=4)
    ttk.Entry(frm, textvariable=v_backup, width=52).grid(row=row, column=1, padx=5)
    ttk.Button(frm, text="浏览…", command=pick_backup).grid(row=row, column=2, padx=5)

    row += 1
    ttk.Label(frm, text="文件类型：").grid(row=row, column=0, sticky="e", padx=5, pady=4)
    ttk.Entry(frm, textvariable=v_pattern, width=20).grid(row=row, column=1, sticky="w")
    ttk.Label(frm, text="（默认 *.GTJ，留空=全部）").grid(row=row, column=2, sticky="w")

    row += 1
    ttk.Label(frm, text="保留天数：").grid(row=row, column=0, sticky="e", padx=5, pady=4)
    ttk.Entry(frm, textvariable=v_days, width=8).grid(row=row, column=1, sticky="w")
    ttk.Label(frm, text="（删除 N 天前的 backup*.zip）").grid(row=row, column=2, sticky="w")

    row += 1
    ttk.Label(frm, text="最多保留：").grid(row=row, column=0, sticky="e", padx=5, pady=4)
    ttk.Entry(frm, textvariable=v_count, width=8).grid(row=row, column=1, sticky="w")
    ttk.Label(frm, text="（超出条数从最旧删起）").grid(row=row, column=2, sticky="w")

    row += 1
    ttk.Label(frm, text="压缩密码：").grid(row=row, column=0, sticky="e", padx=5, pady=4)
    ttk.Entry(frm, textvariable=v_pwd, width=20, show="*").grid(row=row, column=1, sticky="w")
    ttk.Label(frm, text="（不保存；留空=默认密码 123456）").grid(row=row, column=2, sticky="w")

    row += 1
    ttk.Label(frm, text="自动备份设置：").grid(row=row, column=0, sticky="ne", padx=5, pady=(4, 4))
    auto = ttk.Frame(frm)
    auto.grid(row=row, column=1, columnspan=2, sticky="w")
    ttk.Checkbutton(auto, text="开机自动备份（登录后执行）", variable=v_logon).pack(anchor="w")
    daily_row = ttk.Frame(auto)
    daily_row.pack(anchor="w")
    ttk.Checkbutton(daily_row, text="每日定时备份", variable=v_daily).pack(side="left")
    ttk.Label(daily_row, text="  时间(HH:MM)：").pack(side="left")
    ttk.Entry(daily_row, textvariable=v_time, width=8).pack(side="left")
    ttk.Label(auto, text="注：注册任务计划通常需要以管理员身份运行本程序。").pack(anchor="w")

    row += 1
    btns = ttk.Frame(frm)
    btns.grid(row=row, column=0, columnspan=3, pady=8)
    btn_backup = ttk.Button(btns, text="开始备份", command=do_backup)
    btn_backup.pack(side="left", padx=6)
    ttk.Button(btns, text="保存配置", command=save).pack(side="left", padx=6)
    ttk.Button(btns, text="应用计划", command=apply_schedule).pack(side="left", padx=6)
    ttk.Button(btns, text="取消计划", command=cancel_schedule).pack(side="left", padx=6)
    ttk.Button(btns, text="关于", command=show_about).pack(side="left", padx=6)

    row += 1
    progress_var = tk.DoubleVar(value=0)
    status_var = tk.StringVar(value="欢迎使用 BackupTool。设置好后点击“开始备份”。")
    ttk.Progressbar(frm, variable=progress_var, maximum=100).grid(
        row=row, column=0, columnspan=3, sticky="ew", padx=5, pady=4)
    row += 1
    ttk.Label(frm, textvariable=status_var, foreground="#555").grid(
        row=row, column=0, columnspan=3, sticky="w", padx=5)

    row += 1
    ttk.Label(frm, text="日志：").grid(row=row, column=0, sticky="w", padx=5, pady=4)
    row += 1
    log_text = tk.Text(frm, height=6, width=80, state="disabled")
    log_text.grid(row=row, column=0, columnspan=3, padx=5, pady=4, sticky="nsew")
    frm.rowconfigure(row, weight=1)
    frm.columnconfigure(1, weight=1)

    link = tk.Label(root, text="作者：乐福学长    网站：https://lefuo.com    源码：github.com/wuean/backuptools",
                    fg="blue", cursor="hand2")
    link.pack(pady=4)
    link.bind("<Button-1>", lambda e: _open_url("https://lefuo.com"))

    root.mainloop()


def _open_url(url):
    try:
        os.startfile(url)
    except Exception:
        pass


# ---------------- 入口 ----------------

def main():
    if "--silent" in sys.argv:
        cfg = load_config()
        if not cfg.get("source_dir") or not os.path.isdir(cfg.get("source_dir", "")):
            write_log("--silent：备份配置不完整或源目录不存在，跳过。")
            popup("BackupTool - 乐福学长",
                  "备份配置不完整或源目录不存在，请先打开 BackupTool 设置并保存。",
                  error=True)
            return
        ok, summary = run_backup(cfg, password="")  # silent 模式：默认密码
        popup("备份完成 - 乐福学长" if ok else "备份失败 - 乐福学长",
              summary + ("\n" if ok else "\n\n详见程序目录 backup_log.txt。"),
              error=not ok)
        return
    build_gui()


if __name__ == "__main__":
    main()
