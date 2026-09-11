"""
TEST.py - Single-file Telegram Hosting & File Manager Bot
Python 3.11+

Install:
    pip install python-telegram-bot python-dotenv psutil httpx

Configure .env:
    BOT_TOKEN=...
    ADMIN_ID=...
    DATA_DIR=./data
    AI_API_KEY=
    AI_BASE_URL=https://api.openai.com/v1
    AI_MODEL=gpt-4o-mini
    MAX_UPLOAD_MB=100
    DEFAULT_STORAGE_MB=500
    MAX_PROCESSES=1

Run:
    python TEST.py

Production note:
This file is a control-panel bot. Running untrusted user applications directly
on the host is NOT a sufficient security boundary. Use a dedicated unprivileged
service/container/VM with cgroups, network policy and mandatory access controls
before offering arbitrary third-party code execution.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import secrets
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
import zipfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx
import psutil
from dotenv import load_dotenv
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# ============================================================
# CONFIG
# ============================================================

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
ADMIN_ID = int(os.getenv("ADMIN_ID", "0") or 0)
DATA_DIR = Path(os.getenv("DATA_DIR", "./data")).resolve()
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "100"))
DEFAULT_STORAGE_MB = int(os.getenv("DEFAULT_STORAGE_MB", "500"))
DEFAULT_PROCESS_LIMIT = int(os.getenv("MAX_PROCESSES", "1"))
AI_API_KEY = os.getenv("AI_API_KEY", "").strip()
AI_BASE_URL = os.getenv("AI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
AI_MODEL = os.getenv("AI_MODEL", "gpt-4o-mini")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is missing. Put it in .env")

DATA_DIR.mkdir(parents=True, exist_ok=True)
USERS_DIR = DATA_DIR / "users"
USERS_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "bot.sqlite3"

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
log = logging.getLogger("hosting-bot")

# ============================================================
# DATABASE
# ============================================================

SCHEMA = """
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS plans (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    storage_mb INTEGER NOT NULL,
    process_limit INTEGER NOT NULL,
    website INTEGER NOT NULL DEFAULT 0,
    git_clone INTEGER NOT NULL DEFAULT 0,
    api_access INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT,
    name TEXT,
    plan_id INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    banned INTEGER NOT NULL DEFAULT 0,
    subscription_expiry TEXT,
    FOREIGN KEY(plan_id) REFERENCES plans(id)
);

CREATE TABLE IF NOT EXISTS processes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    pid INTEGER,
    command TEXT NOT NULL,
    status TEXT NOT NULL,
    log_path TEXT,
    started_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_process_user ON processes(user_id);

CREATE TABLE IF NOT EXISTS websites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    root_path TEXT NOT NULL,
    port INTEGER,
    status TEXT NOT NULL DEFAULT 'STOPPED',
    process_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    key_hash TEXT NOT NULL,
    prefix TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_api_user ON api_keys(user_id);

CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    plan_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    external_id TEXT,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    details TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init_db():
    with closing(db()) as con:
        con.executescript(SCHEMA)
        con.execute(
            "INSERT OR IGNORE INTO plans "
            "(id,name,storage_mb,process_limit,website,git_clone,api_access) "
            "VALUES (1,'FREE',?,?,?,?,?)",
            (DEFAULT_STORAGE_MB, DEFAULT_PROCESS_LIMIT, 0, 0, 0),
        )
        con.execute(
            "INSERT OR IGNORE INTO plans "
            "(id,name,storage_mb,process_limit,website,git_clone,api_access) "
            "VALUES (2,'PRO',5120,5,1,1,1)"
        )
        con.execute(
            "INSERT OR IGNORE INTO plans "
            "(id,name,storage_mb,process_limit,website,git_clone,api_access) "
            "VALUES (3,'PREMIUM',20480,10,1,1,1)"
        )
        con.commit()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def audit(user_id, action, details=""):
    with closing(db()) as con:
        con.execute(
            "INSERT INTO audit_logs(user_id,action,details,created_at) VALUES(?,?,?,?)",
            (user_id, action, details[:1000], now_iso()),
        )
        con.commit()


def ensure_user(tg_user):
    with closing(db()) as con:
        con.execute(
            "INSERT OR IGNORE INTO users(id,username,name,created_at) VALUES(?,?,?,?)",
            (tg_user.id, tg_user.username, tg_user.full_name, now_iso()),
        )
        con.execute(
            "UPDATE users SET username=?, name=? WHERE id=?",
            (tg_user.username, tg_user.full_name, tg_user.id),
        )
        con.commit()
    user_root(tg_user.id)


def user_record(user_id):
    with closing(db()) as con:
        return con.execute(
            """SELECT u.*, p.name plan_name, p.storage_mb, p.process_limit,
                      p.website, p.git_clone, p.api_access
               FROM users u JOIN plans p ON p.id=u.plan_id
               WHERE u.id=?""",
            (user_id,),
        ).fetchone()


# ============================================================
# SECURITY / FILESYSTEM
# ============================================================

VALID_NAME = re.compile(r"^[A-Za-z0-9._() @+-]{1,180}$")
ALLOWED_RUN_EXT = {".py", ".js"}
ALLOWED_GIT_HOSTS = {"github.com", "gitlab.com", "codeberg.org"}
ALLOWED_PACKAGES = {
    "requests",
    "flask",
    "fastapi",
    "discord.py",
    "pyTelegramBotAPI",
    "aiogram",
}
SAFE_PORTS = set(range(8000, 8101))


def user_root(user_id: int) -> Path:
    root = (USERS_DIR / str(int(user_id))).resolve()
    root.mkdir(parents=True, exist_ok=True)
    for name in ("files", "logs", "websites", "processes"):
        (root / name).mkdir(exist_ok=True)
    return root


def files_root(user_id: int) -> Path:
    return user_root(user_id) / "files"


def safe_name(name: str) -> str:
    name = Path(name or "").name
    if name in {".", ".."} or not VALID_NAME.fullmatch(name):
        raise ValueError("Invalid filename")
    return name


def safe_rel(user_id: int, relative: str) -> Path:
    root = files_root(user_id).resolve()
    rel = str(relative or ".").replace("\\", "/")
    candidate = (root / rel).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        raise ValueError("Path traversal blocked")
    return candidate


def relative_display(user_id: int, path: Path) -> str:
    root = files_root(user_id).resolve()
    return str(path.resolve().relative_to(root)).replace("\\", "/")


def storage_used(user_id: int) -> int:
    total = 0
    root = files_root(user_id)
    for p in root.rglob("*"):
        try:
            if p.is_file():
                total += p.stat().st_size
        except OSError:
            pass
    return total


def count_files(user_id: int) -> int:
    return sum(1 for p in files_root(user_id).rglob("*") if p.is_file())


def human_size(n: int) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{n} B"


# ============================================================
# KEYBOARDS
# ============================================================

def main_keyboard():
    rows = [
        [("📢 Updates", "updates"), ("🌐 Upload", "upload")],
        [("📁 My Files", "files"), ("⚡ Bot Speed", "speed")],
        [("🚀 Status", "status"), ("▶️ Processes", "processes")],
        [("🔄 Restart", "proc_refresh"), ("⏹ Stop", "proc_refresh")],
        [("⚙️ Recommended Install", "install"), ("🤖 AI Agent", "ai")],
        [("🔤 Font Generator", "font"), ("🆘 Help", "help")],
        [("🌐 Git Clone", "git"), ("📞 Contact Owner", "contact")],
        [("📱 WhatsApp Bot", "whatsapp"), ("🟣 Discord Bot", "discord")],
        [("🚀 API", "api"), ("🌍 Website", "website")],
        [("💻 Local Host", "localhost"), ("💳 Buy Plan", "plans")],
        [("🛒 Store", "store"), ("👤 My Account", "account")],
    ]
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton(a, callback_data=b) for a, b in row] for row in rows]
    )


def back_home_keyboard():
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("🏠 Main Menu", callback_data="home")]]
    )


def files_keyboard(rel="."):
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("⬆️ Upload", callback_data="upload"),
                InlineKeyboardButton("📁 New Folder", callback_data="newfolder"),
            ],
            [
                InlineKeyboardButton("🔄 Refresh", callback_data=f"files:{rel}"),
                InlineKeyboardButton("🏠 Home", callback_data="home"),
            ],
        ]
    )


# ============================================================
# PROCESS MANAGER
# ============================================================

RUNNING = {}


def running_count(user_id):
    return sum(
        1
        for x in RUNNING.values()
        if x["user_id"] == user_id and x["process"].returncode is None
    )


async def start_process(user_id: int, rel: str):
    rec = user_record(user_id)
    if not rec:
        raise ValueError("User not found")

    if running_count(user_id) >= rec["process_limit"]:
        raise ValueError("Your process limit has been reached.")

    path = safe_rel(user_id, rel)
    if not path.is_file():
        raise ValueError("File not found.")
    if path.suffix.lower() not in ALLOWED_RUN_EXT:
        raise ValueError("Only Python and Node.js entry files are supported.")

    if path.suffix.lower() == ".js":
        executable = "node"
        command = [executable, str(path)]
    else:
        executable = sys.executable
        command = [executable, "-u", str(path)]

    if path.suffix.lower() == ".js" and shutil.which("node") is None:
        raise RuntimeError("Node.js is not installed on the server.")

    log_file = user_root(user_id) / "logs" / f"{path.stem}.log"
    log_file.parent.mkdir(exist_ok=True)

    f = open(log_file, "ab", buffering=0)
    env = {
        "PATH": os.getenv("PATH", ""),
        "HOME": str(user_root(user_id)),
        "PYTHONUNBUFFERED": "1",
    }

    process = await asyncio.create_subprocess_exec(
        *command,
        cwd=str(path.parent),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=f,
        stderr=asyncio.subprocess.STDOUT,
        env=env,
        start_new_session=True,
    )

    RUNNING[process.pid] = {
        "user_id": user_id,
        "process": process,
        "file": rel,
        "log": log_file,
        "file_handle": f,
        "started": time.time(),
    }

    with closing(db()) as con:
        con.execute(
            """INSERT INTO processes
               (user_id,name,pid,command,status,log_path,started_at)
               VALUES(?,?,?,?,?,?,?)""",
            (
                user_id,
                path.name,
                process.pid,
                " ".join(command),
                "RUNNING",
                str(log_file),
                now_iso(),
            ),
        )
        con.commit()

    audit(user_id, "process_start", path.name)
    return process.pid


async def stop_process(user_id: int, pid: int):
    info = RUNNING.get(pid)
    if not info or info["user_id"] != user_id:
        raise ValueError("Process not found or not owned by you.")

    proc = info["process"]
    try:
        proc.terminate()
        await asyncio.wait_for(proc.wait(), timeout=5)
    except (ProcessLookupError, asyncio.TimeoutError):
        if proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
    finally:
        try:
            info["file_handle"].close()
        except Exception:
            pass

    with closing(db()) as con:
        con.execute(
            "UPDATE processes SET status='STOPPED' WHERE user_id=? AND pid=?",
            (user_id, pid),
        )
        con.commit()
    RUNNING.pop(pid, None)
    audit(user_id, "process_stop", str(pid))


async def process_watcher():
    while True:
        for pid, info in list(RUNNING.items()):
            proc = info["process"]
            if proc.returncode is not None:
                try:
                    info["file_handle"].close()
                except Exception:
                    pass
                with closing(db()) as con:
                    con.execute(
                        "UPDATE processes SET status='STOPPED' WHERE user_id=? AND pid=?",
                        (info["user_id"], pid),
                    )
                    con.commit()
                RUNNING.pop(pid, None)
        await asyncio.sleep(2)


# ============================================================
# FILE OPERATIONS
# ============================================================

async def render_files(query, user_id, rel="."):
    try:
        folder = safe_rel(user_id, rel)
        folder.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        return await query.edit_message_text(
            f"❌ {e}", reply_markup=back_home_keyboard()
        )

    items = sorted(folder.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
    shown = [f"📁 *MY FILES* — `{relative_display(user_id, folder) or '/'}`", ""]

    if folder != files_root(user_id):
        parent = relative_display(user_id, folder.parent) or "."
        shown.append(f"⬅️ Parent: `{parent}`")
        shown.append("")

    if not items:
        shown.append("📭 Folder is empty.")
    else:
        for p in items[:80]:
            icon = "📁" if p.is_dir() else "📄"
            shown.append(f"{icon} `{p.name}`")

    shown.append("")
    shown.append(f"💾 Used: {human_size(storage_used(user_id))}")

    await query.edit_message_text(
        "\n".join(shown)[:3900],
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=files_keyboard(relative_display(user_id, folder) or "."),
    )


# ============================================================
# AI
# ============================================================

async def ai_analyze(text: str) -> str:
    if not AI_API_KEY:
        return (
            "🤖 AI is not configured.\n\n"
            "Add `AI_API_KEY` to `.env` and restart the bot."
        )

    headers = {
        "Authorization": f"Bearer {AI_API_KEY}",
        "Content-Type": "application/json",
    }
    body = {
        "model": AI_MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a coding assistant for a hosting panel. Explain "
                    "errors, fixes, packages and safe steps. Never instruct the "
                    "bot to execute unrestricted shell commands."
                ),
            },
            {"role": "user", "content": text[:12000]},
        ],
    }

    async with httpx.AsyncClient(timeout=40) as client:
        r = await client.post(
            f"{AI_BASE_URL}/chat/completions",
            headers=headers,
            json=body,
        )
        r.raise_for_status()
        data = r.json()
        return data["choices"][0]["message"]["content"][:3900]


# ============================================================
# PACKAGE INSTALLER
# ============================================================

async def install_package(user_id: int, package: str):
    package = package.strip()
    if package not in ALLOWED_PACKAGES:
        raise ValueError("This package is not on the allowlist.")

    # IMPORTANT: This uses the server Python environment in this minimal
    # single-file edition. For production, create one venv/container per user.
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        package,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    output, _ = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(output.decode(errors="replace")[-2500:])
    audit(user_id, "package_install", package)


# ============================================================
# GIT
# ============================================================

async def git_clone(user_id: int, url: str):
    parsed = urlparse(url.strip())
    if parsed.scheme != "https" or parsed.netloc.lower() not in ALLOWED_GIT_HOSTS:
        raise ValueError("Only HTTPS GitHub/GitLab/Codeberg URLs are allowed.")

    name = Path(parsed.path.rstrip("/")).name
    if name.endswith(".git"):
        name = name[:-4]
    safe_name(name)

    target = safe_rel(user_id, name)
    if target.exists():
        raise ValueError("A folder with that name already exists.")

    proc = await asyncio.create_subprocess_exec(
        "git",
        "clone",
        "--",
        url.strip(),
        str(target),
        cwd=str(files_root(user_id)),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    output, _ = await proc.communicate()
    if proc.returncode != 0:
        shutil.rmtree(target, ignore_errors=True)
        raise RuntimeError(output.decode(errors="replace")[-2500:])

    audit(user_id, "git_clone", url)
    return name


# ============================================================
# API KEYS
# ============================================================

def create_api_key(user_id: int):
    raw = "th_" + secrets.token_urlsafe(32)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    with closing(db()) as con:
        con.execute(
            "INSERT INTO api_keys(user_id,key_hash,prefix,created_at) VALUES(?,?,?,?)",
            (user_id, digest, raw[:10], now_iso()),
        )
        con.commit()
    return raw



# ============================================================
# FONT GENERATOR / SMALL CAPS
# ============================================================

SERIF_BOLD_CAPS = {chr(ord("A") + i): chr(0x1D400 + i) for i in range(26)}

SMALL_CAPS = {
    "a": "ᴀ", "b": "ʙ", "c": "ᴄ", "d": "ᴅ", "e": "ᴇ",
    "f": "ꜰ", "g": "ɢ", "h": "ʜ", "i": "ɪ", "j": "ᴊ",
    "k": "ᴋ", "l": "ʟ", "m": "ᴍ", "n": "ɴ", "o": "ᴏ",
    "p": "ᴘ", "q": "ǫ", "r": "ʀ", "s": "s", "t": "ᴛ",
    "u": "ᴜ", "v": "ᴠ", "w": "ᴡ", "x": "x", "y": "ʏ",
    "z": "ᴢ",
}

def style_text(text: str) -> str:
    result = []
    at_word_start = True
    for ch in text:
        if ch.isalpha():
            if at_word_start:
                result.append(SERIF_BOLD_CAPS.get(ch.upper(), ch.upper()))
                at_word_start = False
            else:
                result.append(SMALL_CAPS.get(ch.lower(), ch.lower()))
        else:
            result.append(ch)
            if ch.isspace() or ch in '-_/\\|.,!?;:()[]{}<>"\'`~@#$%^&*+=—–':
                at_word_start = True
    return "".join(result)


# ============================================================
# GLOBAL SMALL-CAPS OUTPUT STYLE
# ============================================================

def styled_output(text):
    """Convert bot-visible text to the Small Caps style."""
    if text is None:
        return text
    return style_text(str(text))


def _patch_telegram_output_style():
    """Apply Small Caps to bot outputs and inline keyboard labels."""
    from telegram import Bot, CallbackQuery, Message

    if not getattr(Message.reply_text, "_small_caps_patched", False):
        _original_reply_text = Message.reply_text

        async def _styled_reply_text(self, text=None, *args, **kwargs):
            return await _original_reply_text(
                self, styled_output(text), *args, **kwargs
            )

        _styled_reply_text._small_caps_patched = True
        Message.reply_text = _styled_reply_text

    if not getattr(CallbackQuery.edit_message_text, "_small_caps_patched", False):
        _original_edit_message_text = CallbackQuery.edit_message_text

        async def _styled_edit_message_text(self, text, *args, **kwargs):
            return await _original_edit_message_text(
                self, styled_output(text), *args, **kwargs
            )

        _styled_edit_message_text._small_caps_patched = True
        CallbackQuery.edit_message_text = _styled_edit_message_text

    if not getattr(InlineKeyboardButton, "_small_caps_patched", False):
        _original_button_init = InlineKeyboardButton.__init__

        def _styled_button_init(self, text, *args, **kwargs):
            return _original_button_init(
                self, styled_output(text), *args, **kwargs
            )

        _styled_button_init._small_caps_patched = True
        InlineKeyboardButton.__init__ = _styled_button_init

    if not getattr(Bot.send_message, "_small_caps_patched", False):
        _original_send_message = Bot.send_message

        async def _styled_send_message(self, chat_id, text, *args, **kwargs):
            return await _original_send_message(
                self, chat_id, styled_output(text), *args, **kwargs
            )

        _styled_send_message._small_caps_patched = True
        Bot.send_message = _styled_send_message


_patch_telegram_output_style()

async def font_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ensure_user(update.effective_user)
    context.user_data["mode"] = "font"
    await update.message.reply_text(
        "🔤 *FONT GENERATOR*\\n\\n"
        "Send any text and I will convert it to Small Caps style.\\n\\n"
        "Example: `hello world` → `𝐇ᴇʟʟᴏ 𝐖ᴏʀʟᴅ`",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=back_home_keyboard(),
    )


# ============================================================
# COMMANDS
# ============================================================


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🆘 *HELP / FEATURES*\n\n"
        "📁 File Manager\n"
        "▶️ Process Manager + Logs\n"
        "⚡ Bot Speed / 🚀 Hosting Status\n"
        "🔤 Small Caps Font Generator\n"
        "🤖 AI Agent\n"
        "🌐 Git Clone\n"
        "⚙️ Package Installer\n"
        "🚀 API / 🌍 Website / 💻 Local Host\n"
        "💳 Plans / 🛒 Store / 👤 Account\n\n"
        "Use /start to open the main menu.",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=main_keyboard(),
    )

async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ensure_user(update.effective_user)
    rec = user_record(update.effective_user.id)
    if rec["banned"]:
        return await update.message.reply_text("🚫 Your account is banned.")

    await update.message.reply_text(
        "🚀 *Telegram Hosting Panel*\n\n"
        "Upload files, manage your workspace and control supported processes.",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=main_keyboard(),
    )


async def admin_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return

    with closing(db()) as con:
        users = con.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
        procs = con.execute(
            "SELECT COUNT(*) n FROM processes WHERE status='RUNNING'"
        ).fetchone()["n"]
        disk = psutil.disk_usage("/")

    await update.message.reply_text(
        "👑 *ADMIN PANEL*\n\n"
        f"👥 Users: {users}\n"
        f"▶️ Recorded processes: {procs}\n"
        f"💾 Disk: {disk.percent}%\n\n"
        "Commands:\n"
        "/users — user count\n"
        "/broadcast TEXT — broadcast\n"
        "/ban USER_ID\n"
        "/unban USER_ID",
        parse_mode=ParseMode.MARKDOWN,
    )


async def users_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        return
    with closing(db()) as con:
        rows = con.execute(
            "SELECT id,username,name,plan_id,banned FROM users ORDER BY created_at DESC LIMIT 30"
        ).fetchall()
    text = ["👥 *USERS*"]
    for r in rows:
        text.append(
            f"`{r['id']}` — {r['username'] or '-'} — "
            f"{'🚫' if r['banned'] else '🟢'}"
        )
    await update.message.reply_text(
        "\n".join(text)[:3900], parse_mode=ParseMode.MARKDOWN
    )


async def ban_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID or not context.args:
        return
    uid = int(context.args[0])
    with closing(db()) as con:
        con.execute("UPDATE users SET banned=1 WHERE id=?", (uid,))
        con.commit()
    await update.message.reply_text(f"🚫 Banned `{uid}`.", parse_mode=ParseMode.MARKDOWN)


async def unban_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID or not context.args:
        return
    uid = int(context.args[0])
    with closing(db()) as con:
        con.execute("UPDATE users SET banned=0 WHERE id=?", (uid,))
        con.commit()
    await update.message.reply_text(f"✅ Unbanned `{uid}`.", parse_mode=ParseMode.MARKDOWN)


async def broadcast_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID or not context.args:
        return
    message = " ".join(context.args)
    with closing(db()) as con:
        rows = con.execute("SELECT id FROM users WHERE banned=0").fetchall()

    ok = 0
    for row in rows:
        try:
            await context.bot.send_message(row["id"], message)
            ok += 1
            await asyncio.sleep(0.05)
        except Exception:
            pass

    await update.message.reply_text(f"📢 Broadcast sent: {ok}")


# ============================================================
# CALLBACK HANDLER
# ============================================================

async def callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    uid = q.from_user.id
    ensure_user(q.from_user)

    rec = user_record(uid)
    if rec["banned"]:
        return await q.edit_message_text("🚫 Your account is banned.")

    data = q.data or ""

    # ---------------- HOME ----------------
    if data == "home":
        await q.edit_message_text(
            "🏠 *MAIN MENU*",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=main_keyboard(),
        )
        return

    # ---------------- FONT / HELP ----------------
    if data == "font":
        context.user_data["mode"] = "font"
        await q.edit_message_text(
            "🔤 *FONT GENERATOR*\n\n"
            "Send any text and I will convert it to Small Caps style.\n\n"
            "Example: `hello world` → `𝐇ᴇʟʟᴏ 𝐖ᴏʀʟᴅ`",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=back_home_keyboard(),
        )
        return

    if data == "help":
        await q.edit_message_text(
            "🆘 *HELP / FEATURES*\n\n"
            "📁 File Manager\n"
            "▶️ Process Manager + Logs\n"
            "⚡ Speed / 🚀 Hosting Status\n"
            "🔤 Small Caps Font Generator\n"
            "🤖 AI Agent\n"
            "🌐 Git Clone\n"
            "⚙️ Package Installer\n"
            "🚀 API / 🌍 Website / 💻 Local Host\n"
            "💳 Plans / 🛒 Store / 👤 Account",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=back_home_keyboard(),
        )
        return

    # ---------------- ACCOUNT ----------------
    if data == "account":
        used = storage_used(uid)
        procs = running_count(uid)
        text = (
            "👤 *MY ACCOUNT*\n\n"
            f"🆔 ID: `{uid}`\n"
            f"👤 Username: @{q.from_user.username or '-'}\n"
            f"📦 Files: {count_files(uid)}\n"
            f"💾 Storage: {human_size(used)} / {rec['storage_mb']} MB\n"
            f"📊 Plan: {rec['plan_name']}\n"
            f"🚀 Processes: {procs} / {rec['process_limit']}\n"
            f"🌐 Website: {'AVAILABLE' if rec['website'] else 'LOCKED'}\n"
            f"📅 Created: {rec['created_at'][:10]}\n"
            f"⏳ Expiry: {rec['subscription_expiry'] or 'N/A'}"
        )
        await q.edit_message_text(
            text, parse_mode=ParseMode.MARKDOWN, reply_markup=back_home_keyboard()
        )
        return

    # ---------------- FILES ----------------
    if data == "files":
        await render_files(q, uid, ".")
        return

    if data.startswith("files:"):
        rel = data.split(":", 1)[1] or "."
        await render_files(q, uid, rel)
        return

    # ---------------- UPLOAD ----------------
    if data == "upload":
        context.user_data["mode"] = "upload"
        await q.edit_message_text(
            "🌐 *UPLOAD*\n\nSend a file/document now.\n\n"
            f"Maximum configured upload: {MAX_UPLOAD_MB} MB",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=back_home_keyboard(),
        )
        return

    # ---------------- NEW FOLDER ----------------
    if data == "newfolder":
        context.user_data["mode"] = "newfolder"
        await q.edit_message_text(
            "📁 Send the new folder name.",
            reply_markup=back_home_keyboard(),
        )
        return

    # ---------------- SPEED ----------------
    if data == "speed":
        started = time.perf_counter()
        cpu = psutil.cpu_percent(interval=0.1)
        vm = psutil.virtual_memory()
        elapsed = (time.perf_counter() - started) * 1000
        await q.edit_message_text(
            "⚡ *BOT SPEED*\n\n"
            f"Response Time: `{elapsed:.2f} ms`\n"
            f"🖥 CPU Usage: `{cpu}%`\n"
            f"💾 RAM: `{vm.percent}%`\n"
            f"🟢 Free RAM: `{human_size(vm.available)}`\n"
            f"📦 Plan: `{rec['plan_name']}`",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=back_home_keyboard(),
        )
        return

    # ---------------- STATUS ----------------
    if data == "status":
        cpu = psutil.cpu_percent(interval=0.1)
        vm = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        await q.edit_message_text(
            "🚀 *HOSTING STATUS*\n\n"
            "Bot: 🟢 ONLINE\n"
            "Server: 🟢 ONLINE\n"
            f"CPU: `{cpu}%`\n"
            f"RAM: `{vm.percent}%`\n"
            f"Disk: `{disk.percent}%`\n"
            f"Processes: `{len(RUNNING)}`",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=back_home_keyboard(),
        )
        return

    # ---------------- PROCESSES ----------------
    if data in {"processes", "proc_refresh"}:
        lines = ["▶️ *PROCESS MANAGER*", ""]
        owned = []
        for pid, info in RUNNING.items():
            if info["user_id"] == uid:
                owned.append((pid, info))

        if not owned:
            lines.append("📭 No running processes.")
        else:
            for pid, info in owned:
                uptime = int(time.time() - info["started"])
                lines.append(
                    f"📄 `{info['file']}`\n"
                    f"🟢 RUNNING — PID `{pid}` — Uptime `{uptime}s`"
                )

        buttons = []
        for pid, info in owned:
            buttons.append(
                [
                    InlineKeyboardButton(
                        f"⏹ Stop {pid}", callback_data=f"stop:{pid}"
                    ),
                    InlineKeyboardButton(
                        "📜 Logs", callback_data=f"logs:{pid}"
                    ),
                ]
            )
        buttons.append([InlineKeyboardButton("🔄 Refresh", callback_data="proc_refresh")])
        buttons.append([InlineKeyboardButton("🏠 Home", callback_data="home")])

        await q.edit_message_text(
            "\n".join(lines),
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=InlineKeyboardMarkup(buttons),
        )
        return

    if data.startswith("stop:"):
        pid = int(data.split(":", 1)[1])
        try:
            await stop_process(uid, pid)
            await q.edit_message_text(
                f"⏹ Process `{pid}` stopped.",
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=back_home_keyboard(),
            )
        except Exception as e:
            await q.edit_message_text(
                f"❌ {e}", reply_markup=back_home_keyboard()
            )
        return

    if data.startswith("logs:"):
        pid = int(data.split(":", 1)[1])
        info = RUNNING.get(pid)
        if not info or info["user_id"] != uid:
            return await q.edit_message_text(
                "❌ Process not found.", reply_markup=back_home_keyboard()
            )
        try:
            raw = info["log"].read_text(errors="replace")
            raw = raw[-3500:] if raw else "(empty)"
            await q.edit_message_text(
                f"📜 *LOGS — PID {pid}*\n\n```text\n{raw}\n```",
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=back_home_keyboard(),
            )
        except Exception as e:
            await q.edit_message_text(
                f"❌ {e}", reply_markup=back_home_keyboard()
            )
        return

    # ---------------- AI ----------------
    if data == "ai":
        context.user_data["mode"] = "ai"
        await q.edit_message_text(
            "🤖 *AI AGENT*\n\n"
            "Send a Python/JavaScript error, log, or coding question.",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=back_home_keyboard(),
        )
        return

    # ---------------- GIT ----------------
    if data == "git":
        if not rec["git_clone"]:
            return await q.edit_message_text(
                "🔒 Git Clone is not available on your current plan.",
                reply_markup=back_home_keyboard(),
            )
        context.user_data["mode"] = "git"
        await q.edit_message_text(
            "🌐 *GIT CLONE*\n\n"
            "Send an HTTPS GitHub/GitLab/Codeberg repository URL.",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=back_home_keyboard(),
        )
        return

    # ---------------- API ----------------
    if data == "api":
        if not rec["api_access"]:
            return await q.edit_message_text(
                "🔒 API access is not available on your current plan.",
                reply_markup=back_home_keyboard(),
            )
        key = create_api_key(uid)
        await q.edit_message_text(
            "🚀 *API*\n\n"
            "🔑 Your new key is shown once:\n"
            f"`{key}`\n\n"
            "Store it securely.",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=back_home_keyboard(),
        )
        return

    # ---------------- WEBSITE ----------------
    if data == "website":
        if not rec["website"]:
            return await q.edit_message_text(
                "🔒 Website hosting requires a supported plan.",
                reply_markup=back_home_keyboard(),
            )
        await q.edit_message_text(
            "🌍 *WEBSITE*\n\n"
            "Static website hosting is enabled in the architecture.\n"
            "For production, expose it through a reverse proxy and isolated "
            "web server/container.",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=back_home_keyboard(),
        )
        return

    # ---------------- LOCAL HOST ----------------
    if data == "localhost":
        await q.edit_message_text(
            "💻 *LOCAL HOST*\n\n"
            "Use a safe configured port (8000–8100) and an isolated web-server "
            "process. Do not expose arbitrary interfaces or ports.",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=back_home_keyboard(),
        )
        return

    # ---------------- INSTALL ----------------
    if data == "install":
        buttons = [
            [InlineKeyboardButton(x, callback_data=f"pkg:{x}")]
            for x in ("requests", "flask", "fastapi", "discord.py")
        ]
        buttons.append([InlineKeyboardButton("🏠 Home", callback_data="home")])
        await q.edit_message_text(
            "⚙️ *RECOMMENDED INSTALL*\n\nChoose an allowlisted package:",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=InlineKeyboardMarkup(buttons),
        )
        return

    if data.startswith("pkg:"):
        package = data.split(":", 1)[1]
        await q.edit_message_text(f"⏳ Installing `{package}`...", parse_mode=ParseMode.MARKDOWN)
        try:
            await install_package(uid, package)
            await q.edit_message_text(
                f"✅ `{package}` installed.",
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=back_home_keyboard(),
            )
        except Exception as e:
            await q.edit_message_text(
                f"❌ Installation failed:\n`{str(e)[:2500]}`",
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=back_home_keyboard(),
            )
        return

    # ---------------- PLANS / STORE ----------------
    if data in {"plans", "store"}:
        await q.edit_message_text(
            "🛒 *STORE*\n\n"
            "🆓 FREE\n"
            "• 500 MB storage\n"
            "• 1 process\n"
            "• Basic file manager\n\n"
            "💎 PRO\n"
            "• 5 GB storage\n"
            "• 5 processes\n"
            "• Website\n"
            "• Git Clone\n"
            "• API\n\n"
            "👑 PREMIUM\n"
            "• 20 GB storage\n"
            "• 10 processes\n"
            "• Advanced features\n\n"
            "💳 Payment providers should be connected through a verified "
            "webhook before real upgrades are enabled.",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=back_home_keyboard(),
        )
        return

    # ---------------- OPTIONAL INTEGRATIONS ----------------
    if data in {"whatsapp", "discord"}:
        title = "📱 WHATSAPP BOT" if data == "whatsapp" else "🟣 DISCORD BOT"
        await q.edit_message_text(
            f"{title}\n\n"
            "This integration is optional. Credentials must be stored securely "
            "and never exposed in chat. Add a provider adapter when you connect "
            "the external service.",
            reply_markup=back_home_keyboard(),
        )
        return

    # ---------------- UPDATES / CONTACT ----------------
    if data == "updates":
        await q.edit_message_text(
            "📢 *UPDATES*\n\nConfigure your official updates channel in the bot settings.",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=back_home_keyboard(),
        )
        return

    if data == "contact":
        await q.edit_message_text(
            "📞 *CONTACT OWNER*\n\nConfigure the owner's Telegram username in your deployment settings.",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=back_home_keyboard(),
        )
        return


# ============================================================
# MESSAGE HANDLER
# ============================================================

async def message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.effective_user:
        return

    ensure_user(update.effective_user)
    uid = update.effective_user.id
    rec = user_record(uid)

    if rec["banned"]:
        return await update.message.reply_text("🚫 Your account is banned.")

    mode = context.user_data.get("mode")

    if mode == "font":
        text = update.message.text or ""
        if not text:
            return
        return await update.message.reply_text(style_text(text))

    if mode == "ai":
        await update.message.chat.send_action("typing")
        try:
            answer = await ai_analyze(update.message.text or "")
        except Exception as e:
            answer = f"❌ AI error: {type(e).__name__}"
        return await update.message.reply_text(answer)

    if mode == "git":
        await update.message.reply_text("⏳ Cloning repository...")
        try:
            name = await git_clone(uid, update.message.text or "")
            context.user_data.pop("mode", None)
            return await update.message.reply_text(
                f"✅ Repository cloned: `{name}`",
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=main_keyboard(),
            )
        except Exception as e:
            return await update.message.reply_text(f"❌ {e}")

    if mode == "newfolder":
        try:
            name = safe_name(update.message.text or "")
            path = files_root(uid) / name
            path.mkdir()
            context.user_data.pop("mode", None)
            return await update.message.reply_text(
                f"✅ Folder created: `{name}`",
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=main_keyboard(),
            )
        except Exception as e:
            return await update.message.reply_text(f"❌ {e}")

    # If user sends plain text without a mode, show menu.
    await update.message.reply_text(
        "🏠 Choose an option from the menu.",
        reply_markup=main_keyboard(),
    )


async def document_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ensure_user(update.effective_user)
    uid = update.effective_user.id
    rec = user_record(uid)

    if rec["banned"]:
        return await update.message.reply_text("🚫 Your account is banned.")

    document = update.message.document
    if not document:
        return

    size = int(document.file_size or 0)
    max_bytes = MAX_UPLOAD_MB * 1024 * 1024
    if size > max_bytes:
        return await update.message.reply_text(
            f"❌ File exceeds {MAX_UPLOAD_MB} MB upload limit."
        )

    name = document.file_name or "upload.bin"
    try:
        name = safe_name(name)
    except ValueError as e:
        return await update.message.reply_text(f"❌ {e}")

    current = storage_used(uid)
    if current + size > rec["storage_mb"] * 1024 * 1024:
        return await update.message.reply_text("❌ Your storage limit has been reached.")

    target = files_root(uid) / name
    if target.exists():
        return await update.message.reply_text(
            "❌ A file with that name already exists."
        )

    await update.message.reply_text("⏳ Uploading...")

    try:
        tg_file = await document.get_file()
        await tg_file.download_to_drive(custom_path=str(target))
        audit(uid, "upload", name)
        await update.message.reply_text(
            "✅ *Upload Complete*\n\n"
            f"📄 File: `{name}`\n"
            f"📦 Size: `{human_size(size)}`",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=main_keyboard(),
        )
    except Exception as e:
        try:
            target.unlink(missing_ok=True)
        except Exception:
            pass
        await update.message.reply_text(f"❌ Upload failed: {e}")


# ============================================================
# ERROR HANDLER
# ============================================================

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
    log.exception("Unhandled Telegram error", exc_info=context.error)
    if isinstance(update, Update) and update.effective_message:
        try:
            await update.effective_message.reply_text(
                "❌ Something went wrong. Please try again."
            )
        except Exception:
            pass


# ============================================================
# STARTUP / SHUTDOWN
# ============================================================

async def post_init(app: Application):
    init_db()
    app.create_task(process_watcher())
    log.info("Database initialized. Bot started.")


def build_app():
    app = (
        ApplicationBuilder()
        .token(BOT_TOKEN)
        .post_init(post_init)
        .build()
    )

    app.add_handler(CommandHandler("start", start_cmd))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("font", font_cmd))
    app.add_handler(CommandHandler("admin", admin_cmd))
    app.add_handler(CommandHandler("users", users_cmd))
    app.add_handler(CommandHandler("ban", ban_cmd))
    app.add_handler(CommandHandler("unban", unban_cmd))
    app.add_handler(CommandHandler("broadcast", broadcast_cmd))

    app.add_handler(CallbackQueryHandler(callback))
    app.add_handler(MessageHandler(filters.Document.ALL, document_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, message_handler))

    app.add_error_handler(error_handler)
    return app


if __name__ == "__main__":
    print("=" * 55)
    print(" Telegram Hosting & File Manager Bot")
    print("=" * 55)
    print(f"Data directory : {DATA_DIR}")
    print(f"Database       : {DB_PATH}")
    print(f"Upload limit   : {MAX_UPLOAD_MB} MB")
    print("Starting bot...")
    build_app().run_polling(allowed_updates=["message", "callback_query"])
