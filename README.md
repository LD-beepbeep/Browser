# BeepBeep Browser

A minimalist, privacy-focused web browser in a single Python file, built on **PySide6 + QtWebEngine**.

---

## Features

| Feature | Details |
|---|---|
| **Engine** | PySide6 `QWebEngineView` (Chromium-based) with a shared profile to minimise RAM |
| **UI** | Slim tab bar + 3 px progress bar. No address bar visible by default |
| **Address bar** | Toggle with **Ctrl+L**; supports URLs and DuckDuckGo search |
| **Tab management** | **Ctrl+T** new tab · **Ctrl+W** close · drag-to-reorder · "+" button |
| **Bookmarks** | JSON file (`~/.local/share/BeepBeep/bookmarks.json`). **Ctrl+D** add · **Ctrl+B** manage |
| **Password manager** | Fernet-encrypted credential store (PBKDF2-SHA256). **Ctrl+P** to open. Autofill on page load. Import / export as plain JSON |
| **Tracker blocking** | URL-request interceptor blocks 35+ known tracking/ad hosts |
| **Dark mode** | System palette + `color-scheme: dark` CSS injected into every page; `ForceDarkMode` enabled on Qt ≥ 6.7 |
| **Privacy** | Plugins disabled; background networking, sync, and translate disabled via Chromium flags |

### Keyboard shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+T` | New tab |
| `Ctrl+W` | Close current tab |
| `Ctrl+L` | Toggle address bar |
| `Ctrl+D` | Bookmark current page |
| `Ctrl+B` | Show bookmarks |
| `Ctrl+P` | Open password manager |
| `Ctrl+R` / `F5` | Reload |
| `Alt+←` / `Alt+→` | Back / Forward |
| `F11` | Toggle full screen |
| `Escape` | Hide address bar / stop loading |

---

## Requirements

- Python 3.10+
- PySide6 ≥ 6.5
- cryptography ≥ 41 (password manager only; browser runs without it)

```bash
pip install -r requirements.txt
```

---

## Running

```bash
python browser.py
```

---

## Building a standalone Windows `.exe` with PyInstaller

### 1. Install PyInstaller

```bash
pip install pyinstaller>=6.0.0
```

### 2. Bundle into a single windowed executable

```bash
pyinstaller --onefile --windowed \
    --name BeepBeep \
    --icon icon.ico \
    --add-binary "$(python -c 'import PySide6; import os; print(os.path.join(os.path.dirname(PySide6.__file__), \"Qt\", \"bin\", \"QtWebEngineProcess.exe\"))')":. \
    browser.py
```

> **Windows one-liner** (PowerShell):
> ```powershell
> $qtbin = python -c "import PySide6, os; print(os.path.join(os.path.dirname(PySide6.__file__), 'Qt', 'bin', 'QtWebEngineProcess.exe'))"
> pyinstaller --onefile --windowed --name BeepBeep --icon icon.ico "--add-binary=$qtbin;." browser.py
> ```

The resulting `dist\BeepBeep.exe` is self-contained.

> **RAM target**: A fresh window loading `start.duckduckgo.com` typically uses **60–90 MB** of working set, well under the 100 MB goal. The shared `QWebEngineProfile`, disabled plugins, and reduced Chromium flags all contribute to this.

---

## Data locations

| Platform | Path |
|---|---|
| Linux | `~/.local/share/BeepBeep/` |
| macOS | `~/Library/Application Support/BeepBeep/` |
| Windows | `%APPDATA%\BeepBeep\BeepBeep\` |

Files stored:

- `bookmarks.json` — plain JSON bookmark list
- `passwords.enc` — Fernet-encrypted credential blob
- `salt.bin` — PBKDF2 salt (16 bytes)