#!/usr/bin/env python3
"""
BeepBeep Browser — Minimalist, privacy-focused web browser.

Single-file Python script. Requires PySide6 and (optionally) cryptography.

Keyboard Shortcuts:
  Ctrl+T        New tab
  Ctrl+W        Close current tab
  Ctrl+L        Toggle address bar
  Ctrl+D        Bookmark current page
  Ctrl+B        Show bookmarks
  Ctrl+P        Password manager
  Ctrl+R / F5   Reload
  Alt+Left      Back
  Alt+Right     Forward
  F11           Toggle full screen
  Escape        Hide address bar / stop loading
"""

import gc
import sys
import os
import json
import base64
import html.parser
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# ── Optional dependency: cryptography (for password encryption) ───────────────
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

from PySide6.QtCore import (
    Qt,
    QEasingCurve,
    QPoint,
    QPropertyAnimation,
    QTimer,
    QUrl,
    QStandardPaths,
    Signal,
)
from PySide6.QtGui import QColor, QIcon, QKeySequence, QPalette, QShortcut
from PySide6.QtWebEngineCore import (
    QWebEngineProfile,
    QWebEngineScript,
    QWebEngineSettings,
    QWebEngineUrlRequestInfo,
    QWebEngineUrlRequestInterceptor,
)
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QTabBar,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

# ──────────────────────────── Constants ──────────────────────────────────────

HOME_URL = "https://start.duckduckgo.com/"

# Available search engines: key -> (display name, query URL prefix)
SEARCH_ENGINES: Dict[str, Tuple[str, str]] = {
    "duckduckgo": ("DuckDuckGo", "https://duckduckgo.com/?q="),
    "google": ("Google", "https://www.google.com/search?q="),
    "bing": ("Bing", "https://www.bing.com/search?q="),
}

# Known tracking / advertising hosts to block.
TRACKING_HOSTS: frozenset = frozenset(
    {
        "google-analytics.com",
        "googletagmanager.com",
        "googlesyndication.com",
        "doubleclick.net",
        "analytics.twitter.com",
        "static.ads-twitter.com",
        "connect.facebook.net",
        "amazon-adsystem.com",
        "adnxs.com",
        "scorecardresearch.com",
        "quantserve.com",
        "krxd.net",
        "mediamath.com",
        "rubiconproject.com",
        "pubmatic.com",
        "openx.net",
        "chartbeat.com",
        "newrelic.com",
        "hotjar.com",
        "fullstory.com",
        "mixpanel.com",
        "segment.io",
        "amplitude.com",
        "heap.io",
        "logrocket.com",
        "outbrain.com",
        "taboola.com",
        "criteo.com",
        "bat.bing.com",
        "cloudflareinsights.com",
        "sentry.io",
        "bugsnag.com",
        "rollbar.com",
        "adsafeprotected.com",
        "moatads.com",
    }
)

# JavaScript injected into every page to listen for autofill events.
_AUTOFILL_LISTENER_JS = """
(function () {
    document.addEventListener('__beepbeep_autofill', function (e) {
        var u = e.detail.username;
        var p = e.detail.password;
        var selectors = [
            ['input[autocomplete="username"]', 'input[autocomplete="current-password"]'],
            ['input[type="email"]', 'input[type="password"]'],
            ['input[name*="user"]', 'input[type="password"]'],
            ['input[name*="email"]', 'input[type="password"]'],
        ];
        for (var i = 0; i < selectors.length; i++) {
            var uf = document.querySelector(selectors[i][0]);
            var pf = document.querySelector(selectors[i][1]);
            if (uf && pf) {
                if (u) { uf.value = u; uf.dispatchEvent(new Event('input', {bubbles: true})); }
                if (p) { pf.value = p; pf.dispatchEvent(new Event('input', {bubbles: true})); }
                break;
            }
        }
    });
})();
"""

# JavaScript that forces dark color-scheme on every page.
_DARK_MODE_JS = """
(function () {
    var s = document.createElement('style');
    s.id = '__beepbeep_dark';
    s.textContent = ':root { color-scheme: dark !important; }';
    var head = document.head || document.documentElement;
    if (head && !document.getElementById('__beepbeep_dark')) {
        head.appendChild(s);
    }
})();
"""


# ──────────────────────── App Data Directory ─────────────────────────────────


def _app_dir() -> Path:
    """Return (and create if needed) the application data directory."""
    loc = QStandardPaths.writableLocation(
        QStandardPaths.StandardLocation.AppDataLocation
    )
    path = Path(loc) if loc else Path.home() / ".beepbeep"
    path.mkdir(parents=True, exist_ok=True)
    return path


# ────────────────────────── Tracking Blocker ─────────────────────────────────


class TrackingBlocker(QWebEngineUrlRequestInterceptor):
    """Blocks outgoing requests to known tracking and advertising hosts."""

    def interceptRequest(self, info: QWebEngineUrlRequestInfo) -> None:  # noqa: N802
        host = info.requestUrl().host().removeprefix("www.")
        for blocked in TRACKING_HOSTS:
            if host == blocked or host.endswith("." + blocked):
                info.block(True)
                return


# ────────────────────────── Password Manager ─────────────────────────────────


class PasswordManager:
    """
    Stores credentials encrypted with Fernet (PBKDF2-SHA256 key derivation).

    File layout (inside app-data dir):
      passwords.enc  — Fernet-encrypted JSON blob
      salt.bin       — 16-byte random salt
    """

    def __init__(self, data_dir: Path) -> None:
        self._enc_file = data_dir / "passwords.enc"
        self._salt_file = data_dir / "salt.bin"
        self._fernet: Optional[Fernet] = None
        self._credentials: Dict[str, Dict[str, str]] = {}

    # ── Key management ────────────────────────────────────────────────────

    def _derive_key(self, master: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480_000,
        )
        return base64.urlsafe_b64encode(kdf.derive(master.encode()))

    def unlock(self, master_password: str) -> bool:
        """
        Unlock the credential store.
        Returns True on success, False if the password is wrong / store is corrupted.
        """
        if not CRYPTO_AVAILABLE:
            return False

        if self._salt_file.exists():
            salt = self._salt_file.read_bytes()
        else:
            salt = os.urandom(16)
            self._salt_file.write_bytes(salt)

        key = self._derive_key(master_password, salt)
        self._fernet = Fernet(key)

        if self._enc_file.exists():
            try:
                raw = self._fernet.decrypt(self._enc_file.read_bytes())
                self._credentials = json.loads(raw)
                return True
            except (InvalidToken, json.JSONDecodeError, Exception):
                self._fernet = None
                return False

        # Fresh store — write an empty one.
        self._persist()
        return True

    def _persist(self) -> None:
        if self._fernet is None:
            return
        raw = json.dumps(self._credentials).encode()
        self._enc_file.write_bytes(self._fernet.encrypt(raw))

    # ── Public API ────────────────────────────────────────────────────────

    @property
    def is_unlocked(self) -> bool:
        return self._fernet is not None

    @property
    def fernet(self) -> "Optional[Fernet]":
        """Return the active Fernet instance (None if locked)."""
        return self._fernet

    def get(self, domain: str) -> Optional[Tuple[str, str]]:
        """Return (username, password) for *domain*, or None if not stored."""
        entry = self._credentials.get(domain)
        if entry:
            return entry.get("username", ""), entry.get("password", "")
        return None

    def save(self, domain: str, username: str, password: str) -> None:
        self._credentials[domain] = {"username": username, "password": password}
        self._persist()

    def delete(self, domain: str) -> None:
        self._credentials.pop(domain, None)
        self._persist()

    def all_domains(self) -> List[str]:
        return list(self._credentials.keys())

    # ── Import / Export ───────────────────────────────────────────────────

    def export_json(self, path: str) -> None:
        """Export credentials as plain JSON (for migration only — no encryption)."""
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self._credentials, fh, indent=2)

    def import_json(self, path: str) -> int:
        """Import credentials from a plain JSON file. Returns number imported."""
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        count = 0
        for domain, entry in data.items():
            if isinstance(entry, dict) and "username" in entry and "password" in entry:
                self._credentials[domain] = entry
                count += 1
        self._persist()
        return count


# ────────────────────────── Bookmark Manager ─────────────────────────────────


class BookmarkManager:
    """
    Bookmarks stored as a JSON array in the app-data directory.

    When a Fernet key is provided via ``unlock()``, bookmarks are persisted
    in encrypted form (``bookmarks.enc``).  Plain ``bookmarks.json`` is kept
    for backward-compatibility and is migrated to encrypted on first unlock.
    """

    def __init__(self, data_dir: Path) -> None:
        self._file = data_dir / "bookmarks.json"
        self._enc_file = data_dir / "bookmarks.enc"
        self._fernet: "Optional[Fernet]" = None
        self._items: List[Dict[str, str]] = []
        self._load()

    # ── Key management ────────────────────────────────────────────────────

    def unlock(self, fernet: "Fernet") -> None:
        """Set the encryption key and reload / migrate bookmarks."""
        self._fernet = fernet
        if self._enc_file.exists():
            try:
                raw = fernet.decrypt(self._enc_file.read_bytes())
                self._items = json.loads(raw)
                return
            except Exception:
                self._items = []
                return
        # No encrypted file yet – persist whatever we loaded from plain JSON.
        self._save()

    # ── Persistence ───────────────────────────────────────────────────────

    def _load(self) -> None:
        if self._file.exists():
            try:
                self._items = json.loads(self._file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._items = []

    def _save(self) -> None:
        data_bytes = json.dumps(self._items, indent=2, ensure_ascii=False).encode()
        if self._fernet is not None:
            self._enc_file.write_bytes(self._fernet.encrypt(data_bytes))
            # Remove the unencrypted file once migration is complete.
            if self._file.exists():
                try:
                    self._file.unlink()
                except OSError:
                    pass
        else:
            self._file.write_text(data_bytes.decode(), encoding="utf-8")

    def add(self, title: str, url: str) -> None:
        if not any(b["url"] == url for b in self._items):
            self._items.append({"title": title, "url": url})
            self._save()

    def remove(self, index: int) -> None:
        if 0 <= index < len(self._items):
            self._items.pop(index)
            self._save()

    def all(self) -> List[Dict[str, str]]:
        return list(self._items)

    def import_html(self, path: str) -> int:
        """Import bookmarks from a Netscape/Firefox HTML bookmarks file."""

        class _Parser(html.parser.HTMLParser):
            def __init__(self) -> None:
                super().__init__()
                self.bookmarks: List[Dict[str, str]] = []
                self._url: Optional[str] = None
                self._title: str = ""
                self._in_a: bool = False

            def handle_starttag(self, tag: str, attrs: list) -> None:
                if tag.lower() == "a":
                    self._in_a = True
                    self._url = dict(attrs).get("href", "")
                    self._title = ""

            def handle_endtag(self, tag: str) -> None:
                if tag.lower() == "a" and self._in_a:
                    self._in_a = False
                    if self._url:
                        self.bookmarks.append(
                            {"title": self._title or self._url, "url": self._url}
                        )
                    self._url = None
                    self._title = ""

            def handle_data(self, data: str) -> None:
                if self._in_a:
                    self._title += data

        with open(path, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        parser = _Parser()
        parser.feed(content)
        count = 0
        for bm in parser.bookmarks:
            if not any(b["url"] == bm["url"] for b in self._items):
                self._items.append(bm)
                count += 1
        if count:
            self._save()
        return count


# ────────────────────────── Config Manager ───────────────────────────────────


class ConfigManager:
    """Persists user preferences (search engine, onboarding state) in config.json."""

    def __init__(self, data_dir: Path) -> None:
        self._file = data_dir / "config.json"
        self._data: Dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        if self._file.exists():
            try:
                self._data = json.loads(self._file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._data = {}

    def save(self) -> None:
        self._file.write_text(
            json.dumps(self._data, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    # ── Onboarding ────────────────────────────────────────────────────────

    @property
    def onboarding_done(self) -> bool:
        return bool(self._data.get("onboarding_done", False))

    @onboarding_done.setter
    def onboarding_done(self, value: bool) -> None:
        self._data["onboarding_done"] = value

    # ── Search engine ─────────────────────────────────────────────────────

    @property
    def search_engine(self) -> str:
        key = self._data.get("search_engine", "duckduckgo")
        return key if key in SEARCH_ENGINES else "duckduckgo"

    @search_engine.setter
    def search_engine(self, key: str) -> None:
        if key in SEARCH_ENGINES:
            self._data["search_engine"] = key

    def search_engine_name(self) -> str:
        return SEARCH_ENGINES[self.search_engine][0]

    def build_search_url(self, query: str) -> str:
        _, base_url = SEARCH_ENGINES[self.search_engine]
        return base_url + query.replace(" ", "+")


# ──────────────────────────── Web View ───────────────────────────────────────


class WebView(QWebEngineView):
    """
    QWebEngineView subclass that:
    - Supports autofill injection via PasswordManager
    - Routes popup / new-window requests back to the browser window as new tabs
    - Shows a custom context menu with "Search with [Engine]" option
    """

    def __init__(
        self,
        profile: QWebEngineProfile,
        pm: PasswordManager,
        config: Optional["ConfigManager"] = None,
        on_popup: Optional[Callable[["WebView"], None]] = None,
        on_new_tab: Optional[Callable[[str], None]] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        from PySide6.QtWebEngineCore import QWebEnginePage

        self.setPage(QWebEnginePage(profile, self))
        self._pm = pm
        self._config = config
        self._on_popup = on_popup
        self._on_new_tab = on_new_tab
        self.loadFinished.connect(self._try_autofill)

    def _try_autofill(self, ok: bool) -> None:
        if not ok or not self._pm.is_unlocked:
            return
        domain = self.url().host().removeprefix("www.")
        creds = self._pm.get(domain)
        if creds:
            username, password = creds
            js = (
                "document.dispatchEvent(new CustomEvent('__beepbeep_autofill', "
                "{detail: {username: " + json.dumps(username) + ", "
                "password: " + json.dumps(password) + "}}));"
            )
            self.page().runJavaScript(js)

    def createWindow(  # noqa: N802
        self, window_type: "QWebEnginePage.WebWindowType"
    ) -> "WebView":
        """Intercept new-window requests and open them as new tabs."""
        view = WebView(
            self.page().profile(),
            self._pm,
            self._config,
            self._on_popup,
            self._on_new_tab,
        )
        if self._on_popup:
            self._on_popup(view)
        return view

    def contextMenuEvent(self, event) -> None:  # noqa: ANN001
        """Custom context menu: standard items + 'Search with [Engine]' when text is selected."""
        menu = self.createStandardContextMenu()
        selected = self.selectedText().strip()
        if selected and self._config is not None:
            engine_name = self._config.search_engine_name()
            menu.addSeparator()
            search_action = menu.addAction(f"Search with {engine_name}")
            search_action.triggered.connect(
                lambda checked=False, t=selected: self._search_selected(t)
            )
        menu.exec(event.globalPos())

    def _search_selected(self, text: str) -> None:
        if self._config is None:
            return
        url = self._config.build_search_url(text)
        if self._on_new_tab:
            self._on_new_tab(url)
        else:
            self.setUrl(QUrl(url))


# ──────────────────────── Bookmark Dialog ────────────────────────────────────


class BookmarkDialog(QDialog):
    def __init__(self, bm: BookmarkManager, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Bookmarks")
        self.setMinimumSize(480, 320)
        self._bm = bm
        self._selected_url: Optional[str] = None

        layout = QVBoxLayout(self)

        self._list = QListWidget()
        self._refresh()
        layout.addWidget(self._list)

        btn_row = QHBoxLayout()
        open_btn = QPushButton("Open")
        del_btn = QPushButton("Delete")
        close_btn = QPushButton("Close")
        btn_row.addWidget(open_btn)
        btn_row.addWidget(del_btn)
        btn_row.addStretch()
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)

        open_btn.clicked.connect(self._open)
        del_btn.clicked.connect(self._delete)
        close_btn.clicked.connect(self.reject)
        self._list.doubleClicked.connect(self._open)

    def _refresh(self) -> None:
        self._list.clear()
        for bm in self._bm.all():
            self._list.addItem(f"{bm['title']}  —  {bm['url']}")

    def _open(self) -> None:
        row = self._list.currentRow()
        bms = self._bm.all()
        if 0 <= row < len(bms):
            self._selected_url = bms[row]["url"]
            self.accept()

    def _delete(self) -> None:
        row = self._list.currentRow()
        if row >= 0:
            self._bm.remove(row)
            self._refresh()

    def selected_url(self) -> Optional[str]:
        return self._selected_url


# ────────────────────────── Password Dialog ──────────────────────────────────


class PasswordDialog(QDialog):
    def __init__(self, pm: PasswordManager, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Password Manager")
        self.setMinimumSize(500, 380)
        self._pm = pm
        layout = QVBoxLayout(self)

        if not CRYPTO_AVAILABLE:
            layout.addWidget(
                QLabel(
                    "The 'cryptography' package is not installed.\n"
                    "Run:  pip install cryptography"
                )
            )
            layout.addWidget(
                QPushButton("Close", clicked=self.reject)  # type: ignore[call-arg]
            )
            return

        if not pm.is_unlocked:
            self._build_unlock_ui(layout)
        else:
            self._build_main_ui(layout)

    # ── Unlock screen ─────────────────────────────────────────────────────

    def _build_unlock_ui(self, layout: QVBoxLayout) -> None:
        form = QFormLayout()
        self._master_edit = QLineEdit()
        self._master_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._master_edit.setPlaceholderText("Enter master password")
        form.addRow("Master password:", self._master_edit)
        layout.addLayout(form)

        unlock_btn = QPushButton("Unlock")
        unlock_btn.clicked.connect(self._do_unlock)
        self._master_edit.returnPressed.connect(self._do_unlock)
        layout.addWidget(unlock_btn)
        layout.addStretch()

    def _do_unlock(self) -> None:
        pw = self._master_edit.text()
        if self._pm.unlock(pw):
            # Rebuild the dialog with the full UI
            for i in reversed(range(self.layout().count())):
                item = self.layout().takeAt(i)
                if item.widget():
                    item.widget().deleteLater()
            self._build_main_ui(self.layout())  # type: ignore[arg-type]
        else:
            QMessageBox.warning(
                self, "Error", "Wrong master password or corrupted credential store."
            )

    # ── Main credential UI ────────────────────────────────────────────────

    def _build_main_ui(self, layout: QVBoxLayout) -> None:
        self._cred_list = QListWidget()
        self._refresh_list()
        layout.addWidget(self._cred_list)

        form = QFormLayout()
        self._domain_edit = QLineEdit()
        self._user_edit = QLineEdit()
        self._pass_edit = QLineEdit()
        self._pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Domain:", self._domain_edit)
        form.addRow("Username:", self._user_edit)
        form.addRow("Password:", self._pass_edit)
        layout.addLayout(form)

        btn_row = QHBoxLayout()
        save_btn = QPushButton("Save")
        del_btn = QPushButton("Delete")
        export_btn = QPushButton("Export JSON…")
        import_btn = QPushButton("Import JSON…")
        close_btn = QPushButton("Close")
        for btn in (save_btn, del_btn, export_btn, import_btn):
            btn_row.addWidget(btn)
        btn_row.addStretch()
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)

        save_btn.clicked.connect(self._save_cred)
        del_btn.clicked.connect(self._delete_cred)
        export_btn.clicked.connect(self._export)
        import_btn.clicked.connect(self._import)
        close_btn.clicked.connect(self.accept)
        self._cred_list.currentRowChanged.connect(self._populate_form)

    def _refresh_list(self) -> None:
        self._cred_list.clear()
        for d in self._pm.all_domains():
            self._cred_list.addItem(d)

    def _populate_form(self, row: int) -> None:
        domains = self._pm.all_domains()
        if 0 <= row < len(domains):
            domain = domains[row]
            creds = self._pm.get(domain)
            self._domain_edit.setText(domain)
            if creds:
                self._user_edit.setText(creds[0])
                self._pass_edit.setText(creds[1])

    def _save_cred(self) -> None:
        domain = self._domain_edit.text().strip()
        if domain:
            self._pm.save(domain, self._user_edit.text(), self._pass_edit.text())
            self._refresh_list()

    def _delete_cred(self) -> None:
        domains = self._pm.all_domains()
        row = self._cred_list.currentRow()
        if 0 <= row < len(domains):
            self._pm.delete(domains[row])
            self._refresh_list()
            for w in (self._domain_edit, self._user_edit, self._pass_edit):
                w.clear()

    def _export(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Credentials", "", "JSON files (*.json)"
        )
        if path:
            self._pm.export_json(path)
            QMessageBox.information(self, "Exported", f"Saved to:\n{path}")

    def _import(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Import Credentials", "", "JSON files (*.json)"
        )
        if path:
            n = self._pm.import_json(path)
            self._refresh_list()
            QMessageBox.information(self, "Imported", f"{n} credential(s) imported.")


# ────────────────────────── Draggable Tab Bar ─────────────────────────────────


class DraggableTabBar(QTabBar):
    """
    QTabBar subclass that:
    - Allows dragging the frameless window by clicking empty space in the tab bar.
    - Shows a custom context menu on right-click.
    """

    def __init__(self, window: QMainWindow, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._window = window
        self._drag_start: Optional[QPoint] = None
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

    def mousePressEvent(self, event) -> None:  # noqa: ANN001
        if event.button() == Qt.MouseButton.LeftButton:
            # Only initiate window drag when clicking in empty tab-bar space.
            if self.tabAt(event.pos()) == -1:
                self._drag_start = (
                    event.globalPosition().toPoint()
                    - self._window.frameGeometry().topLeft()
                )
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event) -> None:  # noqa: ANN001
        if (
            event.buttons() & Qt.MouseButton.LeftButton
            and self._drag_start is not None
        ):
            self._window.move(event.globalPosition().toPoint() - self._drag_start)
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event) -> None:  # noqa: ANN001
        self._drag_start = None
        super().mouseReleaseEvent(event)


# ─────────────────────────── Onboarding Wizard ───────────────────────────────


class OnboardingWizard(QDialog):
    """First-launch wizard: import bookmarks/passwords, pick search engine."""

    def __init__(
        self,
        bm: BookmarkManager,
        pm: PasswordManager,
        config: ConfigManager,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Welcome to BeepBeep Browser")
        self.setMinimumSize(520, 440)
        self._bm = bm
        self._pm = pm
        self._config = config
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # Header
        title_lbl = QLabel("🦆  Welcome to BeepBeep Browser")
        title_lbl.setStyleSheet("font-size: 18px; font-weight: bold; padding: 6px 0;")
        layout.addWidget(title_lbl)

        desc_lbl = QLabel(
            "Let's get you set up. First create a Master Password to secure your data,"
            " then optionally import bookmarks and passwords."
        )
        desc_lbl.setWordWrap(True)
        layout.addWidget(desc_lbl)

        # ── Master Password (required) ────────────────────────────────────
        if CRYPTO_AVAILABLE:
            mp_header = QLabel("🔐  Create Master Password  (required)")
            mp_header.setStyleSheet("font-weight: bold; margin-top: 8px;")
            layout.addWidget(mp_header)

            mp_desc = QLabel(
                "Your Master Password encrypts all stored passwords and bookmarks."
                " Choose something strong and memorable — it cannot be recovered."
            )
            mp_desc.setWordWrap(True)
            layout.addWidget(mp_desc)

            mp_form = QFormLayout()
            self._mp_edit = QLineEdit()
            self._mp_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self._mp_edit.setPlaceholderText("At least 8 characters")
            self._mp_confirm = QLineEdit()
            self._mp_confirm.setEchoMode(QLineEdit.EchoMode.Password)
            self._mp_confirm.setPlaceholderText("Re-enter to confirm")
            mp_form.addRow("Password:", self._mp_edit)
            mp_form.addRow("Confirm:", self._mp_confirm)
            layout.addLayout(mp_form)

            self._mp_status = QLabel("")
            self._mp_status.setStyleSheet("color: #ff6b6b;")
            layout.addWidget(self._mp_status)
        else:
            no_crypto_lbl = QLabel(
                "⚠️  The 'cryptography' package is not installed — "
                "data will be stored unencrypted."
            )
            no_crypto_lbl.setWordWrap(True)
            no_crypto_lbl.setStyleSheet("color: #ffa040;")
            layout.addWidget(no_crypto_lbl)

        # ── Bookmarks ────────────────────────────────────────────────────
        bm_header = QLabel("Import Bookmarks")
        bm_header.setStyleSheet("font-weight: bold; margin-top: 8px;")
        layout.addWidget(bm_header)

        bm_row = QHBoxLayout()
        bm_html_btn = QPushButton("Import from HTML…")
        bm_json_btn = QPushButton("Import from JSON…")
        self._bm_status = QLabel("No file selected")
        bm_html_btn.clicked.connect(self._import_bm_html)
        bm_json_btn.clicked.connect(self._import_bm_json)
        bm_row.addWidget(bm_html_btn)
        bm_row.addWidget(bm_json_btn)
        bm_row.addWidget(self._bm_status)
        bm_row.addStretch()
        layout.addLayout(bm_row)

        # ── Passwords ────────────────────────────────────────────────────
        pw_header = QLabel("Import Passwords")
        pw_header.setStyleSheet("font-weight: bold; margin-top: 8px;")
        layout.addWidget(pw_header)

        pw_desc = QLabel(
            "Import existing passwords from a plain JSON file "
            "(they will be re-encrypted with your Master Password)."
        )
        pw_desc.setWordWrap(True)
        layout.addWidget(pw_desc)

        pw_row = QHBoxLayout()
        pw_btn = QPushButton("Import from JSON…")
        self._pw_status = QLabel("No file selected")
        pw_btn.clicked.connect(self._import_passwords)
        pw_row.addWidget(pw_btn)
        pw_row.addWidget(self._pw_status)
        pw_row.addStretch()
        layout.addLayout(pw_row)

        # ── Search engine ────────────────────────────────────────────────
        se_header = QLabel("Default Search Engine")
        se_header.setStyleSheet("font-weight: bold; margin-top: 8px;")
        layout.addWidget(se_header)

        se_row = QHBoxLayout()
        self._se_combo = QComboBox()
        for key, (name, _) in SEARCH_ENGINES.items():
            self._se_combo.addItem(name, key)
        se_row.addWidget(self._se_combo)
        se_row.addStretch()
        layout.addLayout(se_row)

        layout.addStretch()

        finish_btn = QPushButton("Get Started!")
        finish_btn.clicked.connect(self._finish)
        layout.addWidget(finish_btn)

    # ── Import helpers ────────────────────────────────────────────────────

    def _import_bm_html(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Bookmarks",
            "",
            "HTML files (*.html *.htm);;All files (*)",
        )
        if path:
            try:
                n = self._bm.import_html(path)
                self._bm_status.setText(f"Imported {n} bookmark(s)")
            except Exception as exc:
                self._bm_status.setText(f"Error: {exc}")

    def _import_bm_json(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Import Bookmarks", "", "JSON files (*.json);;All files (*)"
        )
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            count = 0
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and "url" in item:
                        self._bm.add(item.get("title", item["url"]), item["url"])
                        count += 1
            self._bm_status.setText(f"Imported {count} bookmark(s)")
        except Exception as exc:
            self._bm_status.setText(f"Error: {exc}")

    def _import_passwords(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Import Passwords", "", "JSON files (*.json);;All files (*)"
        )
        if not path:
            return
        # Use the master password the user is creating in this wizard (if set).
        if CRYPTO_AVAILABLE and hasattr(self, "_mp_edit"):
            master = self._mp_edit.text()
            if not master:
                self._pw_status.setText("Enter a Master Password above first.")
                return
            ok = self._pm.unlock(master)
        else:
            master, ok_input = QInputDialog.getText(
                self,
                "Master Password",
                "Enter master password:",
                QLineEdit.EchoMode.Password,
            )
            ok = ok_input and self._pm.unlock(master)
        if ok:
            try:
                n = self._pm.import_json(path)
                self._pw_status.setText(f"Imported {n} credential(s)")
            except Exception as exc:
                self._pw_status.setText(f"Error: {exc}")
        else:
            self._pw_status.setText("Wrong password or could not initialise store")

    def _finish(self) -> None:
        if CRYPTO_AVAILABLE and hasattr(self, "_mp_edit"):
            pw = self._mp_edit.text()
            confirm = self._mp_confirm.text()
            if not pw:
                self._mp_status.setText("Master password is required.")
                return
            if len(pw) < 8:
                self._mp_status.setText("Password must be at least 8 characters.")
                return
            if pw != confirm:
                self._mp_status.setText("Passwords do not match.")
                return
            if not self._pm.unlock(pw):
                self._mp_status.setText("Failed to initialise credential store.")
                return
            # Unlock bookmarks with the same Fernet key so they are encrypted too.
            if self._pm.fernet is not None:
                self._bm.unlock(self._pm.fernet)
        idx = self._se_combo.currentIndex()
        key = self._se_combo.itemData(idx)
        if key:
            self._config.search_engine = key
        self._config.onboarding_done = True
        self._config.save()
        self.accept()


# ────────────────────────────── Lock Screen ──────────────────────────────────


class LockScreen(QWidget):
    """
    Minimalist fullscreen overlay shown on startup.

    The browser window is visible behind the overlay but inaccessible until
    the correct Master Password is entered.  On success the ``unlocked``
    signal is emitted and the caller is responsible for hiding/removing this
    widget.
    """

    unlocked = Signal()

    def __init__(self, pm: PasswordManager, parent: QWidget) -> None:
        super().__init__(parent)
        self._pm = pm
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet(
            "LockScreen { background: rgba(8, 8, 14, 0.96); }"
        )
        self._build_ui()

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Frosted-glass card
        card = QWidget()
        card.setFixedWidth(360)
        card.setStyleSheet(
            "QWidget {"
            "  background: rgba(28, 28, 38, 0.94);"
            "  border: 1px solid rgba(255,255,255,0.12);"
            "  border-radius: 18px;"
            "}"
        )
        form = QVBoxLayout(card)
        form.setSpacing(14)
        form.setContentsMargins(32, 36, 32, 32)

        icon_lbl = QLabel("🔒")
        icon_lbl.setStyleSheet("font-size: 42px; background: transparent; border: none;")
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        title_lbl = QLabel("BeepBeep Browser")
        title_lbl.setStyleSheet(
            "font-size: 22px; font-weight: bold; color: #e2e2ee;"
            " background: transparent; border: none;"
        )
        title_lbl.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        sub_lbl = QLabel("Enter your Master Password to continue")
        sub_lbl.setStyleSheet(
            "font-size: 12px; color: rgba(175, 175, 195, 0.85);"
            " background: transparent; border: none;"
        )
        sub_lbl.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        self._pw_edit = QLineEdit()
        self._pw_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._pw_edit.setPlaceholderText("Master Password")
        self._pw_edit.setFixedHeight(40)
        self._pw_edit.setStyleSheet(
            "QLineEdit {"
            "  background: rgba(18, 18, 26, 0.92);"
            "  border: 1px solid rgba(255,255,255,0.16);"
            "  border-radius: 9px;"
            "  padding: 0 14px;"
            "  font-size: 14px;"
            "  color: #e2e2ee;"
            "}"
            "QLineEdit:focus { border-color: rgba(74, 158, 255, 0.65); }"
        )

        self._err_lbl = QLabel("")
        self._err_lbl.setStyleSheet(
            "color: #ff6b6b; font-size: 12px; background: transparent; border: none;"
        )
        self._err_lbl.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self._err_lbl.hide()

        unlock_btn = QPushButton("Unlock")
        unlock_btn.setFixedHeight(40)
        unlock_btn.setStyleSheet(
            "QPushButton {"
            "  background: qlineargradient("
            "    x1:0, y1:0, x2:1, y2:0,"
            "    stop:0 #4a9eff, stop:1 #6e5fff"
            "  );"
            "  border: none;"
            "  border-radius: 9px;"
            "  color: #ffffff;"
            "  font-size: 14px;"
            "  font-weight: bold;"
            "}"
            "QPushButton:hover { background: qlineargradient("
            "  x1:0, y1:0, x2:1, y2:0, stop:0 #5aaaff, stop:1 #7e6fff); }"
            "QPushButton:pressed { background: #3a8eef; }"
        )

        form.addWidget(icon_lbl)
        form.addWidget(title_lbl)
        form.addWidget(sub_lbl)
        form.addWidget(self._pw_edit)
        form.addWidget(self._err_lbl)
        form.addWidget(unlock_btn)

        outer.addWidget(card)

        unlock_btn.clicked.connect(self._do_unlock)
        self._pw_edit.returnPressed.connect(self._do_unlock)

    def _do_unlock(self) -> None:
        pw = self._pw_edit.text()
        if self._pm.unlock(pw):
            self._err_lbl.hide()
            self.unlocked.emit()
        else:
            self._pw_edit.clear()
            self._err_lbl.setText("Incorrect password — data remains encrypted.")
            self._err_lbl.show()

    def showEvent(self, event) -> None:  # noqa: ANN001
        super().showEvent(event)
        parent_w = self.parentWidget()
        if parent_w:
            self.resize(parent_w.size())
        self._pw_edit.setFocus()


# ──────────────────────────── Settings Dialog ────────────────────────────────


class SettingsDialog(QDialog):
    """Settings dialog: choose search engine."""

    def __init__(self, config: ConfigManager, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumSize(360, 160)
        self._config = config
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        form = QFormLayout()
        self._se_combo = QComboBox()
        for key, (name, _) in SEARCH_ENGINES.items():
            self._se_combo.addItem(name, key)

        current = self._config.search_engine
        for i in range(self._se_combo.count()):
            if self._se_combo.itemData(i) == current:
                self._se_combo.setCurrentIndex(i)
                break

        form.addRow("Search Engine:", self._se_combo)
        layout.addLayout(form)
        layout.addStretch()

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._save_and_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _save_and_accept(self) -> None:
        key = self._se_combo.itemData(self._se_combo.currentIndex())
        if key:
            self._config.search_engine = key
            self._config.save()
        self.accept()


class BrowserWindow(QMainWindow):
    def __init__(self, config: ConfigManager) -> None:
        super().__init__()
        self.setWindowTitle("BeepBeep Browser")
        self.resize(1280, 800)

        # Always-on-top, frameless "floating" window.
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint
        )

        # Lock-screen overlay (None until show_lock_screen() is called).
        self._lock_screen: Optional[LockScreen] = None

        self._config = config
        app_dir = _app_dir()
        self._bm = BookmarkManager(app_dir)
        self._pm = PasswordManager(app_dir)

        # Single shared profile minimises per-tab memory overhead.
        self._profile = QWebEngineProfile("beepbeep", self)
        self._setup_profile()

        # ── Central widget layout ────────────────────────────────────────
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setSpacing(0)
        root.setContentsMargins(0, 0, 0, 0)

        # Slim progress bar (3 px tall, hidden when not loading).
        self._progress = QProgressBar()
        self._progress.setFixedHeight(3)
        self._progress.setTextVisible(False)
        self._progress.setRange(0, 100)
        self._progress.hide()
        self._progress.setStyleSheet(
            "QProgressBar { background: transparent; border: none; }"
            "QProgressBar::chunk { background: "
            "  qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #4a9eff,stop:1 #7b5fff); }"
        )
        root.addWidget(self._progress)

        # Address bar (hidden by default, shown with Ctrl+L).
        # maximumHeight is animated — do NOT call setFixedHeight here.
        self._address_bar = QLineEdit()
        self._address_bar.setPlaceholderText("Enter URL or search…")
        self._address_bar.setMinimumHeight(0)
        self._address_bar.setMaximumHeight(0)   # starts collapsed
        self._address_bar.hide()
        self._address_bar.returnPressed.connect(self._navigate_from_bar)
        root.addWidget(self._address_bar)

        # Address-bar slide animation (reused for show and hide).
        self._addr_anim = QPropertyAnimation(self._address_bar, b"maximumHeight", self)
        self._addr_anim.setDuration(180)
        self._addr_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

        # ── Tab widget with custom (draggable) tab bar ───────────────────
        self._tabs = QTabWidget()
        self._tab_bar = DraggableTabBar(self)
        self._tabs.setTabBar(self._tab_bar)
        self._tabs.setTabsClosable(True)
        self._tabs.setMovable(True)
        self._tabs.setDocumentMode(True)
        self._tabs.tabCloseRequested.connect(self._close_tab)
        self._tabs.currentChanged.connect(self._on_tab_changed)
        # Enable right-click context menu on the tab bar.
        self._tab_bar.customContextMenuRequested.connect(self._show_tab_context_menu)
        root.addWidget(self._tabs)

        # ── Custom title-bar corner widgets ──────────────────────────────
        # Left corner: window controls (minimize / close).
        left_corner = QWidget()
        left_layout = QHBoxLayout(left_corner)
        left_layout.setContentsMargins(4, 2, 4, 2)
        left_layout.setSpacing(4)
        min_btn = QPushButton("─")
        min_btn.setFixedSize(22, 22)
        min_btn.setFlat(True)
        min_btn.setToolTip("Minimize")
        min_btn.clicked.connect(self.showMinimized)
        close_btn = QPushButton("✕")
        close_btn.setFixedSize(22, 22)
        close_btn.setFlat(True)
        close_btn.setToolTip("Close")
        close_btn.clicked.connect(self.close)
        left_layout.addWidget(min_btn)
        left_layout.addWidget(close_btn)
        self._tabs.setCornerWidget(left_corner, Qt.Corner.TopLeftCorner)

        # Right corner: new-tab button + settings gear.
        right_corner = QWidget()
        right_layout = QHBoxLayout(right_corner)
        right_layout.setContentsMargins(4, 2, 4, 2)
        right_layout.setSpacing(4)
        new_tab_btn = QPushButton("+")
        new_tab_btn.setFixedSize(26, 22)
        new_tab_btn.setFlat(True)
        new_tab_btn.setToolTip("New tab  (Ctrl+T)")
        new_tab_btn.clicked.connect(lambda: self.open_tab())
        settings_btn = QPushButton("⚙")
        settings_btn.setFixedSize(26, 22)
        settings_btn.setFlat(True)
        settings_btn.setToolTip("Settings")
        settings_btn.clicked.connect(self._show_settings)
        right_layout.addWidget(new_tab_btn)
        right_layout.addWidget(settings_btn)
        self._tabs.setCornerWidget(right_corner, Qt.Corner.TopRightCorner)

        # ── Apply glassmorphism / pill-tab stylesheet ─────────────────────
        self._apply_stylesheet()

        # ── Try Windows Acrylic blur-behind ──────────────────────────────
        self._apply_acrylic_effect()

        # ── Keyboard shortcuts ───────────────────────────────────────────
        self._bind_shortcuts()

        # ── GC timer: Python garbage collection every 60 seconds ─────────
        self._gc_timer = QTimer(self)
        self._gc_timer.timeout.connect(gc.collect)
        self._gc_timer.start(60_000)

        # Open the first tab.
        self.open_tab(HOME_URL)

    # ── Profile setup ─────────────────────────────────────────────────────

    def _setup_profile(self) -> None:
        p = self._profile

        # Tracker / ad blocker.
        self._blocker = TrackingBlocker()
        p.setUrlRequestInterceptor(self._blocker)

        # Use disk cache to reduce network load across restarts.
        p.setHttpCacheType(QWebEngineProfile.HttpCacheType.DiskHttpCache)
        p.setPersistentCookiesPolicy(
            QWebEngineProfile.PersistentCookiesPolicy.AllowPersistentCookies
        )

        settings = p.settings()
        settings.setAttribute(QWebEngineSettings.WebAttribute.PluginsEnabled, False)
        settings.setAttribute(
            QWebEngineSettings.WebAttribute.ScrollAnimatorEnabled, False
        )

        # Force dark mode if supported by this Qt build (Qt ≥ 6.7).
        try:
            settings.setAttribute(
                QWebEngineSettings.WebAttribute.ForceDarkMode, True
            )
        except AttributeError:
            pass

        # Inject autofill listener into every page.
        self._inject_script(
            name="BeepBeepAutofill",
            source=_AUTOFILL_LISTENER_JS,
            point=QWebEngineScript.InjectionPoint.DocumentReady,
            world=QWebEngineScript.ScriptWorldId.MainWorld,
        )

        # Inject dark-mode CSS into every page (fallback for older Qt).
        self._inject_script(
            name="BeepBeepDarkMode",
            source=_DARK_MODE_JS,
            point=QWebEngineScript.InjectionPoint.DocumentCreation,
            world=QWebEngineScript.ScriptWorldId.MainWorld,
            sub_frames=True,
        )

    def _inject_script(
        self,
        *,
        name: str,
        source: str,
        point: QWebEngineScript.InjectionPoint,
        world: QWebEngineScript.ScriptWorldId,
        sub_frames: bool = False,
    ) -> None:
        script = QWebEngineScript()
        script.setName(name)
        script.setSourceCode(source)
        script.setInjectionPoint(point)
        script.setWorldId(world)
        script.setRunsOnSubFrames(sub_frames)
        self._profile.scripts().insert(script)

    # ── Stylesheet & visual helpers ───────────────────────────────────────

    def _apply_stylesheet(self) -> None:
        """Apply glassmorphism + pill-tab stylesheet to the whole window."""
        self.setStyleSheet(
            # ── Window / central background ──
            "QMainWindow, QWidget { background: rgba(18, 18, 24, 0.98); }"

            # ── Tab pane ──
            "QTabWidget::pane { border: none; background: transparent; }"
            "QTabWidget::tab-bar { alignment: left; }"

            # ── Tab bar background ──
            "QTabBar {"
            "  background: rgba(22, 22, 30, 0.90);"
            "  border-bottom: 1px solid rgba(255,255,255,0.07);"
            "}"

            # ── Pill tabs ──
            "QTabBar::tab {"
            "  background: rgba(255,255,255,0.05);"
            "  border: 1px solid rgba(255,255,255,0.09);"
            "  border-radius: 13px;"
            "  padding: 4px 20px;"
            "  margin: 3px 2px;"
            "  color: rgba(200,200,215,0.82);"
            "  min-width: 70px;"
            "  max-width: 210px;"
            "}"
            "QTabBar::tab:selected {"
            "  background: rgba(74,158,255,0.17);"
            "  border: 1.5px solid rgba(74,158,255,0.72);"
            "  color: #ffffff;"
            "}"
            "QTabBar::tab:only-one {"
            "  background: rgba(74,158,255,0.17);"
            "  border: 1.5px solid rgba(74,158,255,0.72);"
            "  color: #ffffff;"
            "}"
            "QTabBar::tab:hover:!selected {"
            "  background: rgba(255,255,255,0.11);"
            "  border-color: rgba(255,255,255,0.18);"
            "}"
            "QTabBar::close-button { image: none; }"

            # ── Address bar ──
            "QLineEdit {"
            "  background: rgba(28,28,38,0.92);"
            "  border: 1px solid rgba(255,255,255,0.11);"
            "  border-radius: 7px;"
            "  padding: 0 12px;"
            "  color: #dcdce8;"
            "  font-size: 13px;"
            "  selection-background-color: rgba(74,158,255,0.40);"
            "}"
            "QLineEdit:focus {"
            "  border-color: rgba(74,158,255,0.60);"
            "  background: rgba(28,28,42,0.96);"
            "}"

            # ── Flat / icon buttons ──
            "QPushButton:flat {"
            "  background: transparent;"
            "  border: none;"
            "  color: #c8c8d6;"
            "}"
            "QPushButton:flat:hover {"
            "  background: rgba(255,255,255,0.09);"
            "  border-radius: 5px;"
            "}"

            # ── Normal buttons (dialogs, etc.) ──
            "QPushButton {"
            "  background: rgba(255,255,255,0.06);"
            "  border: 1px solid rgba(255,255,255,0.10);"
            "  border-radius: 6px;"
            "  color: #c8c8d6;"
            "  padding: 3px 10px;"
            "}"
            "QPushButton:hover {"
            "  background: rgba(255,255,255,0.11);"
            "  border-color: rgba(255,255,255,0.20);"
            "}"
            "QPushButton:pressed { background: rgba(74,158,255,0.20); }"

            # ── Status bar ──
            "QStatusBar {"
            "  background: rgba(14,14,20,0.96);"
            "  color: rgba(180,180,200,0.70);"
            "  font-size: 11px;"
            "  border-top: 1px solid rgba(255,255,255,0.05);"
            "}"

            # ── Progress bar ──
            "QProgressBar { background: transparent; border: none; }"
            "QProgressBar::chunk {"
            "  background: qlineargradient("
            "    x1:0,y1:0,x2:1,y2:0,stop:0 #4a9eff,stop:1 #7b5fff); }"
        )

    def _apply_acrylic_effect(self) -> None:
        """
        Attempt to enable Windows 10/11 Acrylic blur-behind via DWM.

        Silently ignored on non-Windows or older Windows builds that lack the
        required DWM attributes.
        """
        if sys.platform != "win32":
            return
        try:
            import ctypes
            import ctypes.wintypes
            hwnd = int(self.winId())
            dwmapi = ctypes.windll.dwmapi  # type: ignore[attr-defined]
            # Enable immersive dark mode title bar (if applicable).
            DWMWA_USE_IMMERSIVE_DARK_MODE = 20
            dwmapi.DwmSetWindowAttribute(
                hwnd,
                DWMWA_USE_IMMERSIVE_DARK_MODE,
                ctypes.byref(ctypes.c_int(1)),
                ctypes.sizeof(ctypes.c_int),
            )
            # Request Acrylic system backdrop (Windows 11 22H2+).
            DWMWA_SYSTEMBACKDROP_TYPE = 38
            dwmapi.DwmSetWindowAttribute(
                hwnd,
                DWMWA_SYSTEMBACKDROP_TYPE,
                ctypes.byref(ctypes.c_int(3)),   # 3 = Acrylic
                ctypes.sizeof(ctypes.c_int),
            )
            self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        except Exception:
            pass  # Non-critical; gracefully degrade on unsupported hosts.

    # ── Lock screen ───────────────────────────────────────────────────────

    def show_lock_screen(self) -> None:
        """Overlay the browser window with the Master Password lock screen."""
        self._lock_screen = LockScreen(self._pm, self)
        self._lock_screen.unlocked.connect(self._on_unlocked)
        self._lock_screen.show()
        self._lock_screen.raise_()

    def _on_unlocked(self) -> None:
        """Called when the lock screen emits ``unlocked``."""
        if self._lock_screen is not None:
            self._lock_screen.hide()
            self._lock_screen.deleteLater()
            self._lock_screen = None
        # Unlock the bookmark manager with the same derived key.
        if CRYPTO_AVAILABLE and self._pm.fernet is not None:
            self._bm.unlock(self._pm.fernet)

    # ── Qt event overrides ────────────────────────────────────────────────

    def showEvent(self, event) -> None:  # noqa: ANN001
        super().showEvent(event)
        if self._lock_screen is not None:
            self._lock_screen.resize(self.size())
            self._lock_screen.raise_()

    def resizeEvent(self, event) -> None:  # noqa: ANN001
        super().resizeEvent(event)
        if self._lock_screen is not None:
            self._lock_screen.resize(self.size())

    # ── Tab management ────────────────────────────────────────────────────

    def open_tab(self, url: str = HOME_URL) -> WebView:
        """Create a new tab.  Web content is loaded lazily on first focus."""
        view = self._make_view()
        view._pending_url = url  # type: ignore[attr-defined]
        idx = self._tabs.addTab(view, "New Tab")
        self._tabs.setCurrentIndex(idx)
        # Actual setUrl() call is deferred to _on_tab_changed.
        return view

    def _make_view(self) -> WebView:
        """Create a WebView and wire up all signals."""
        view = WebView(
            self._profile,
            self._pm,
            config=self._config,
            on_popup=self._adopt_popup_view,
            on_new_tab=lambda url: self.open_tab(url),
        )
        view.titleChanged.connect(lambda t, v=view: self._set_tab_title(v, t))
        view.loadStarted.connect(lambda v=view: self._on_load_started(v))
        view.loadProgress.connect(lambda pct, v=view: self._on_load_progress(v, pct))
        view.loadFinished.connect(lambda ok, v=view: self._on_load_finished(v, ok))
        view.urlChanged.connect(lambda u: self._on_url_changed(u))
        view.page().linkHovered.connect(
            lambda url: self.statusBar().showMessage(url, 2000)
        )
        return view

    def _adopt_popup_view(self, view: WebView) -> None:
        """Register signals for a popup/new-window view and add it as a tab."""
        view.titleChanged.connect(lambda t, v=view: self._set_tab_title(v, t))
        view.loadStarted.connect(lambda v=view: self._on_load_started(v))
        view.loadProgress.connect(lambda pct, v=view: self._on_load_progress(v, pct))
        view.loadFinished.connect(lambda ok, v=view: self._on_load_finished(v, ok))
        view.urlChanged.connect(lambda u: self._on_url_changed(u))
        view.page().linkHovered.connect(
            lambda url: self.statusBar().showMessage(url, 2000)
        )
        idx = self._tabs.addTab(view, "New Tab")
        self._tabs.setCurrentIndex(idx)

    def _close_tab(self, index: int) -> None:
        if self._tabs.count() <= 1:
            self.close()
            return
        widget = self._tabs.widget(index)
        self._tabs.removeTab(index)
        if widget:
            widget.deleteLater()

    def _current_view(self) -> Optional[WebView]:
        w = self._tabs.currentWidget()
        return w if isinstance(w, WebView) else None

    # ── Navigation ────────────────────────────────────────────────────────

    def _navigate_from_bar(self) -> None:
        text = self._address_bar.text().strip()
        if not text:
            return
        # Treat as URL if it looks like one, otherwise use the configured search engine.
        if "." in text and " " not in text:
            url = (
                text
                if text.startswith(("http://", "https://", "file://"))
                else "https://" + text
            )
        else:
            url = self._config.build_search_url(text)
        view = self._current_view()
        if view:
            view.setUrl(QUrl(url))
        self._hide_address_bar()

    # ── Address-bar animation helpers ─────────────────────────────────────

    def _show_address_bar(self) -> None:
        if self._address_bar.isVisible():
            return
        view = self._current_view()
        if view:
            self._address_bar.setText(view.url().toString())
        self._addr_anim.stop()
        try:
            self._addr_anim.finished.disconnect()
        except RuntimeError:
            pass
        self._address_bar.setMaximumHeight(0)
        self._address_bar.show()
        self._addr_anim.setStartValue(0)
        self._addr_anim.setEndValue(32)
        self._addr_anim.start()
        self._address_bar.setFocus()
        self._address_bar.selectAll()

    def _hide_address_bar(self) -> None:
        if not self._address_bar.isVisible():
            return
        self._addr_anim.stop()
        try:
            self._addr_anim.finished.disconnect()
        except RuntimeError:
            pass
        self._addr_anim.setStartValue(self._address_bar.maximumHeight() or 32)
        self._addr_anim.setEndValue(0)
        self._addr_anim.finished.connect(self._address_bar.hide)
        self._addr_anim.start()

    def _toggle_address_bar(self) -> None:
        if self._address_bar.isVisible():
            self._hide_address_bar()
        else:
            self._show_address_bar()

    # ── Bookmarks ─────────────────────────────────────────────────────────

    def _add_bookmark(self) -> None:
        view = self._current_view()
        if view:
            self._bm.add(
                view.title() or view.url().toString(), view.url().toString()
            )
            self.statusBar().showMessage("Bookmarked!", 2000)

    def _show_bookmarks(self) -> None:
        dlg = BookmarkDialog(self._bm, self)
        if dlg.exec() == QDialog.DialogCode.Accepted and dlg.selected_url():
            view = self._current_view()
            if view:
                view.setUrl(QUrl(dlg.selected_url()))

    # ── Password manager ──────────────────────────────────────────────────

    def _show_passwords(self) -> None:
        PasswordDialog(self._pm, self).exec()

    # ── Settings / search engine ──────────────────────────────────────────

    def _show_settings(self) -> None:
        SettingsDialog(self._config, self).exec()

    def _set_search_engine(self) -> None:
        """Quick-pick dialog for selecting the search engine."""
        names = [SEARCH_ENGINES[k][0] for k in SEARCH_ENGINES]
        current_name = self._config.search_engine_name()
        current_idx = names.index(current_name) if current_name in names else 0
        choice, ok = QInputDialog.getItem(
            self,
            "Set Search Engine",
            "Choose your default search engine:",
            names,
            current_idx,
            False,
        )
        if ok and choice:
            for key, (name, _) in SEARCH_ENGINES.items():
                if name == choice:
                    self._config.search_engine = key
                    self._config.save()
                    self.statusBar().showMessage(
                        f"Search engine set to {name}.", 2000
                    )
                    break

    # ── Cache ─────────────────────────────────────────────────────────────

    def _clear_cache(self) -> None:
        self._profile.clearHttpCache()
        self.statusBar().showMessage("Cache cleared.", 3000)

    # ── Tab-bar context menu ──────────────────────────────────────────────

    def _show_tab_context_menu(self, pos: QPoint) -> None:
        """Right-click context menu on the tab bar."""
        menu = QMenu(self)
        menu.addAction("New Tab", lambda: self.open_tab())
        menu.addSeparator()
        is_on_top = bool(self.windowFlags() & Qt.WindowType.WindowStaysOnTopHint)
        on_top_act = menu.addAction("Always on Top")
        on_top_act.setCheckable(True)
        on_top_act.setChecked(is_on_top)
        on_top_act.triggered.connect(self._toggle_always_on_top)
        menu.addSeparator()
        menu.addAction("Settings", self._show_settings)
        menu.addAction("Set Search Engine", self._set_search_engine)
        menu.addSeparator()
        menu.addAction("Clear Cache", self._clear_cache)
        menu.exec(self._tab_bar.mapToGlobal(pos))

    def _toggle_always_on_top(self) -> None:
        flags = self.windowFlags()
        if flags & Qt.WindowType.WindowStaysOnTopHint:
            flags &= ~Qt.WindowType.WindowStaysOnTopHint
        else:
            flags |= Qt.WindowType.WindowStaysOnTopHint
        self.setWindowFlags(flags)
        self.show()

    # ── Load event plumbing ───────────────────────────────────────────────

    def _on_load_started(self, view: WebView) -> None:
        if view is self._current_view():
            self._progress.setValue(0)
            self._progress.show()

    def _on_load_progress(self, view: WebView, pct: int) -> None:
        if view is self._current_view():
            self._progress.setValue(pct)

    def _on_load_finished(self, view: WebView, _ok: bool) -> None:
        if view is self._current_view():
            self._progress.hide()
            self._progress.setValue(0)

    def _set_tab_title(self, view: WebView, title: str) -> None:
        idx = self._tabs.indexOf(view)
        if idx >= 0:
            self._tabs.setTabText(idx, (title[:28] + "…") if len(title) > 28 else title or "New Tab")

    def _on_tab_changed(self, _index: int) -> None:
        view = self._current_view()
        if view is None:
            return
        # Lazy load: trigger the first page load when the tab is focused.
        pending = getattr(view, "_pending_url", None)
        if pending is not None:
            view._pending_url = None  # type: ignore[attr-defined]
            view.setUrl(QUrl(pending))
        if self._address_bar.isVisible():
            self._address_bar.setText(view.url().toString())

    def _on_url_changed(self, url: QUrl) -> None:
        if self._address_bar.isVisible():
            view = self._current_view()
            if view and view.url() == url:
                self._address_bar.setText(url.toString())

    # ── Keyboard shortcuts ────────────────────────────────────────────────

    def _bind_shortcuts(self) -> None:
        pairs = [
            ("Ctrl+T", lambda: self.open_tab()),
            ("Ctrl+W", lambda: self._close_tab(self._tabs.currentIndex())),
            ("Ctrl+L", self._toggle_address_bar),
            ("Ctrl+D", self._add_bookmark),
            ("Ctrl+B", self._show_bookmarks),
            ("Ctrl+P", self._show_passwords),
            ("Ctrl+R", lambda: self._current_view() and self._current_view().reload()),
            ("F5", lambda: self._current_view() and self._current_view().reload()),
            ("Alt+Left", lambda: self._current_view() and self._current_view().back()),
            (
                "Alt+Right",
                lambda: self._current_view() and self._current_view().forward(),
            ),
            ("F11", self._toggle_fullscreen),
            ("Escape", self._on_escape),
        ]
        for key, slot in pairs:
            sc = QShortcut(QKeySequence(key), self)
            sc.activated.connect(slot)

    def _toggle_fullscreen(self) -> None:
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()

    def _on_escape(self) -> None:
        if self._address_bar.isVisible():
            self._hide_address_bar()
        elif self.isFullScreen():
            self.showNormal()
        else:
            view = self._current_view()
            if view:
                view.stop()

    # ── Window lifecycle ──────────────────────────────────────────────────

    def closeEvent(self, event) -> None:  # noqa: ANN001
        """
        Explicitly remove all WebViews before Qt starts destroying the profile,
        avoiding the 'WebEnginePage still not deleted' warning.
        """
        while self._tabs.count():
            w = self._tabs.widget(0)
            self._tabs.removeTab(0)
            if w:
                w.deleteLater()
        super().closeEvent(event)


# ──────────────────────────── Entry point ────────────────────────────────────


def main() -> None:
    # Zero-Bloat Chromium flags for minimal RAM and CPU overhead.
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
        "--disable-extensions --disable-sync --disable-translate "
        "--disable-background-networking --disable-default-apps "
        "--disable-gpu-shader-disk-cache --disable-reading-from-canvas "
        "--disable-notifications --single-process"
    )

    app = QApplication(sys.argv)
    app.setApplicationName("BeepBeep")
    app.setOrganizationName("BeepBeep")
    app.setApplicationDisplayName("BeepBeep Browser")

    # Dark system palette for all Qt widgets.
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(28, 28, 28))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(220, 220, 220))
    palette.setColor(QPalette.ColorRole.Base, QColor(18, 18, 18))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(38, 38, 38))
    palette.setColor(QPalette.ColorRole.Text, QColor(220, 220, 220))
    palette.setColor(QPalette.ColorRole.Button, QColor(45, 45, 45))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(220, 220, 220))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.Link, QColor(100, 180, 255))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(45, 45, 45))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(220, 220, 220))
    app.setPalette(palette)

    # Load (or create) persistent config before building the window.
    config = ConfigManager(_app_dir())

    window = BrowserWindow(config)

    if not config.onboarding_done:
        # First launch: show the window, then immediately run the wizard.
        window.show()
        wizard = OnboardingWizard(window._bm, window._pm, config, window)
        wizard.exec()
    else:
        # Subsequent launches: show lock screen if a master password exists.
        salt_file = _app_dir() / "salt.bin"
        if salt_file.exists():
            window.show_lock_screen()
        window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
