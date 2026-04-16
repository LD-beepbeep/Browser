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

import sys
import os
import json
import base64
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

# ── Optional dependency: cryptography (for password encryption) ───────────────
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

from PySide6.QtCore import Qt, QUrl, QStandardPaths
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
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

# ──────────────────────────── Constants ──────────────────────────────────────

HOME_URL = "https://start.duckduckgo.com/"

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
    """Bookmarks stored as a JSON array in the app-data directory."""

    def __init__(self, data_dir: Path) -> None:
        self._file = data_dir / "bookmarks.json"
        self._items: List[Dict[str, str]] = []
        self._load()

    def _load(self) -> None:
        if self._file.exists():
            try:
                self._items = json.loads(self._file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._items = []

    def _save(self) -> None:
        self._file.write_text(
            json.dumps(self._items, indent=2, ensure_ascii=False), encoding="utf-8"
        )

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


# ──────────────────────────── Web View ───────────────────────────────────────


class WebView(QWebEngineView):
    """
    QWebEngineView subclass that:
    - Supports autofill injection via PasswordManager
    - Routes popup / new-window requests back to the browser window as new tabs
    """

    def __init__(
        self,
        profile: QWebEngineProfile,
        pm: PasswordManager,
        on_popup: Optional[Callable[["WebView"], None]] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        from PySide6.QtWebEngineCore import QWebEnginePage

        self.setPage(QWebEnginePage(profile, self))
        self._pm = pm
        self._on_popup = on_popup
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
        view = WebView(self.page().profile(), self._pm, self._on_popup)
        if self._on_popup:
            self._on_popup(view)
        return view


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


# ────────────────────────── Browser Window ───────────────────────────────────


class BrowserWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("BeepBeep Browser")
        self.resize(1280, 800)

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
            "QProgressBar::chunk { background: #4a9eff; }"
        )
        root.addWidget(self._progress)

        # Address bar (hidden by default, shown with Ctrl+L).
        self._address_bar = QLineEdit()
        self._address_bar.setPlaceholderText("Enter URL or search…")
        self._address_bar.setFixedHeight(30)
        self._address_bar.hide()
        self._address_bar.returnPressed.connect(self._navigate_from_bar)
        root.addWidget(self._address_bar)

        # Tab widget.
        self._tabs = QTabWidget()
        self._tabs.setTabsClosable(True)
        self._tabs.setMovable(True)
        self._tabs.setDocumentMode(True)
        self._tabs.tabCloseRequested.connect(self._close_tab)
        self._tabs.currentChanged.connect(self._on_tab_changed)
        root.addWidget(self._tabs)

        # "+" button in the top-right corner of the tab bar.
        new_tab_btn = QPushButton("+")
        new_tab_btn.setFixedSize(26, 24)
        new_tab_btn.setFlat(True)
        new_tab_btn.setToolTip("New tab  (Ctrl+T)")
        new_tab_btn.clicked.connect(lambda: self.open_tab())
        self._tabs.setCornerWidget(new_tab_btn, Qt.Corner.TopRightCorner)

        # ── Keyboard shortcuts ───────────────────────────────────────────
        self._bind_shortcuts()

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

    # ── Tab management ────────────────────────────────────────────────────

    def open_tab(self, url: str = HOME_URL) -> WebView:
        """Create a new tab and navigate to *url*."""
        view = self._make_view()
        idx = self._tabs.addTab(view, "New Tab")
        self._tabs.setCurrentIndex(idx)
        view.setUrl(QUrl(url))
        return view

    def _make_view(self) -> WebView:
        """Create a WebView and wire up all signals."""
        view = WebView(self._profile, self._pm, on_popup=self._adopt_popup_view)
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
        # Treat as URL if it looks like one, otherwise search with DuckDuckGo.
        if "." in text and " " not in text:
            url = (
                text
                if text.startswith(("http://", "https://", "file://"))
                else "https://" + text
            )
        else:
            url = "https://duckduckgo.com/?q=" + text.replace(" ", "+")
        view = self._current_view()
        if view:
            view.setUrl(QUrl(url))
        self._address_bar.hide()

    def _toggle_address_bar(self) -> None:
        if self._address_bar.isVisible():
            self._address_bar.hide()
        else:
            view = self._current_view()
            if view:
                self._address_bar.setText(view.url().toString())
            self._address_bar.show()
            self._address_bar.setFocus()
            self._address_bar.selectAll()

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
        if view and self._address_bar.isVisible():
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
            self._address_bar.hide()
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
    # Hint to Chromium to reduce background resource usage.
    os.environ.setdefault(
        "QTWEBENGINE_CHROMIUM_FLAGS",
        "--disable-extensions --disable-sync --disable-translate "
        "--disable-background-networking --disable-default-apps",
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

    window = BrowserWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
