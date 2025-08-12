# cybersec_lab_v2.py
# Python 3.12+
# pip install PySide6 cryptography

from __future__ import annotations

import base64
import binascii
import os
import secrets
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# ---- Crypto backend ----------------------------------------------------------
CRYPTO_OK = True
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding, x25519, ed25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except Exception as e:
    CRYPTO_OK = False
    CRYPTO_ERR = str(e)

# ---- Qt ----------------------------------------------------------------------
from PySide6.QtCore import Qt, QTimer, QThread, Signal, QSize
from PySide6.QtGui import QAction, QIcon, QPalette, QColor, QTextOption, QFont
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QListWidget, QStackedWidget, QLineEdit, QTextEdit, QGroupBox,
    QFormLayout, QComboBox, QSpinBox, QCheckBox, QFileDialog, QProgressBar,
    QSplitter, QDockWidget, QMessageBox, QStyleFactory, QFrame
)

APP_NAME = "CyberSec Lab — Session 1"
APP_VERSION = "1.1.0"

# ---- Small helpers -----------------------------------------------------------

def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("utf-8"))

def pretty_bytes(b: bytes, max_len=180) -> str:
    s = b64e(b)
    return s if len(s) <= max_len else s[:max_len] + "…"

def pretty_time_ms(t0: float) -> str:
    return f"{(time.perf_counter() - t0)*1000:.1f} ms"

def warn_box(parent, title, text):
    QMessageBox.warning(parent, title, text)

def info_box(parent, title, text):
    QMessageBox.information(parent, title, text)

def rule() -> QFrame:
    line = QFrame()
    line.setFrameShape(QFrame.HLine)
    line.setFrameShadow(QFrame.Sunken)
    line.setStyleSheet("color: rgba(255,255,255,0.10);")
    return line

# ---- Dark / “glass” theme ----------------------------------------------------

def apply_dark_palette(app: QApplication):
    app.setStyle(QStyleFactory.create("Fusion"))
    dark = QPalette()
    bg = QColor(28, 30, 36, 230)     # translucent “glass”
    alt = QColor(36, 38, 44, 230)
    base = QColor(22, 24, 28, 230)
    text = QColor(232, 234, 241)
    disabled = QColor(140, 140, 145)

    dark.setColor(QPalette.Window, bg)
    dark.setColor(QPalette.WindowText, text)
    dark.setColor(QPalette.Base, base)
    dark.setColor(QPalette.AlternateBase, alt)
    dark.setColor(QPalette.Text, text)
    dark.setColor(QPalette.Button, alt)
    dark.setColor(QPalette.ButtonText, text)
    dark.setColor(QPalette.ToolTipBase, QColor(40, 40, 40))
    dark.setColor(QPalette.ToolTipText, text)
    dark.setColor(QPalette.Link, QColor(85, 170, 255))
    dark.setColor(QPalette.Highlight, QColor(66, 133, 244))
    dark.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
    dark.setColor(QPalette.Disabled, QPalette.WindowText, disabled)
    dark.setColor(QPalette.Disabled, QPalette.Text, disabled)
    dark.setColor(QPalette.Disabled, QPalette.ButtonText, disabled)
    app.setPalette(dark)

    app.setStyleSheet("""
        QWidget { font-size: 13px; color: #E8EAF1; }
        QGroupBox { border: 1px solid rgba(255,255,255,0.08);
                    border-radius: 10px; margin-top: 14px; padding: 10px 10px 12px 10px; }
        QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; font-weight: 600; color: #C9D1D9; }
        QTextEdit, QLineEdit { background: rgba(0,0,0,0.22);
                               border: 1px solid rgba(255,255,255,0.08);
                               border-radius: 8px; padding: 7px; selection-background-color: #3A4A7A; }
        QPushButton { background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 rgba(255,255,255,0.08), stop:1 rgba(255,255,255,0.03));
                      border: 1px solid rgba(255,255,255,0.13);
                      border-radius: 8px; padding: 7px 12px; font-weight: 600; }
        QPushButton:hover { background: rgba(255,255,255,0.14); }
        QPushButton:pressed { background: rgba(255,255,255,0.20); }
        QComboBox, QSpinBox, QCheckBox { background: rgba(0,0,0,0.22);
                              border: 1px solid rgba(255,255,255,0.08);
                              border-radius: 8px; padding: 4px 6px; }
        QListWidget { background: rgba(0,0,0,0.18);
                      border-right: 1px solid rgba(255,255,255,0.10);
                      padding: 6px; }
        QStatusBar { background: rgba(0,0,0,0.25); }
        QToolTip { color: #E6E6EB; background-color: rgba(0,0,0,0.88);
                   border: 1px solid rgba(255,255,255,0.12); }
        QLabel.h1 { font-size: 18px; font-weight: 700; color: #EDEFF6; }
        QLabel.sub { color: #AEB6C2; }
    """)

# ---- Tutor content (now with Button Guides) ----------------------------------

def md_to_html(md: str) -> str:
    # Very light MD → HTML: just line breaks and **bold**
    md = md.replace("**", "<b>").replace("<b><b>", "**").replace("</b></b>", "**")
    return "<div style='line-height:1.38'>" + md.replace("\n", "<br>") + "</div>"

TUTOR = {
"Hashing & Salting": md_to_html("""
<b>What you’ll learn</b><br>
Turn a password into a fixed-length, irreversible hash and add a unique salt so equal passwords don’t collide.
<br><br>
<b>Try this flow</b><br>
1) Enter a password. Choose an algorithm (SHA-256, SHA3-256, BLAKE2b = fast; PBKDF2 / scrypt = slow on purpose).<br>
2) Toggle <b>Add salt</b> and click <b>Hash</b>. Re-hash twice and compare: same input → different output (thanks to salt).<br>
3) Click <b>Generate salted record</b> then test with <b>Verify</b> to see server-side login logic.
<br><br>
<b>Button Guide</b><br>
• <b>Hash</b>: Runs the chosen function. PBKDF2/scrypt use slow, tunable work factors.<br>
• <b>Generate salted record</b>: Builds <i>alg$salt$hash</i> to simulate a password DB row.<br>
• <b>Verify</b>: Recomputes the hash with record’s alg+salt. Success ⇒ password matches.
"""),

"AES (Symmetric)": md_to_html("""
<b>What you’ll learn</b><br>
Encrypt and authenticate data with one shared key using AES-GCM (confidentiality + integrity).
<br><br>
<b>Try this flow</b><br>
1) <b>Generate key</b> (256-bit).<br>
2) Type a message → <b>Encrypt (AES-GCM)</b> to see Nonce, Ciphertext, and Tag.<br>
3) Click <b>Flip a byte</b> to simulate tampering, then <b>Decrypt</b> (should fail).
<br><br>
<b>Button Guide</b><br>
• <b>Generate key</b>: Random 256-bit key in memory.<br>
• <b>Encrypt</b>: New 96-bit nonce; tag appended to ciphertext (we split for display).<br>
• <b>Decrypt</b>: Verifies tag; if wrong/edited → authentication error.<br>
• <b>Flip a byte</b>: Corrupts ciphertext to show integrity protection.
"""),

"RSA (Public-key)": md_to_html("""
<b>What you’ll learn</b><br>
Classic public-key crypto: anyone encrypts to your <b>public</b> key, only you decrypt with your <b>private</b> key (OAEP).
<br><br>
<b>Try this flow (Encryption)</b><br>
1) <b>Generate RSA</b> (2048 or 3072).<br>
2) Enter plaintext → <b>Encrypt with Public</b> → share ciphertext.<br>
3) Only the holder of the private key can <b>Decrypt with Private</b>.
<br><br>
<b>Button Guide</b><br>
• <b>Generate RSA</b>: Creates keypair and shows PEMs.<br>
• <b>Encrypt with Public</b>: OAEP (SHA-256) — modern and secure.<br>
• <b>Decrypt with Private</b>: Recovers the plaintext if key matches.<br>
• <b>Try Public Decrypt (explain)</b>: Why it <i>doesn’t</i> decrypt OAEP and how this direction is really about signatures.<br>
• <b>Private→Public demo</b>: Produces a <i>signature-like</i> blob with the private key and checks it with the public key (no plaintext recovery).
"""),

"Key Exchange": md_to_html("""
<b>What you’ll learn</b><br>
Create a shared secret over an insecure channel using X25519 (modern Diffie-Hellman).
<br><br>
<b>Try this flow</b><br>
1) <b>Generate A</b> then <b>Generate B</b> keys.<br>
2) <b>Derive</b>: both sides compute the exact same secret <i>without sending it</i>.
<br><br>
<b>Button Guide</b><br>
• <b>Generate A/B</b>: New ephemeral private/public keys (base64 shows public).<br>
• <b>Derive</b>: Each side does a curve multiply to reach the same secret.
"""),

"Digital Signatures": md_to_html("""
<b>What you’ll learn</b><br>
Prove who signed and that content wasn’t changed using Ed25519.
<br><br>
<b>Try this flow</b><br>
1) <b>Generate signer key</b>.<br>
2) Write a message → <b>Sign</b> → copy signature.<br>
3) Alter the message → <b>Verify</b> (should fail).
<br><br>
<b>Button Guide</b><br>
• <b>Generate signer key</b>: Ed25519 keypair.<br>
• <b>Sign</b>: Private key creates a 64-byte signature (base64 shown).<br>
• <b>Verify</b>: Public key checks signature against current message.
"""),

"Passkeys (Sim)": md_to_html("""
<b>What you’ll learn</b><br>
Passwordless auth: device makes a keypair per website; site stores only your public key.
<br><br>
<b>Try this flow</b><br>
1) Enter site (rpId) → <b>Register</b> to create/store a device keypair and send the public key to the “server”.<br>
2) <b>New challenge</b> → <b>Login</b>: device signs the challenge; server verifies with your public key.
<br><br>
<b>Button Guide</b><br>
• <b>Register</b>: New device keypair bound to the site.<br>
• <b>New challenge</b>: Random value “server” will verify.<br>
• <b>Login</b>: Signs challenge with device key; server verifies → success.
"""),

"Encryption in Transit": md_to_html("""
<b>What you’ll learn</b><br>
End-to-end (E2E) vs hop-by-hop encryption.
<br><br>
<b>Try this flow</b><br>
1) Enter a message; toggle <b>End-to-end ON</b>.<br>
2) <b>Send</b> with E2E ON: middle node (“Eve”) sees only ciphertext.<br>
3) Send with E2E OFF: the server/middle can read plaintext.
<br><br>
<b>Button Guide</b><br>
• <b>End-to-end ON</b>: Alice encrypts for Bob; only Bob can decrypt.<br>
• <b>Send</b>: Simulates transport and what each hop can see.
"""),

"Secure Delete (Lab)": md_to_html("""
<b>What you’ll learn</b><br>
Safer file wiping in a sandbox; why software wipes aren’t perfect on SSDs.
<br><br>
<b>Try this flow</b><br>
1) <b>Create sample file</b> (always in sandbox).<br>
2) <b>Secure delete</b> (multi-pass overwrite → rename → unlink).<br>
3) Only enable <b>Allow real paths</b> if you accept the risk.
<br><br>
<b>Button Guide</b><br>
• <b>Create sample file</b>: Writes random 256 KiB to sandbox.\n<br>
• <b>Secure delete</b>: Overwrites N passes (alt random/zeros), renames, deletes.<br>
• <b>Overwrite passes</b>: More passes = more time; doesn’t defeat SSD wear-levelling.
"""),
}

# ---- Widgets ----------------------------------------------------------------

class TutorDock(QDockWidget):
    def __init__(self, parent=None):
        super().__init__("Tutor", parent)
        self.setAllowedAreas(Qt.RightDockWidgetArea | Qt.LeftDockWidgetArea)
        w = QWidget()
        lay = QVBoxLayout(w)
        self.text = QTextEdit()
        self.text.setReadOnly(True)
        self.text.setWordWrapMode(QTextOption.WordWrap)
        self.text.setMinimumWidth(360)
        self.text.setStyleSheet("font-size: 13px;")
        lay.addWidget(self.text)
        self.setWidget(w)

    def set_topic(self, topic: str):
        self.text.setHtml(TUTOR.get(topic, "<b>Welcome!</b> Pick a topic on the left."))

# -- Hashing & Salting ---------------------------------------------------------

class HashingWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.pass_in = QLineEdit()
        self.pass_in.setEchoMode(QLineEdit.Password)
        self.pass_in.setPlaceholderText("Enter a password…")
        self.pass_in.setToolTip("This is the user’s password (never stored in plaintext).")

        self.salt_chk = QCheckBox("Add salt")
        self.salt_chk.setChecked(True)
        self.salt_chk.setToolTip("When ON, we generate a random salt so identical passwords don’t collide.")

        self.salt_len = QSpinBox(); self.salt_len.setRange(8, 64); self.salt_len.setValue(16)
        self.salt_len.setToolTip("Number of salt bytes (random). 16 is common; longer is fine.")

        self.alg = QComboBox()
        self.alg.addItems(["SHA-256", "SHA3-256", "BLAKE2b", "PBKDF2-HMAC-SHA256", "scrypt"])
        self.alg.setToolTip("Fast hashes (SHA-*, BLAKE2) vs slow, password-hardening KDFs (PBKDF2, scrypt).")

        self.pbkdf2_iter = QSpinBox(); self.pbkdf2_iter.setRange(1000, 1_000_000); self.pbkdf2_iter.setValue(200_000)
        self.pbkdf2_iter.setToolTip("PBKDF2 iterations. Higher = slower to brute force.")

        self.scrypt_n = QSpinBox(); self.scrypt_n.setRange(2**10, 2**20); self.scrypt_n.setSingleStep(2**2); self.scrypt_n.setValue(2**14)
        self.scrypt_n.setToolTip("scrypt N cost parameter (power of two).")
        self.scrypt_r = QSpinBox(); self.scrypt_r.setRange(1, 32); self.scrypt_r.setValue(8); self.scrypt_r.setToolTip("scrypt r parameter.")
        self.scrypt_p = QSpinBox(); self.scrypt_p.setRange(1, 16); self.scrypt_p.setValue(1); self.scrypt_p.setToolTip("scrypt p parameter.")

        self.out_hash = QLineEdit(); self.out_hash.setReadOnly(True)
        self.out_salt = QLineEdit(); self.out_salt.setReadOnly(True)
        self.out_time = QLabel("")

        btn_hash = QPushButton("Hash")
        btn_hash.setToolTip("Compute the hash/KDF using the chosen settings.")
        btn_hash.clicked.connect(self.do_hash)

        self.record = QLineEdit(); self.record.setReadOnly(True)
        self.record.setToolTip("Server-style: alg$salt$hash (base64).")
        self.verify_in = QLineEdit(); self.verify_in.setEchoMode(QLineEdit.Password)
        self.verify_in.setPlaceholderText("Enter password to verify…")

        btn_record = QPushButton("Generate salted record")
        btn_record.setToolTip("Builds a DB record using a fresh random salt.")
        btn_verify = QPushButton("Verify against record")
        btn_verify.setToolTip("Re-hashes with record’s salt; compares hashes securely.")
        btn_record.clicked.connect(self.make_record)
        btn_verify.clicked.connect(self.verify_record)

        top = QGroupBox("Input")
        fl = QFormLayout(top)
        fl.addRow("Password:", self.pass_in)
        row = QHBoxLayout(); row.addWidget(self.salt_chk); row.addWidget(QLabel("Salt bytes:")); row.addWidget(self.salt_len); row.addStretch()
        fl.addRow("Salting:", row)
        fl.addRow("Algorithm:", self.alg)
        pbk = QHBoxLayout(); pbk.addWidget(QLabel("PBKDF2 iterations:")); pbk.addWidget(self.pbkdf2_iter); pbk.addStretch()
        fl.addRow("", pbk)
        scr = QHBoxLayout()
        scr.addWidget(QLabel("scrypt n:")); scr.addWidget(self.scrypt_n)
        scr.addWidget(QLabel("r:")); scr.addWidget(self.scrypt_r)
        scr.addWidget(QLabel("p:")); scr.addWidget(self.scrypt_p); scr.addStretch()
        fl.addRow("", scr)
        fl.addRow("", btn_hash)

        out = QGroupBox("Output")
        fo = QFormLayout(out)
        fo.addRow("Hash (base64):", self.out_hash)
        fo.addRow("Salt (base64):", self.out_salt)
        fo.addRow("Time:", self.out_time)

        rec = QGroupBox("Server-style record")
        fr = QFormLayout(rec)
        fr.addRow(QLabel("Format: <i>alg$salt$hash</i>  (base64 fields where applicable)"))
        fr.addRow("Record:", self.record)
        vlay = QHBoxLayout(); vlay.addWidget(QLabel("Verify password:")); vlay.addWidget(self.verify_in); vlay.addWidget(btn_verify)
        fr.addRow("", vlay)
        fr.addRow("", btn_record)

        main = QVBoxLayout(self)
        main.addWidget(top)
        main.addWidget(out)
        main.addWidget(rec)
        main.addStretch()

    def _hash_core(self, password: bytes, salt: Optional[bytes]) -> tuple[str, Optional[bytes], bytes, float]:
        alg = self.alg.currentText()
        t0 = time.perf_counter()
        if alg == "SHA-256":
            h = hashes.Hash(hashes.SHA256())
            if salt: h.update(salt)
            h.update(password)
            out = h.finalize()
        elif alg == "SHA3-256":
            h = hashes.Hash(hashes.SHA3_256())
            if salt: h.update(salt)
            h.update(password)
            out = h.finalize()
        elif alg == "BLAKE2b":
            h = hashes.Hash(hashes.BLAKE2b(64))
            if salt: h.update(salt)
            h.update(password)
            out = h.finalize()
        elif alg == "PBKDF2-HMAC-SHA256":
            if salt is None:
                salt = secrets.token_bytes(self.salt_len.value())
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=self.pbkdf2_iter.value())
            out = kdf.derive(password)
        elif alg == "scrypt":
            if salt is None:
                salt = secrets.token_bytes(self.salt_len.value())
            kdf = Scrypt(salt=salt, length=32, n=self.scrypt_n.value(), r=self.scrypt_r.value(), p=self.scrypt_p.value())
            out = kdf.derive(password)
        else:
            raise ValueError("Unknown alg")
        dt = time.perf_counter() - t0
        return alg, salt, out, dt

    def do_hash(self):
        pw = self.pass_in.text().encode("utf-8")
        if not pw:
            warn_box(self, "Input needed", "Please enter a password.")
            return
        salt = secrets.token_bytes(self.salt_len.value()) if self.salt_chk.isChecked() else None
        alg, salt, digest, dt = self._hash_core(pw, salt)
        self.out_hash.setText(b64e(digest))
        self.out_salt.setText(b64e(salt) if salt else "")
        self.out_time.setText(pretty_time_ms(time.perf_counter() - (time.perf_counter() - dt)))

    def make_record(self):
        pw = self.pass_in.text().encode("utf-8")
        if not pw:
            warn_box(self, "Input needed", "Enter a password to build a record.")
            return
        salt = secrets.token_bytes(self.salt_len.value())
        alg, salt, digest, _ = self._hash_core(pw, salt)
        self.record.setText(f"{alg}${b64e(salt)}$" + b64e(digest))
        self.verify_in.clear()
        info_box(self, "Record created", "Stored format: alg$salt$hash.\nOn login we hash again and compare.")

    def verify_record(self):
        rec = self.record.text().strip()
        if not rec:
            warn_box(self, "No record", "Generate a salted record first.")
            return
        try:
            alg, s_b64, d_b64 = rec.split("$", 2)
            salt = b64d(s_b64)
            digest = b64d(d_b64)
        except Exception:
            warn_box(self, "Bad format", "Expected: alg$salt$hash")
            return
        pw = self.verify_in.text().encode("utf-8")
        if not pw:
            warn_box(self, "Input needed", "Enter a password to verify.")
            return
        # temporarily switch alg to record’s
        old = self.alg.currentText()
        idx = self.alg.findText(alg)
        if idx == -1:
            warn_box(self, "Unsupported", f"Algorithm {alg} not available.")
            return
        self.alg.setCurrentIndex(idx)
        _, _, digest2, _ = self._hash_core(pw, salt)
        self.alg.setCurrentText(old)
        if secrets.compare_digest(digest, digest2):
            info_box(self, "Match", "✅ Password matches this record.")
        else:
            warn_box(self, "Nope", "❌ Password does not match.")

# -- AES -----------------------------------------------------------------------

class AESWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.key = None

        self.msg_in = QTextEdit(); self.msg_in.setPlaceholderText("Type a secret message…")
        self.msg_in.setToolTip("Plaintext that will be encrypted with AES-GCM.")
        self.ct_out = QTextEdit(); self.ct_out.setReadOnly(True)
        self.nonce_out = QLineEdit(); self.nonce_out.setReadOnly(True)
        self.tag_out = QLineEdit(); self.tag_out.setReadOnly(True)

        gen = QPushButton("Generate key")
        gen.setToolTip("Create a fresh random 256-bit AES key.")
        enc = QPushButton("Encrypt (AES-GCM)")
        enc.setToolTip("Encrypt + authenticate. Produces nonce + ciphertext + tag.")
        dec = QPushButton("Decrypt")
        dec.setToolTip("Decrypt and verify the tag; fails if tampered.")
        flip = QPushButton("Flip a byte (tamper)")
        flip.setToolTip("Corrupt ciphertext to demonstrate integrity checks.")

        gen.clicked.connect(self.gen_key)
        enc.clicked.connect(self.encrypt_msg)
        dec.clicked.connect(self.decrypt_msg)
        flip.clicked.connect(self.flip_byte)

        f = QFormLayout()
        f.addRow("Plaintext:", self.msg_in)
        f.addRow("Nonce (b64):", self.nonce_out)
        f.addRow("Ciphertext (b64):", self.ct_out)
        f.addRow("Tag (b64):", self.tag_out)

        btns = QHBoxLayout()
        btns.addWidget(gen); btns.addWidget(enc); btns.addWidget(dec); btns.addWidget(flip); btns.addStretch()

        wrap = QVBoxLayout(self)
        wrap.addLayout(f)
        wrap.addLayout(btns)
        wrap.addStretch()

    def gen_key(self):
        self.key = AESGCM.generate_key(bit_length=256)
        info_box(self, "Key ready", "Generated a 256-bit AES key in memory.")

    def encrypt_msg(self):
        if self.key is None:
            warn_box(self, "No key", "Click “Generate key” first.")
            return
        pt = self.msg_in.toPlainText().encode("utf-8")
        if not pt:
            warn_box(self, "Empty", "Type something to encrypt.")
            return
        aes = AESGCM(self.key)
        nonce = secrets.token_bytes(12)
        t0 = time.perf_counter()
        ct = aes.encrypt(nonce, pt, b"")
        dt = pretty_time_ms(t0)
        tag = ct[-16:]; body = ct[:-16]
        self.nonce_out.setText(b64e(nonce))
        self.ct_out.setPlainText(b64e(body))
        self.tag_out.setText(b64e(tag))
        self.msg_in.setPlainText(f"(Encrypted in {dt})\n" + self.msg_in.toPlainText())

    def decrypt_msg(self):
        if self.key is None:
            warn_box(self, "No key", "Generate the key first.")
            return
        try:
            nonce = b64d(self.nonce_out.text())
            body = b64d(self.ct_out.toPlainText().strip())
            tag = b64d(self.tag_out.text().strip())
            ct = body + tag
        except Exception:
            warn_box(self, "Bad input", "Check nonce/ciphertext/tag fields.")
            return
        aes = AESGCM(self.key)
        try:
            pt = aes.decrypt(nonce, ct, b"")
            self.msg_in.setPlainText(pt.decode("utf-8", errors="replace"))
            info_box(self, "Decrypted", "✅ Authenticated — plaintext recovered.")
        except Exception:
            warn_box(self, "Auth failed", "❌ Tampered or wrong key/nonce/tag.")

    def flip_byte(self):
        s = self.ct_out.toPlainText().strip()
        if not s:
            warn_box(self, "Nothing to flip", "Encrypt first.")
            return
        try:
            b = bytearray(b64d(s))
        except Exception:
            warn_box(self, "Bad input", "Ciphertext must be URL-safe base64.")
            return
        if len(b) == 0:
            return
        i = secrets.randbelow(len(b))
        b[i] ^= 0x01
        self.ct_out.setPlainText(b64e(bytes(b)))
        info_box(self, "Tampered", f"Flipped one random bit at byte offset {i}.")

# -- RSA -----------------------------------------------------------------------

class RSAWidget(QWidget):
    def __init__(self, on_explain_public_decrypt=None, parent=None):
        super().__init__(parent)
        self.private_key = None
        self.public_key = None
        self.on_explain_public_decrypt = on_explain_public_decrypt

        # Keys panel
        self.pub = QTextEdit(); self.pub.setReadOnly(True)
        self.priv = QTextEdit(); self.priv.setReadOnly(True)
        gen2048 = QPushButton("Generate RSA (2048)")
        gen3072 = QPushButton("Generate RSA (3072)")
        gen2048.setToolTip("Generate a 2048-bit RSA keypair.")
        gen3072.setToolTip("Generate a 3072-bit RSA keypair.")
        gen2048.clicked.connect(lambda: self.gen_rsa(2048))
        gen3072.clicked.connect(lambda: self.gen_rsa(3072))

        keys = QGroupBox("Keys")
        kf = QFormLayout(keys)
        kf.addRow("Public key (PEM):", self.pub)
        kf.addRow("Private key (PEM):", self.priv)
        keybtns = QHBoxLayout(); keybtns.addWidget(gen2048); keybtns.addWidget(gen3072); keybtns.addStretch()
        kf.addRow("", keybtns)

        # Encryption (OAEP)
        self.msg = QTextEdit(); self.msg.setPlaceholderText("Message to encrypt…")
        self.ct = QTextEdit(); self.ct.setPlaceholderText("Ciphertext (base64)…")
        enc_pub = QPushButton("Encrypt with Public")
        dec_priv = QPushButton("Decrypt with Private")
        enc_pub.setToolTip("Real encryption: OAEP (SHA-256).")
        dec_priv.setToolTip("Only private key holder can decrypt.")
        enc_pub.clicked.connect(self.encrypt_oaep)
        dec_priv.clicked.connect(self.decrypt_oaep)

        oaep = QGroupBox("Encryption (OAEP)")
        of = QFormLayout(oaep)
        of.addRow("Plaintext:", self.msg)
        of.addRow("Ciphertext (b64):", self.ct)
        obtns = QHBoxLayout(); obtns.addWidget(enc_pub); obtns.addWidget(dec_priv); obtns.addStretch()
        of.addRow("", obtns)

        # “Public decrypt” teaching block
        explain = QPushButton("Try Public Decrypt (explain)")
        explain.setToolTip("Shows why public decrypt isn’t how RSA encryption works, and what to use instead.")
        explain.clicked.connect(self.explain_public_decrypt)

        # Private→Public demo (signature-like)
        self.sig_blob = QLineEdit(); self.sig_blob.setReadOnly(False)
        priv_make = QPushButton("Private→Public demo (make blob)")
        pub_check = QPushButton("Check blob with Public")
        priv_make.setToolTip("Uses a signature under the hood (not encryption).")
        pub_check.setToolTip("Verifies with public key; you don’t recover plaintext.")
        priv_make.clicked.connect(self.private_to_public_demo)
        pub_check.clicked.connect(self.check_private_public_demo)

        pp = QGroupBox("Private→Public demo (educational)")
        pf = QFormLayout(pp)
        pf.addRow("Blob (b64):", self.sig_blob)
        pbtns = QHBoxLayout(); pbtns.addWidget(priv_make); pbtns.addWidget(pub_check); pbtns.addStretch()
        pf.addRow("", pbtns)

        lay = QVBoxLayout(self)
        lay.addWidget(keys)
        lay.addWidget(oaep)
        lay.addWidget(explain)
        lay.addWidget(pp)
        lay.addStretch()

    def gen_rsa(self, bits: int):
        t0 = time.perf_counter()
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        self.public_key = self.private_key.public_key()
        dt = pretty_time_ms(t0)
        self.pub.setPlainText(self.public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode())
        self.priv.setPlainText(self.private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode())
        info_box(self, "Keys ready", f"Generated {bits}-bit RSA in {dt}")

    def encrypt_oaep(self):
        if not self.public_key:
            warn_box(self, "No key", "Generate RSA first.")
            return
        pt = self.msg.toPlainText().encode("utf-8")
        if not pt:
            warn_box(self, "Empty", "Type something to encrypt.")
            return
        ct = self.public_key.encrypt(
            pt,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)
        )
        self.ct.setPlainText(b64e(ct))

    def decrypt_oaep(self):
        if not self.private_key:
            warn_box(self, "No key", "Generate RSA first.")
            return
        s = self.ct.toPlainText().strip()
        if not s:
            warn_box(self, "Empty", "Paste ciphertext to decrypt.")
            return
        try:
            ct = b64d(s)
            pt = self.private_key.decrypt(
                ct,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(), label=None)
            )
            self.msg.setPlainText(pt.decode("utf-8", errors="replace"))
            info_box(self, "Decrypted", "✅ OAEP decryption with the private key succeeded.")
        except Exception:
            warn_box(self, "Fail", "❌ Wrong key or corrupted ciphertext.")

    def explain_public_decrypt(self):
        text = (
            "You can’t decrypt OAEP ciphertext with the public key.\n\n"
            "• <b>Encryption</b>: Public → Encrypt, Private → Decrypt.\n"
            "• <b>Signatures</b>: Private → <i>sign</i>, Public → Verify (no plaintext recovery).\n\n"
            "If you want the ‘public decrypt’ direction, what you really want is a <b>signature</b>.\n"
            "→ Use the <i>Digital Signatures</i> tab, or try the ‘Private→Public demo’ below."
        )
        QMessageBox.information(self, "Why public decrypt isn’t a thing", md_to_html(text))
        if self.on_explain_public_decrypt:
            self.on_explain_public_decrypt()

    def private_to_public_demo(self):
        if not self.private_key:
            warn_box(self, "No key", "Generate RSA first.")
            return
        # Educational: actually produce a signature over current plaintext
        message = self.msg.toPlainText().encode("utf-8")
        if not message:
            warn_box(self, "Empty", "Type a message first.")
            return
        # Use RSASSA-PSS with SHA-256 (modern)
        signer = self.private_key
        sig = signer.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        self.sig_blob.setText(b64e(sig))
        info_box(self, "Blob created", "This is a <b>signature</b> made with the private key.\n"
                 "Use ‘Check blob with Public’ to verify (you don’t get plaintext from a signature).")

    def check_private_public_demo(self):
        if not self.public_key:
            warn_box(self, "No key", "Generate RSA first.")
            return
        try:
            sig = b64d(self.sig_blob.text().strip())
        except Exception:
            warn_box(self, "Bad blob", "Blob must be base64.")
            return
        message = self.msg.toPlainText().encode("utf-8")
        if not message:
            warn_box(self, "Empty", "Provide a message to verify against.")
            return
        try:
            self.public_key.verify(
                sig,
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            info_box(self, "Verified", "✅ Public key verified the private-key-made blob.\n"
                     "This is <b>not</b> decryption; it’s signature verification.")
        except Exception:
            warn_box(self, "Invalid", "❌ Verification failed (wrong blob/message/key).")

# -- Key exchange --------------------------------------------------------------

class KEXWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.a_priv: Optional[x25519.X25519PrivateKey] = None
        self.b_priv: Optional[x25519.X25519PrivateKey] = None

        self.a_pub = QLineEdit(); self.a_pub.setReadOnly(True)
        self.b_pub = QLineEdit(); self.b_pub.setReadOnly(True)
        self.a_shared = QLineEdit(); self.a_shared.setReadOnly(True)
        self.b_shared = QLineEdit(); self.b_shared.setReadOnly(True)

        btn_a = QPushButton("Generate A")
        btn_b = QPushButton("Generate B")
        btn_d = QPushButton("Derive")

        btn_a.clicked.connect(self.gen_a)
        btn_b.clicked.connect(self.gen_b)
        btn_d.clicked.connect(self.derive)

        f = QFormLayout()
        f.addRow("A public (b64):", self.a_pub)
        f.addRow("B public (b64):", self.b_pub)
        f.addRow("A’s shared (b64):", self.a_shared)
        f.addRow("B’s shared (b64):", self.b_shared)

        btns = QHBoxLayout(); btns.addWidget(btn_a); btns.addWidget(btn_b); btns.addStretch(); btns.addWidget(btn_d)

        lay = QVBoxLayout(self)
        lay.addLayout(f)
        lay.addLayout(btns)
        lay.addStretch()

    def gen_a(self):
        self.a_priv = x25519.X25519PrivateKey.generate()
        apub = self.a_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.a_pub.setText(b64e(apub))

    def gen_b(self):
        self.b_priv = x25519.X25519PrivateKey.generate()
        bpub = self.b_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.b_pub.setText(b64e(bpub))

    def derive(self):
        if not (self.a_priv and self.b_priv):
            warn_box(self, "Keys first", "Generate A and B keys.")
            return
        a_shared = self.a_priv.exchange(self.b_priv.public_key())
        b_shared = self.b_priv.exchange(self.a_priv.public_key())
        self.a_shared.setText(b64e(a_shared))
        self.b_shared.setText(b64e(b_shared))
        if a_shared == b_shared:
            info_box(self, "Match", "✅ Both sides derived the same secret.")
        else:
            warn_box(self, "Mismatch", "❌ Something went wrong.")

# -- Signatures ----------------------------------------------------------------

class SignWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.signer: Optional[ed25519.Ed25519PrivateKey] = None
        self.public: Optional[ed25519.Ed25519PublicKey] = None

        self.msg = QTextEdit(); self.msg.setPlaceholderText("Message to sign…")
        self.sig = QLineEdit(); self.sig.setReadOnly(True)
        self.pub = QTextEdit(); self.pub.setReadOnly(True)

        gen = QPushButton("Generate signer key")
        sign = QPushButton("Sign")
        verify = QPushButton("Verify")

        gen.clicked.connect(self.gen_key)
        sign.clicked.connect(self.do_sign)
        verify.clicked.connect(self.do_verify)

        f = QFormLayout()
        f.addRow("Message:", self.msg)
        f.addRow("Signature (b64):", self.sig)
        f.addRow("Public key (base64):", self.pub)

        btns = QHBoxLayout(); btns.addWidget(gen); btns.addStretch(); btns.addWidget(sign); btns.addWidget(verify)

        lay = QVBoxLayout(self)
        lay.addLayout(f)
        lay.addLayout(btns)
        lay.addStretch()

    def gen_key(self):
        self.signer = ed25519.Ed25519PrivateKey.generate()
        self.public = self.signer.public_key()
        raw = self.public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.pub.setPlainText(binascii.b2a_base64(raw, newline=False).decode("utf-8"))

    def do_sign(self):
        if not self.signer:
            warn_box(self, "No key", "Generate a signer key first.")
            return
        m = self.msg.toPlainText().encode("utf-8")
        sig = self.signer.sign(m)
        self.sig.setText(b64e(sig))

    def do_verify(self):
        if not self.public:
            warn_box(self, "No key", "Generate a signer key first.")
            return
        try:
            sig = b64d(self.sig.text())
        except Exception:
            warn_box(self, "Bad signature", "Signature must be base64.")
            return
        m = self.msg.toPlainText().encode("utf-8")
        try:
            self.public.verify(sig, m)
            info_box(self, "Valid", "✅ Signature OK for this message.")
        except Exception:
            warn_box(self, "Invalid", "❌ Signature does not match.")

# -- Passkeys ------------------------------------------------------------------

class PasskeysWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.device_keys: dict[str, ed25519.Ed25519PrivateKey] = {}
        self.server_pub: dict[str, ed25519.Ed25519PublicKey] = {}

        self.site = QLineEdit(); self.site.setText("example.com")
        self.challenge = QLineEdit(); self.challenge.setReadOnly(True)
        self.signature = QLineEdit(); self.signature.setReadOnly(True)

        btn_reg = QPushButton("Register (create device keypair)")
        btn_login = QPushButton("Login (challenge → sign → verify)")
        gen_chal = QPushButton("New challenge")
        btn_reg.clicked.connect(self.register)
        btn_login.clicked.connect(self.login)
        gen_chal.clicked.connect(self.make_challenge)

        f = QFormLayout()
        f.addRow("Site (rpId):", self.site)
        f.addRow("Challenge (b64):", self.challenge)
        f.addRow("Signature (b64):", self.signature)

        btns = QHBoxLayout(); btns.addWidget(btn_reg); btns.addStretch(); btns.addWidget(gen_chal); btns.addWidget(btn_login)

        lay = QVBoxLayout(self)
        lay.addLayout(f)
        lay.addLayout(btns)
        lay.addStretch()

    def register(self):
        rp = self.site.text().strip()
        if not rp:
            warn_box(self, "rpId needed", "Enter a site, e.g. example.com")
            return
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()
        self.device_keys[rp] = priv
        self.server_pub[rp] = pub
        info_box(self, "Registered", f"Device created a keypair for {rp} and sent the PUBLIC key to the site.")

    def make_challenge(self):
        chal = secrets.token_bytes(32)
        self.challenge.setText(b64e(chal))

    def login(self):
        rp = self.site.text().strip()
        if rp not in self.device_keys or rp not in self.server_pub:
            warn_box(self, "Not registered", "Click Register first.")
            return
        if not self.challenge.text().strip():
            self.make_challenge()
        chal = b64d(self.challenge.text())
        sig = self.device_keys[rp].sign(chal)
        self.signature.setText(b64e(sig))
        try:
            self.server_pub[rp].verify(sig, chal)
            info_box(self, "Login OK", "✅ Challenge verified — welcome back!")
        except Exception:
            warn_box(self, "Login failed", "❌ Signature did not verify.")

# -- Transit -------------------------------------------------------------------

class TransitWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.e2e = QCheckBox("End-to-end ON")
        self.msg = QLineEdit(); self.msg.setPlaceholderText("hello bob, it’s me alice")
        self.alice = QTextEdit(); self.alice.setReadOnly(True)
        self.eve = QTextEdit(); self.eve.setReadOnly(True)
        self.bob = QTextEdit(); self.bob.setReadOnly(True)
        go = QPushButton("Send")
        go.clicked.connect(self.simulate)

        grid = QHBoxLayout()
        grid.addWidget(self._panel("Alice →", self.alice))
        grid.addWidget(self._panel("Eve (middle hop)", self.eve))
        grid.addWidget(self._panel("→ Bob", self.bob))

        top = QHBoxLayout()
        top.addWidget(QLabel("Message:")); top.addWidget(self.msg)
        top.addStretch(); top.addWidget(self.e2e); top.addWidget(go)

        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addLayout(grid)
        lay.addStretch()

    def _panel(self, title, widget):
        g = QGroupBox(title)
        v = QVBoxLayout(g); v.addWidget(widget)
        return g

    def simulate(self):
        text = self.msg.text()
        if not text:
            warn_box(self, "Empty", "Type a message first.")
            return
        if self.e2e.isChecked():
            key = secrets.token_bytes(32)
            nonce = secrets.token_bytes(12)
            ct = AESGCM(key).encrypt(nonce, text.encode(), b"")
            self.alice.setPlainText(
                f"Generate session key\nEncrypt for Bob\n\nnonce={b64e(nonce)}\nct={pretty_bytes(ct)}"
            )
            self.eve.setPlainText("Sees only ciphertext flowing by.\n(Can’t read content)")
            pt = AESGCM(key).decrypt(nonce, ct, b"").decode()
            self.bob.setPlainText(f"Got nonce+ct\nDecrypt with session key\n\nPlaintext: {pt}")
        else:
            self.alice.setPlainText("TLS to server (hop 1)\nServer can read your message.")
            self.eve.setPlainText(f"Server sees plaintext:\n\n{text}\n\nThen re-encrypts to Bob (hop 2).")
            self.bob.setPlainText("TLS from server (hop 2)\nPlaintext delivered.")

# -- Secure delete -------------------------------------------------------------

class WipeWorker(QThread):
    progress = Signal(int)
    finished = Signal(bool, str)

    def __init__(self, path: Path, passes: int = 3, parent=None):
        super().__init__(parent)
        self.path = path
        self.passes = passes
        self._stop = False

    def run(self):
        try:
            size = self.path.stat().st_size
            with open(self.path, "r+b", buffering=0) as f:
                for p in range(self.passes):
                    f.seek(0)
                    chunk = os.urandom(64*1024) if p % 2 == 0 else b"\x00" * (64*1024)
                    written = 0
                    while written < size and not self._stop:
                        to_write = min(len(chunk), size - written)
                        f.write(chunk[:to_write])
                        written += to_write
                        self.progress.emit(int(100 * ((p + written/size) / self.passes)))
            new_name = self.path.with_name(self.path.name + ".wiped")
            try:
                self.path.rename(new_name)
                new_name.unlink(missing_ok=True)
            except Exception:
                self.path.unlink(missing_ok=True)
            self.finished.emit(True, "Secure delete complete (best effort).")
        except Exception as e:
            self.finished.emit(False, f"Error: {e}")

    def stop(self):
        self._stop = True

class WipeWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.sandbox = Path(tempfile.gettempdir()) / "cybersec_sandbox"
        self.sandbox.mkdir(exist_ok=True)
        self.allow_real = QCheckBox("Allow real paths (⚠️ dangerous)")
        self.file_path = QLineEdit(); self.file_path.setPlaceholderText("Path to file…")
        self.choose = QPushButton("…")
        self.create = QPushButton("Create sample file (sandbox)")
        self.wipe = QPushButton("Secure delete")
        self.progress = QProgressBar()
        self.passes = QSpinBox(); self.passes.setRange(1, 7); self.passes.setValue(3)
        self.worker: Optional[WipeWorker] = None

        self.choose.clicked.connect(self.pick_file)
        self.create.clicked.connect(self.make_sample)
        self.wipe.clicked.connect(self.do_wipe)

        f = QFormLayout()
        f.addRow("Sandbox folder:", QLabel(str(self.sandbox)))
        row = QHBoxLayout(); row.addWidget(self.file_path); row.addWidget(self.choose)
        f.addRow("Target file:", row)
        f.addRow("Overwrite passes:", self.passes)
        f.addRow("", self.allow_real)
        f.addRow("", self.create)
        f.addRow("", self.wipe)
        f.addRow("Progress:", self.progress)

        info = QLabel("Safety notes:\n• Defaults to a sandbox directory.\n"
                      "• Only tick “Allow real paths” if you know exactly what you’re doing.\n"
                      "• SSDs & snapshots can retain copies; prefer full-disk encryption + device reset.")
        info.setWordWrap(True)

        lay = QVBoxLayout(self)
        lay.addLayout(f)
        lay.addWidget(info)
        lay.addStretch()

    def pick_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Pick file to wipe", str(self.sandbox))
        if path:
            self.file_path.setText(path)

    def make_sample(self):
        data = os.urandom(1024 * 256)
        name = f"sample_{secrets.token_hex(3)}.bin"
        path = self.sandbox / name
        path.write_bytes(data)
        self.file_path.setText(str(path))
        info_box(self, "Sample ready", f"Created {name} in sandbox.")

    def do_wipe(self):
        p = Path(self.file_path.text().strip())
        if not p.exists():
            warn_box(self, "Not found", "Pick or create a file first.")
            return
        if not self.allow_real.isChecked() and not str(p).startswith(str(self.sandbox)):
            warn_box(self, "Blocked for safety",
                     "Real paths are blocked. Enable 'Allow real paths' only if you accept the risk.")
            return
        self.wipe.setEnabled(False)
        self.worker = WipeWorker(p, self.passes.value())
        self.worker.progress.connect(self.progress.setValue)
        self.worker.finished.connect(self.wipe_done)
        self.worker.start()

    def wipe_done(self, ok: bool, msg: str):
        self.wipe.setEnabled(True)
        self.progress.setValue(0)
        if ok:
            info_box(self, "Done", msg)
            self.file_path.clear()
        else:
            warn_box(self, "Error", msg)

# ---- Main Window -------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME}  ·  v{APP_VERSION}")
        self.setMinimumSize(1180, 740)
        self.setWindowIcon(QIcon.fromTheme("security-high"))

        header = QWidget()
        h = QHBoxLayout(header); h.setContentsMargins(12, 8, 12, 8)
        title = QLabel(APP_NAME); title.setObjectName("title"); title.setProperty("class", "h1")
        subtitle = QLabel("Interactive, learner-friendly crypto playground"); subtitle.setProperty("class", "sub")
        v = QVBoxLayout(); v.addWidget(title); v.addWidget(subtitle)
        h.addLayout(v)
        h.addStretch()

        self.nav = QListWidget(); self.nav.setFixedWidth(240)
        self.nav.addItems([
            "Hashing & Salting",
            "AES (Symmetric)",
            "RSA (Public-key)",
            "Key Exchange",
            "Digital Signatures",
            "Passkeys (Sim)",
            "Encryption in Transit",
            "Secure Delete (Lab)",
        ])
        self.nav.currentRowChanged.connect(self.on_nav)

        self.stack = QStackedWidget()

        # Build tabs
        if not CRYPTO_OK:
            placeholder = QLabel(
                "Crypto features unavailable.\n\n"
                "Install the 'cryptography' package:\n\n"
                "    pip install cryptography\n\n"
                f"Error was:\n{CRYPTO_ERR}"
            ); placeholder.setAlignment(Qt.AlignCenter)
            tabs = [
                HashingWidget(), placeholder, placeholder, placeholder,
                placeholder, placeholder, TransitWidget(), WipeWidget()
            ]
        else:
            tabs = [
                HashingWidget(),
                AESWidget(),
                RSAWidget(on_explain_public_decrypt=lambda: None),
                KEXWidget(),
                SignWidget(),
                PasskeysWidget(),
                TransitWidget(),
                WipeWidget(),
            ]

        for i, t in enumerate(tabs):
            page_name = self.nav.item(i).text()
            w = QWidget(); vbox = QVBoxLayout(w)
            hdr = QLabel(f"<b>{page_name}</b> — interactive demo")
            hdr.setStyleSheet("margin: 4px 2px 6px 2px; font-size: 14px; color: #C9D1D9;")
            vbox.addWidget(hdr)
            vbox.addWidget(rule())
            vbox.addWidget(t)
            self.stack.addWidget(w)

        split = QSplitter(); split.addWidget(self.nav); split.addWidget(self.stack)
        split.setStretchFactor(1, 4)

        central = QWidget(); cl = QVBoxLayout(central)
        cl.addWidget(header)
        cl.addWidget(split)
        self.setCentralWidget(central)

        # Tutor dock
        self.tutor = TutorDock(self)
        self.addDockWidget(Qt.RightDockWidgetArea, self.tutor)
        self.tutor.set_topic(self.nav.item(0).text())

        # Menus
        self._make_menu()

        # First-tip
        QTimer.singleShot(450, self._first_tip)

        # Keep a “first visit” coach per tab
        self._visited = set()
        self.statusBar().showMessage("Ready")

    def _make_menu(self):
        menubar = self.menuBar()
        filem = menubar.addMenu("&File")
        quit_act = QAction("Exit", self); quit_act.triggered.connect(self.close)
        filem.addAction(quit_act)

        viewm = menubar.addMenu("&View")
        tutor_toggle = QAction("Toggle Tutor", self, checkable=True, checked=True)
        tutor_toggle.triggered.connect(lambda s: self.tutor.setVisible(s))
        viewm.addAction(tutor_toggle)

        helpm = menubar.addMenu("&Help")
        about = QAction("About", self)
        about.triggered.connect(self._about)
        helpm.addAction(about)

    def _about(self):
        info_box(self, "About", f"{APP_NAME}\nVersion {APP_VERSION}\n\n"
                 "Live demos for Session 1: hashing, salts, AES, RSA, key exchange, signatures, passkeys, transit encryption, and safer file wipes.\n"
                 "Built with PySide6 + cryptography.")

    def _first_tip(self):
        info = textwrap.dedent("""
        Welcome! Nghi :D 👋

        • Please pick a topic on the left — the right “Tutor” panel walks you through each button, I might have fucked up some stuff, but from my tests; everything should work, i did however make this at 4 am with no sleep just after my 3 day thesis spree soooooo hehe.
        • Tabs are safe sandboxes. The “Secure Delete” lab defaults to a temp folder for safety.
        • Pro tip: Pause on each step and narrate — it’s designed for teaching.
        """).strip()
        info_box(self, "Getting started", info)

    def on_nav(self, idx: int):
        self.stack.setCurrentIndex(idx)
        title = self.nav.item(idx).text()
        self.tutor.set_topic(title)
        self.statusBar().showMessage(title)
        if idx not in self._visited:
            self._visited.add(idx)
            # brief, per-tab coach
            QMessageBox.information(self, f"{title} — quick tour", TUTOR[title])

# ---- main --------------------------------------------------------------------

def main():
    app = QApplication(sys.argv)
    # Slightly larger base font for readability
    app_font = QFont()
    app_font.setPointSize(10)
    app.setFont(app_font)

    apply_dark_palette(app)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
