# netfree_patcher_advanced_he.py

import sys
import subprocess
import os
import re
import shutil
from pathlib import Path

from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QFileDialog, QLabel, QCheckBox,
                             QPlainTextEdit, QMessageBox, QFrame, QLineEdit,
                             QGraphicsOpacityEffect, QScrollArea)
from PyQt6.QtCore import QThread, pyqtSignal, Qt, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import QIcon, QMovie, QFont

# --- Core Patching Logic (runs in a separate thread) ---
class PatcherThread(QThread):
    log_message = pyqtSignal(str)
    process_finished = pyqtSignal(bool, str)

    def __init__(self, apk_file, make_debuggable, keystore_path, key_alias, key_pass):
        super().__init__()
        self.apk_file = Path(apk_file)
        self.make_debuggable = make_debuggable
        self.script_dir = Path(__file__).parent.resolve()
        # Advanced options
        self.keystore_path = Path(keystore_path).expanduser() if keystore_path else Path.home() / ".android" / "debug.keystore"
        self.key_alias = key_alias or "androiddebugkey"
        self.key_pass = key_pass or "android"

    def run_command(self, command):
        try:
            process = subprocess.run(
                command, check=True, text=True, capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )
            if process.stdout: self.log_message.emit(process.stdout)
            if process.stderr: self.log_message.emit(f"STDERR: {process.stderr}")
        except subprocess.CalledProcessError as e:
            error_message = f"Error executing: {' '.join(map(str, command))}\n" \
                          f"Return Code: {e.returncode}\n" \
                          f"Output:\n{e.stdout}\n" \
                          f"Error Output:\n{e.stderr}"
            raise RuntimeError(error_message)

    def run(self):
        try:
            apktool_path = self.script_dir / "apktool.jar"
            keytool_path = self.script_dir / "keytool.exe"
            zipalign_path = self.script_dir / "zipalign.exe"
            apksigner_path = self.script_dir / "apksigner.jar"
            network_config_path = self.script_dir / "network_security_config.xml"

            if not self.keystore_path.exists():
                self.log_message.emit(f"קובץ חתימה לא נמצא. יוצר אחד חדש בנתיב {self.keystore_path}...")
                self.keystore_path.parent.mkdir(parents=True, exist_ok=True)
                keytool_command = [
                    str(keytool_path), "-genkey", "-v", "-keystore", str(self.keystore_path),
                    "-storepass", self.key_pass, "-alias", self.key_alias, "-keypass", self.key_pass,
                    "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000"
                ]
                self.run_command(keytool_command)
            else:
                self.log_message.emit(f"משתמש בקובץ חתימה קיים: {self.keystore_path}")

            filename_stem = self.apk_file.stem
            temp_apk_name = f"{filename_stem}_temp.apk"
            new_apk_name = f"{filename_stem}_netfree.apk"
            tmp_dir = self.script_dir / f"temp_{filename_stem}"

            self.log_message.emit(f"\n--- שלב 1: מפרק את {self.apk_file.name} ---")
            if tmp_dir.exists(): shutil.rmtree(tmp_dir)
            self.run_command(["java", "-jar", str(apktool_path), "d", "-s", "-f", "-o", str(tmp_dir), str(self.apk_file)])

            self.log_message.emit("\n--- שלב 2: מוסיף הגדרות אבטחת רשת ---")
            xml_dir = tmp_dir / "res" / "xml"; xml_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy(network_config_path, xml_dir)

            self.log_message.emit("\n--- שלב 3: משנה את קובץ AndroidManifest.xml ---")
            manifest_path = tmp_dir / "AndroidManifest.xml"
            with open(manifest_path, "r+", encoding="utf-8") as f:
                content = f.read()
                app_tag_match = re.search(r"<application.*?>", content)
                if not app_tag_match: raise RuntimeError("לא ניתן למצוא את תגית <application>.")
                app_tag = app_tag_match.group(0)
                modified_tag = app_tag
                if 'android:networkSecurityConfig' not in app_tag:
                    modified_tag = modified_tag.replace(">", ' android:networkSecurityConfig="@xml/network_security_config">')
                if self.make_debuggable and 'android:debuggable' not in app_tag:
                    modified_tag = modified_tag.replace(">", ' android:debuggable="true">')
                content = content.replace(app_tag, modified_tag)
                f.seek(0); f.write(content); f.truncate()

            self.log_message.emit(f"\n--- שלב 4: בונה מחדש אל {temp_apk_name} ---")
            self.run_command(["java", "-jar", str(apktool_path), "b", "-o", temp_apk_name, str(tmp_dir)])

            self.log_message.emit(f"\n--- שלב 5: מיישר את {new_apk_name} ---")
            self.run_command([str(zipalign_path), "-p", "4", temp_apk_name, new_apk_name])

            self.log_message.emit(f"\n--- שלב 6: חותם את {new_apk_name} ---")
            sign_cmd = [
                "java", "-jar", str(apksigner_path), "sign", "--ks", str(self.keystore_path),
                "--ks-key-alias", self.key_alias, "--ks-pass", f"pass:{self.key_pass}", new_apk_name
            ]
            self.run_command(sign_cmd)

            self.log_message.emit("\n--- שלב 7: מנקה קבצים זמניים ---")
            os.remove(temp_apk_name)
            shutil.rmtree(tmp_dir)

            final_path = self.script_dir / new_apk_name
            self.process_finished.emit(True, f"הצלחה! קובץ APK מתוקן נוצר בנתיב:\n{final_path}")
        except Exception as e:
            self.log_message.emit(f"\n--- אירעה שגיאה ---\n{e}")
            self.process_finished.emit(False, "התיקון נכשל. בדוק את היומן לפרטים נוספים.")


# --- Main GUI Window ---
class App(QWidget):
    def __init__(self):
        super().__init__()
        self.script_dir = Path(__file__).parent.resolve()
        self.selected_apk_path = ""
        self.setWindowTitle("Netfree APK Patcher")
        self.setGeometry(100, 100, 650, 700)
        self.init_ui()
        self.apply_stylesheet()
        self.check_java()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(25, 25, 25, 25)
        main_layout.setSpacing(20)

        title = QLabel("עורך APK עבור נטפרי")
        title.setObjectName("title")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # --- Card for file selection ---
        file_card = self.create_card("1. בחירת קובץ APK")

        # --- File Selection Content ---
        self.select_button = QPushButton("בחר קובץ APK  📂")
        self.select_button.setIcon(QIcon(str(self.script_dir / "folder-open.png")))
        self.select_button.clicked.connect(self.open_file_dialog)
        self.selected_file_path_label = QLabel("לא נבחר קובץ.")
        self.selected_file_path_label.setObjectName("filePath")
        file_card.layout().addWidget(self.select_button)
        file_card.layout().addWidget(self.selected_file_path_label)

        # --- Advanced Options (Collapsible) ---
        self.advanced_toggle_button = QPushButton("אפשרויות מתקדמות ▼")
        self.advanced_toggle_button.setObjectName("toggleButton")
        self.advanced_frame = self.create_advanced_options()
        self.advanced_frame.hide()
        self.advanced_toggle_button.clicked.connect(self.toggle_advanced_options)

        # --- Action Buttons ---
        action_layout = QHBoxLayout()
        self.patch_button = QPushButton("ערוך את ה-APK")
        self.patch_button.setIcon(QIcon(str(self.script_dir / "patch-apk.png")))
        self.patch_button.setObjectName("actionButton")
        self.patch_button.setToolTip("התחל את תהליך ההתקנה.")
        self.patch_button.clicked.connect(self.start_patching)
        self.patch_button.setEnabled(False)
        self.loading_label = QLabel()
        self.loading_movie = QMovie(str(self.script_dir / "loading.gif"))
        self.loading_label.setMovie(self.loading_movie)
        self.loading_label.hide()
        self.open_folder_button = QPushButton("פתח את תיקיית ההתוצאה")
        self.open_folder_button.setIcon(QIcon(str(self.script_dir / "folder-open.png")))
        self.open_folder_button.hide()
        self.open_folder_button.clicked.connect(self.open_output_folder)
        action_layout.addWidget(self.patch_button)
        action_layout.addWidget(self.loading_label)
        action_layout.addStretch()
        action_layout.addWidget(self.open_folder_button)

        # --- Log Area ---
        log_label = QLabel("יומן התקדמות")
        log_label.setObjectName("header")
        self.log_area = QPlainTextEdit()
        self.log_area.setReadOnly(True)

        # --- Add all widgets to main layout ---
        main_layout.addWidget(title)
        main_layout.addWidget(file_card)
        main_layout.addWidget(self.advanced_toggle_button)
        main_layout.addWidget(self.advanced_frame)
        main_layout.addLayout(action_layout)
        main_layout.addWidget(log_label)
        main_layout.addWidget(self.log_area)

    def create_card(self, title_text):
        card = QFrame()
        card.setObjectName("card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(20, 15, 20, 15)
        layout.setSpacing(10)
        card_title = QLabel(title_text)
        card_title.setObjectName("header")
        layout.addWidget(card_title)
        return card

    def create_advanced_options(self):
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        layout.setSpacing(15)

        # Debug Checkbox (Moved here)
        self.debug_checkbox = QCheckBox("הפוך את היישום לניתן לניפוי באגים (debuggable)")
        self.debug_checkbox.setToolTip("מוסיף `android:debuggable=\"true\"` לקובץ המניפסט.\nנדרש עבור כלי ניפוי באגים מסוימים.")
        layout.addWidget(self.debug_checkbox)

        # Keystore Alias
        ks_alias_layout = QHBoxLayout()
        ks_alias_label = QLabel(":כינוי מפתח (Alias)")
        self.ks_alias_input = QLineEdit()
        self.ks_alias_input.setPlaceholderText("ברירת מחדל: androiddebugkey")
        self.ks_alias_input.setToolTip("הכינוי של המפתח בתוך קובץ החתימה.")
        ks_alias_layout.addWidget(ks_alias_label)
        ks_alias_layout.addWidget(self.ks_alias_input)
        layout.addLayout(ks_alias_layout)

        # Keystore Password
        ks_pass_layout = QHBoxLayout()
        ks_pass_label = QLabel(":סיסמת מפתח")
        self.ks_pass_input = QLineEdit()
        self.ks_pass_input.setPlaceholderText("ברירת מחדל: android")
        self.ks_pass_input.setToolTip("הסיסמה עבור קובץ החתימה והמפתח.\nברירת המחדל היא 'android' עבור מפתח ניפוי הבאגים.")
        ks_pass_layout.addWidget(ks_pass_label)
        ks_pass_layout.addWidget(self.ks_pass_input)
        layout.addLayout(ks_pass_layout)

        return frame

    def toggle_advanced_options(self):
        if self.advanced_frame.isVisible():
            self.advanced_toggle_button.setText("אפשרויות מתקדמות ▼")
            self.advanced_frame.hide()
        else:
            self.advanced_toggle_button.setText("אפשרויות מתקדמות ▲")
            self.advanced_frame.show()

    def apply_stylesheet(self):
        self.setStyleSheet("""
            QWidget { background-color: #1e1e1e; color: #f0f0f0; font-family: "Segoe UI", "Arial"; }
            QLabel { background-color: transparent; border: none; }
            #title { font-size: 28px; font-weight: 900; color: #ffffff; padding-bottom: 10px; }
            #header { font-size: 16px; font-weight: 600; color: #ab47bc; padding-bottom: 5px; }
            QFrame#card { background-color: #2d2d2d; border: 1px solid #4a4a4a; border-radius: 12px; }
            QPushButton { background-color: #3c3c3c; border: 1px solid #555; padding: 12px;
                font-size: 14px; font-weight: 500; border-radius: 8px; text-align: right; padding-right: 15px; }
            QPushButton:hover { background-color: #4a4a4a; border-color: #777; }
            #actionButton { background-color: #ab47bc; color: white; font-size: 16px; font-weight: bold; border: none; text-align: center; }
            #actionButton:disabled { background-color: #5f3a69; color: #9e9e9e; }
            #actionButton:hover { background-color: #9c27b0; }
            #toggleButton { text-align: center; background-color: transparent; border: none; color: #ab47bc; }
            QPlainTextEdit { background-color: #121212; color: #e0e0e0; font-family: "Consolas", "Courier New";
                border: 1px solid #4a4a4a; border-radius: 8px; padding: 10px; text-align: left; }
            #filePath { color: #9e9e9e; font-size: 13px; font-style: italic; padding-top: 5px; }
            QLineEdit { border: 1px solid #555; background-color: #3c3c3c; padding: 8px; border-radius: 4px; }
            QCheckBox { background-color: transparent; border: none; spacing: 10px; font-size: 14px; }
            QCheckBox::indicator { width: 20px; height: 20px; margin-left: 10px; }
            QCheckBox::indicator:unchecked { background-color: #3c3c3c; border: 1px solid #555; border-radius: 4px; }
            QCheckBox::indicator:checked { background-color: #ab47bc; border: 1px solid #9c27b0; border-radius: 4px; }
        """)

    def check_java(self):
        self.log_area.appendPlainText("בודק התקנת Java...")
        try:
            subprocess.run(["java", "-version"], check=True, capture_output=True, text=True,
                             creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0)
            self.log_area.appendPlainText("התקנת Java נמצאה. מוכן .")
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.log_area.appendPlainText("קריטי: Java אינו מותקן או אינו מוגדר בנתיב המערכת (PATH).")
            QMessageBox.critical(self, "Java לא נמצא", "נדרשת ערכת פיתוח של Java (JDK).")
            self.patch_button.setEnabled(False)

    def open_file_dialog(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "בחר קובץ APK", "", "Android Package (*.apk)")
        if file_name:
            self.selected_apk_path = file_name
            self.selected_file_path_label.setText(Path(file_name).name)
            self.patch_button.setEnabled(True)
            self.open_folder_button.hide()

    def open_output_folder(self):
        path = str(self.script_dir)
        if sys.platform == 'win32':
            os.startfile(path)
        elif sys.platform == 'darwin':
            subprocess.Popen(['open', path])
        else:
            subprocess.Popen(['xdg-open', path])

    def start_patching(self):
        if not self.selected_apk_path:
            QMessageBox.warning(self, "לא נבחר קובץ", "אנא בחר קובץ APK תחילה.")
            return

        self.patch_button.setEnabled(False)
        self.open_folder_button.hide()
        self.log_area.clear()
        self.loading_label.show()
        self.loading_movie.start()

        self.patcher = PatcherThread(
            apk_file=self.selected_apk_path,
            make_debuggable=self.debug_checkbox.isChecked(),
            keystore_path="",  # Use default debug.keystore
            key_alias=self.ks_alias_input.text(),
            key_pass=self.ks_pass_input.text()
        )
        self.patcher.log_message.connect(self.log_area.appendPlainText)
        self.patcher.process_finished.connect(self.on_patching_finished)
        self.patcher.start()

    def on_patching_finished(self, success, message):
        self.patch_button.setEnabled(True)
        self.loading_movie.stop()
        self.loading_label.hide()

        self.log_area.appendPlainText(f"\n{'='*20}\n{message}")
        if success:
            self.open_folder_button.show()
            QMessageBox.information(self, "הצלחה", message)
        else:
            QMessageBox.critical(self, "כישלון", message)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    # Force Right-to-Left layout for Hebrew UI
    app.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
    ex = App()
    ex.show()
    sys.exit(app.exec())