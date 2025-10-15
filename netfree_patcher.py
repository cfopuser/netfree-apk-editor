# netfree_patcher.py
import sys
import subprocess
import os
import re
import shutil
from pathlib import Path
import json
from urllib import request, error
import ssl

from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QFileDialog, QLabel, QCheckBox,
                             QPlainTextEdit, QMessageBox, QFrame, QLineEdit,
                             QDialog, QStyle)
from PyQt6.QtCore import QThread, pyqtSignal, Qt, QUrl
from PyQt6.QtGui import QIcon, QMovie, QDesktopServices

# --- Application Version ---
VERSION = "1.2"

# --- HELPER FUNCTION FOR PYINSTALLER ---
def get_base_path():
    """
    Gets the correct base path, whether running as a script or a bundled PyInstaller exe.
    """
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        return Path(sys.executable).parent
    else:
        return Path(__file__).parent.resolve()

# --- Update Check Logic (runs in a separate thread) ---
class UpdateCheckThread(QThread):
    update_available = pyqtSignal(str, str)  # version, url
    update_check_failed = pyqtSignal(str)

    def run(self):
        repo_url = "https://api.github.com/repos/cfopuser/netfree-apk-editor/releases/latest"
        try:
            # --- CHANGE 1 of 2: Create an unverified SSL context ---
            # This disables certificate validation, useful for proxies like Netfree.
            unverified_context = ssl._create_unverified_context()

            # --- CHANGE 2 of 2: Pass the context to urlopen ---
            with request.urlopen(repo_url, context=unverified_context) as response:
                if response.status != 200:
                    raise error.URLError(f"GitHub API responded with status: {response.status}")
                data = json.loads(response.read().decode())

            latest_version_str = data['tag_name'].lstrip('v')
            release_url = data['html_url']

            current_v = tuple(map(int, VERSION.split('.')))
            latest_v = tuple(map(int, latest_version_str.split('.')))

            if latest_v > current_v:
                self.update_available.emit(latest_version_str, release_url)

        except Exception as e:
            self.update_check_failed.emit(f"Could not check for updates: {e}")


# --- Custom Update Dialog ---
class UpdateDialog(QDialog):
    def __init__(self, current_version, new_version, url, parent=None):
        super().__init__(parent)
        self.url = url
        self.setWindowTitle("עדכון זמין")
        self.setMinimumWidth(450)
        self.setModal(True)
        if parent and parent.windowIcon():
             self.setWindowIcon(parent.windowIcon())

        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(25, 25, 25, 25)
        top_layout = QHBoxLayout()
        icon_label = QLabel()
        icon_pixmap = self.style().standardPixmap(QStyle.StandardPixmap.SP_MessageBoxInformation)
        icon_label.setPixmap(icon_pixmap.scaled(48, 48, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
        top_layout.addWidget(icon_label)
        title_label = QLabel("עדכון חדש זמין!")
        title_label.setObjectName("updateTitle")
        top_layout.addWidget(title_label)
        top_layout.addStretch()
        main_layout.addLayout(top_layout)
        details_text = (f"<p style='text-align: right;'>גרסה <b>{new_version}</b> זמינה כעת להורדה.</p>"
                        f"<p style='text-align: right;'>אתה משתמש כרגע בגרסה {current_version}.</p>"
                        "<p style='text-align: right; color: #ccc;'>מומלץ לעדכן כדי לקבל את התכונות האחרונות ותיקוני הבאגים.</p>")
        details_label = QLabel(details_text)
        details_label.setWordWrap(True)
        details_label.setObjectName("updateDetails")
        main_layout.addWidget(details_label)
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        later_button = QPushButton("אחר כך")
        later_button.clicked.connect(self.reject)
        download_button = QPushButton("עבור לדף ההורדה")
        download_button.setObjectName("actionButton")
        download_button.clicked.connect(self.accept)
        button_layout.addWidget(later_button)
        button_layout.addWidget(download_button)
        main_layout.addLayout(button_layout)
        self.apply_stylesheet()

    def apply_stylesheet(self):
        self.setStyleSheet("""
            QDialog { background-color: #2d2d2d; border: 1px solid #4a4a4a; border-radius: 12px; font-family: "Segoe UI", "Arial"; }
            QLabel { color: #f0f0f0; background-color: transparent; }
            #updateTitle { font-size: 20px; font-weight: 600; }
            #updateDetails { font-size: 14px; color: #e0e0e0; }
            QPushButton { background-color: #3c3c3c; border: 1px solid #555; padding: 10px 20px; font-size: 14px; font-weight: 500; border-radius: 8px; }
            QPushButton:hover { background-color: #4a4a4a; border-color: #777; }
            #actionButton { background-color: #ab47bc; color: white; font-weight: bold; border: none; }
            #actionButton:hover { background-color: #9c27b0; }
        """)

# --- Core Patching Logic (runs in a separate thread) ---
class PatcherThread(QThread):
    log_message = pyqtSignal(str)
    process_finished = pyqtSignal(bool, str)

    def __init__(self, apk_file, make_debuggable, keystore_path, key_alias, key_pass, base_path):
        super().__init__()
        self.apk_file = Path(apk_file)
        self.make_debuggable = make_debuggable
        self.script_dir = Path(__file__).parent.resolve()
        self.output_dir = Path(base_path)
        self.keystore_path = Path(keystore_path).expanduser() if keystore_path else self.output_dir / "debug.keystore"
        self.key_alias = key_alias or "androiddebugkey"
        self.key_pass = key_pass or "android"

    def run_command(self, command):
        """Runs a command, captures output, and raises a detailed exception on failure."""
        try:
            startupinfo = None
            if sys.platform == 'win32':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            process = subprocess.run(
                command, check=True, text=True, capture_output=True,
                startupinfo=startupinfo
            )
            if process.stdout: self.log_message.emit(process.stdout)
            if process.stderr: self.log_message.emit(f"STDERR: {process.stderr}")
        except subprocess.CalledProcessError as e:
            error_message = (f"Error executing: {' '.join(map(str, command))}\n"
                           f"Return Code: {e.returncode}\nOutput:\n{e.stdout}\nError Output:\n{e.stderr}")
            raise RuntimeError(error_message)
        except FileNotFoundError:
            error_message = (f"Command not found: '{command[0]}'.\n"
                           f"Please ensure a full JDK is installed and its 'bin' directory is in your system's PATH environment variable.")
            raise RuntimeError(error_message)

    def run(self):
        try:
            apktool_path = self.script_dir / "apktool.jar"
            zipalign_path = self.script_dir / "zipalign.exe"
            apksigner_path = self.script_dir / "apksigner.jar"
            network_config_path = self.script_dir / "network_security_config.xml"

            if not self.keystore_path.exists():
                self.log_message.emit(f"קובץ חתימה לא נמצא. יוצר אחד חדש בנתיב {self.keystore_path}...")
                keytool_command = [
                    "keytool", "-genkey", "-v", "-keystore", str(self.keystore_path),
                    "-storepass", self.key_pass, "-alias", self.key_alias, "-keypass", self.key_pass,
                    "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
                    "-dname", "CN=Android Debug, O=Android, C=US"
                ]
                self.run_command(keytool_command)
            else:
                self.log_message.emit(f"משתמש בקובץ חתימה קיים: {self.keystore_path}")

            filename_stem = self.apk_file.stem
            temp_apk_path = self.output_dir / f"{filename_stem}_temp.apk"
            final_apk_path = self.output_dir / f"{filename_stem}_netfree.apk"
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
                app_tag_match = re.search(r"<application.*?>", content, re.DOTALL)
                if not app_tag_match: raise RuntimeError("לא ניתן למצוא את תגית <application>.")
                app_tag = app_tag_match.group(0)
                modified_tag = app_tag
                if 'android:networkSecurityConfig' not in app_tag:
                    modified_tag = modified_tag.replace(">", ' android:networkSecurityConfig="@xml/network_security_config">', 1)
                if self.make_debuggable and 'android:debuggable' not in app_tag:
                    modified_tag = modified_tag.replace(">", ' android:debuggable="true">', 1)
                content = content.replace(app_tag, modified_tag)
                f.seek(0); f.write(content); f.truncate()

            self.log_message.emit(f"\n--- שלב 4: בונה מחדש אל {temp_apk_path.name} ---")
            self.run_command(["java", "-jar", str(apktool_path), "b", "-o", str(temp_apk_path), str(tmp_dir)])

            self.log_message.emit(f"\n--- שלב 5: מיישר את {final_apk_path.name} ---")
            self.run_command([str(zipalign_path), "-p", "4", str(temp_apk_path), str(final_apk_path)])

            self.log_message.emit(f"\n--- שלב 6: חותם את {final_apk_path.name} ---")
            sign_cmd = ["java", "-jar", str(apksigner_path), "sign", "--ks", str(self.keystore_path),
                        "--ks-key-alias", self.key_alias, "--ks-pass", f"pass:{self.key_pass}", str(final_apk_path)]
            self.run_command(sign_cmd)

            self.log_message.emit("\n--- שלב 7: מנקה קבצים זמניים ---")
            os.remove(temp_apk_path)
            shutil.rmtree(tmp_dir)

            self.process_finished.emit(True, f"הצלחה! קובץ APK מתוקן נוצר בנתיב:\n{final_apk_path}")
        except Exception as e:
            self.log_message.emit(f"\n--- אירעה שגיאה ---\n{e}")
            self.process_finished.emit(False, "התיקון נכשל. בדוק את היומן לפרטים נוספים.")

# --- Main GUI Window ---
class App(QWidget):
    def __init__(self):
        super().__init__()
        self.base_path = get_base_path()
        self.script_dir = Path(__file__).parent.resolve()
        self.selected_apk_path = ""
        self.setWindowTitle("Netfree APK Patcher")
        self.setWindowIcon(QIcon(str(self.script_dir / "apk.ico")))
        self.setGeometry(100, 100, 650, 700)
        self.init_ui()
        self.apply_stylesheet()
        self.check_dependencies()
        self.check_for_updates()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(25, 25, 25, 25)
        main_layout.setSpacing(20)
        title = QLabel("עורך APK עבור נטפרי")
        title.setObjectName("title")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        file_card = self.create_card("1. בחירת קובץ APK")
        self.select_button = QPushButton("בחר קובץ APK  📂")
        self.select_button.clicked.connect(self.open_file_dialog)
        self.selected_file_path_label = QLabel("לא נבחר קובץ.")
        self.selected_file_path_label.setObjectName("filePath")
        file_card.layout().addWidget(self.select_button)
        file_card.layout().addWidget(self.selected_file_path_label)
        self.advanced_toggle_button = QPushButton("אפשרויות מתקדמות ▼")
        self.advanced_toggle_button.setObjectName("toggleButton")
        self.advanced_frame = self.create_advanced_options()
        self.advanced_frame.hide()
        self.advanced_toggle_button.clicked.connect(self.toggle_advanced_options)
        action_layout = QHBoxLayout()
        self.patch_button = QPushButton("ערוך את ה-APK")
        self.patch_button.setObjectName("actionButton")
        self.patch_button.clicked.connect(self.start_patching)
        self.patch_button.setEnabled(False)
        self.loading_label = QLabel()
        self.loading_movie = QMovie(str(self.script_dir / "loading.gif"))
        self.loading_label.setMovie(self.loading_movie)
        self.loading_label.hide()
        self.open_folder_button = QPushButton("פתח את תיקיית התוצאות")
        self.open_folder_button.hide()
        self.open_folder_button.clicked.connect(self.open_output_folder)
        action_layout.addWidget(self.patch_button)
        action_layout.addWidget(self.loading_label)
        action_layout.addStretch()
        action_layout.addWidget(self.open_folder_button)
        log_label = QLabel("יומן התקדמות")
        log_label.setObjectName("header")
        self.log_area = QPlainTextEdit()
        self.log_area.setReadOnly(True)
        bottom_layout = QHBoxLayout()
        about_label = QLabel("פותח על ידי @cfopuser")
        about_label.setObjectName("aboutLabel")
        version_label = QLabel(f"Version {VERSION}")
        version_label.setObjectName("aboutLabel")
        bottom_layout.addWidget(version_label)
        bottom_layout.addStretch()
        bottom_layout.addWidget(about_label)
        main_layout.addWidget(title)
        main_layout.addWidget(file_card)
        main_layout.addWidget(self.advanced_toggle_button)
        main_layout.addWidget(self.advanced_frame)
        main_layout.addLayout(action_layout)
        main_layout.addWidget(log_label)
        main_layout.addWidget(self.log_area)
        main_layout.addLayout(bottom_layout)

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
        self.debug_checkbox = QCheckBox("הפוך את היישום לניתן לניפוי באגים (debuggable)")
        layout.addWidget(self.debug_checkbox)
        ks_alias_layout = QHBoxLayout()
        ks_alias_label = QLabel(":כינוי מפתח (Alias)")
        self.ks_alias_input = QLineEdit()
        self.ks_alias_input.setPlaceholderText("ברירת מחדל: androiddebugkey")
        ks_alias_layout.addWidget(ks_alias_label)
        ks_alias_layout.addWidget(self.ks_alias_input)
        layout.addLayout(ks_alias_layout)
        ks_pass_layout = QHBoxLayout()
        ks_pass_label = QLabel(":סיסמת מפתח")
        self.ks_pass_input = QLineEdit()
        self.ks_pass_input.setPlaceholderText("ברירת מחדל: android")
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
            QPushButton { background-color: #3c3c3c; border: 1px solid #555; padding: 12px; font-size: 14px; font-weight: 500; border-radius: 8px; text-align: right; padding-right: 15px; }
            QPushButton:hover { background-color: #4a4a4a; border-color: #777; }
            #actionButton { background-color: #ab47bc; color: white; font-size: 16px; font-weight: bold; border: none; text-align: center; }
            #actionButton:disabled { background-color: #5f3a69; color: #9e9e9e; }
            #actionButton:hover { background-color: #9c27b0; }
            #toggleButton { text-align: center; background-color: transparent; border: none; color: #ab47bc; }
            QPlainTextEdit { background-color: #121212; color: #e0e0e0; font-family: "Consolas", "Courier New"; border: 1px solid #4a4a4a; border-radius: 8px; padding: 10px; text-align: left; }
            #filePath { color: #9e9e9e; font-size: 13px; font-style: italic; padding-top: 5px; }
            QLineEdit { border: 1px solid #555; background-color: #3c3c3c; padding: 8px; border-radius: 4px; }
            QCheckBox { spacing: 10px; font-size: 14px; }
            QCheckBox::indicator { width: 20px; height: 20px; margin-left: 10px; }
            QCheckBox::indicator:unchecked { background-color: #3c3c3c; border: 1px solid #555; border-radius: 4px; }
            QCheckBox::indicator:checked { background-color: #ab47bc; border: 1px solid #9c27b0; border-radius: 4px; }
            #aboutLabel { font-size: 11px; color: #888; padding-top: 5px; }
        """)

    def check_dependencies(self):
        """Checks for both java and keytool."""
        self.log_area.appendPlainText("בודק תלות ב-Java Development Kit (JDK)...")
        try:
            startupinfo = None
            if sys.platform == 'win32':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            subprocess.run(["java", "-version"], check=True, capture_output=True, text=True, startupinfo=startupinfo)
            subprocess.run(["keytool", "-help"], check=True, capture_output=True, text=True, startupinfo=startupinfo)
            self.log_area.appendPlainText("נמצאה התקנת JDK תקינה. מוכן.")
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.log_area.appendPlainText("שגיאה קריטית: JDK אינו מותקן או אינו מוגדר בנתיב המערכת (PATH).")
            QMessageBox.critical(self, "JDK לא נמצא", "אפליקציה זו דורשת התקנה מלאה של Java Development Kit (JDK).\nודא שהיא מותקנת ושהנתיב שלה (למשל, C:\\Program Files\\Java\\jdk-17\\bin) מוגדר במשתני הסביבה של המערכת.")
            self.patch_button.setEnabled(False)
            self.select_button.setEnabled(False)

    def check_for_updates(self):
        self.update_thread = UpdateCheckThread()
        self.update_thread.update_available.connect(self.show_update_dialog)
        self.update_thread.update_check_failed.connect(self.log_update_error)
        self.update_thread.start()

    def show_update_dialog(self, version, url):
        update_dialog = UpdateDialog(VERSION, version, url, self)
        if update_dialog.exec() == QDialog.DialogCode.Accepted:
            QDesktopServices.openUrl(QUrl(url))

    def log_update_error(self, message):
        self.log_area.appendPlainText(f"בדיקת עדכונים: {message}")

    def open_file_dialog(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "בחר קובץ APK", "", "Android Package (*.apk)")
        if file_name:
            self.selected_apk_path = file_name
            self.selected_file_path_label.setText(Path(file_name).name)
            self.patch_button.setEnabled(True)
            self.open_folder_button.hide()

    def open_output_folder(self):
        path = str(self.base_path)
        if sys.platform == 'win32': os.startfile(path)
        elif sys.platform == 'darwin': subprocess.Popen(['open', path])
        else: subprocess.Popen(['xdg-open', path])

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
            keystore_path="",
            key_alias=self.ks_alias_input.text(),
            key_pass=self.ks_pass_input.text(),
            base_path=self.base_path
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
    app.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
    ex = App()
    ex.show()
    sys.exit(app.exec())
