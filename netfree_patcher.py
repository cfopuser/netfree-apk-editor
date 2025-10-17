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
import time

from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QFileDialog, QLabel, QCheckBox,
                             QPlainTextEdit, QMessageBox, QFrame, QLineEdit,
                             QDialog, QStyle, QProgressBar)
from PyQt6.QtCore import QThread, pyqtSignal, Qt, QUrl, QTimer
from PyQt6.QtGui import QIcon, QMovie, QDesktopServices, QTextCursor

# --- Application Constants ---
VERSION = "1.3"
CONFIG_FILE = "config.json"

def get_base_path():
    """
    Gets the correct base path for bundled PyInstaller executables vs. a normal script.
    This ensures that bundled assets (like icons, jars) are found correctly.
    """
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        # Running as a bundled executable
        return Path(sys.executable).parent
    else:
        # Running as a regular .py script
        return Path(__file__).parent.resolve()

# --- Worker Threads ---

class UpdateCheckThread(QThread):
    update_available = pyqtSignal(str, str)
    update_check_failed = pyqtSignal(str)

    def run(self):
        repo_url = "https://api.github.com/repos/cfopuser/netfree-apk-editor/releases/latest"
        try:
            unverified_context = ssl._create_unverified_context()
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


class PatcherThread(QThread):
    progress_updated = pyqtSignal(int)
    log_message = pyqtSignal(str)
    # MODIFIED: Signal now includes the final path string
    process_finished = pyqtSignal(bool, str, str)

    def __init__(self, apk_file, make_debuggable, keystore_path, key_alias, key_pass, base_path):
        super().__init__()
        self.apk_file = Path(apk_file)
        self.make_debuggable = make_debuggable
        self.script_dir = Path(__file__).parent.resolve()
        self.output_dir = Path(base_path)

        if keystore_path:
            self.keystore_path = Path(keystore_path).expanduser()
            self.is_custom_keystore = True
        else:
            self.keystore_path = self.output_dir / "debug.keystore"
            self.is_custom_keystore = False

        self.key_alias = key_alias or "androiddebugkey"
        self.key_pass = key_pass or "android"

    def run_command(self, command):
        """Runs a command, captures output, and raises a detailed exception on failure."""
        try:
            startupinfo = None
            creationflags = 0
            if sys.platform == 'win32':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                creationflags = subprocess.CREATE_NO_WINDOW

            process = subprocess.run(
                command, check=True, text=True, capture_output=True,
                startupinfo=startupinfo,
                creationflags=creationflags
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
        """The main entry point for the thread's execution. It runs the entire patching workflow."""
        total_steps = 7
        current_step = 0
        def update_progress():
            nonlocal current_step
            current_step += 1
            progress = int((current_step / total_steps) * 100)
            self.progress_updated.emit(progress)

        filename_stem = self.apk_file.stem
        temp_apk_path = self.output_dir / f"{filename_stem}_temp.apk"
        tmp_dir = self.script_dir / f"temp_{filename_stem}"
        final_apk_path = self.output_dir / f"{filename_stem}_netfree.apk"

        try:
            self.progress_updated.emit(0)

            apktool_path = self.script_dir / "apktool.jar"
            zipalign_path = self.script_dir / "zipalign.exe"
            apksigner_path = self.script_dir / "apksigner.jar"
            network_config_path = self.script_dir / "network_security_config.xml"

            if self.is_custom_keystore and not self.keystore_path.exists():
                raise FileNotFoundError(f"קובץ חתימה מותאם אישית לא נמצא בנתיב: {self.keystore_path}")
            elif not self.keystore_path.exists():
                self.log_message.emit(f"קובץ חתימה לא נמצא. יוצר אחד חדש בנתיב {self.keystore_path}...")
                keytool_command = ["keytool", "-genkey", "-v", "-keystore", str(self.keystore_path), "-storepass", self.key_pass, "-alias", self.key_alias, "-keypass", self.key_pass, "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000", "-dname", "CN=Android Debug, O=Android, C=US"]
                self.run_command(keytool_command)
            else:
                self.log_message.emit(f"משתמש בקובץ חתימה קיים: {self.keystore_path}")
            update_progress()

            self.log_message.emit(f"\n--- שלב 1: מפרק את {self.apk_file.name} ---")
            if tmp_dir.exists(): shutil.rmtree(tmp_dir)
            self.run_command(["java", "-jar", str(apktool_path), "d", "-s", "-f", "-o", str(tmp_dir), str(self.apk_file)])
            update_progress()

            self.log_message.emit("\n--- שלב 2: מוסיף הגדרות אבטחת רשת ---")
            xml_dir = tmp_dir / "res" / "xml"
            xml_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy(network_config_path, xml_dir)
            update_progress()

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
            update_progress()

            self.log_message.emit(f"\n--- שלב 4: בונה מחדש אל {temp_apk_path.name} ---")
            self.run_command(["java", "-jar", str(apktool_path), "b", "-o", str(temp_apk_path), str(tmp_dir)])
            update_progress()

            self.log_message.emit(f"\n--- שלב 5: מיישר את {final_apk_path.name} ---")
            self.run_command([str(zipalign_path), "-p", "4", str(temp_apk_path), str(final_apk_path)])
            update_progress()

            self.log_message.emit(f"\n--- שלב 6: חותם את {final_apk_path.name} ---")
            sign_cmd = ["java", "-jar", str(apksigner_path), "sign", "--ks", str(self.keystore_path), "--ks-key-alias", self.key_alias, "--ks-pass", f"pass:{self.key_pass}", str(final_apk_path)]
            self.run_command(sign_cmd)
            update_progress()

            self.process_finished.emit(True, f"הצלחה! קובץ APK מתוקן נוצר בנתיב:\n{final_apk_path}")

        except Exception as e:
            self.log_message.emit(f"\n--- אירעה שגיאה ---\n{e}")
            self.process_finished.emit(False, "התיקון נכשל. בדוק את היומן לפרטים נוספים.")

        finally:
            self.log_message.emit("\n--- שלב 7: מנקה קבצים זמניים ---")
            if temp_apk_path.exists():
                try: os.remove(temp_apk_path)
                except OSError as e: self.log_message.emit(f"שגיאה במחיקת קובץ זמני: {e}")
            if tmp_dir.exists():
                try: shutil.rmtree(tmp_dir)
                except OSError as e: self.log_message.emit(f"שגיאה במחיקת תיקייה זמנית: {e}")


class DeepEditThread(QThread):
    log_message = pyqtSignal(str)

    process_finished = pyqtSignal(bool, str, str)

    def __init__(self, apk_file, base_path):
        super().__init__()
        self.apk_file = Path(apk_file)
        self.base_path = Path(base_path)

    def run(self):
        self.script_dir = Path(__file__).parent.resolve()
        apk_mitm_path = self.script_dir / "apk-mitm.exe"
        # apk-mitm creates the output file in the same directory as the input file
        final_apk_path = self.apk_file.parent / f"{self.apk_file.stem}-patched.apk"

        try:
            if not apk_mitm_path.exists():
                raise FileNotFoundError(f"קובץ 'apk-mitm.exe' לא נמצא בתיקיית התוכנה.\nודא שהוא קיים בנתיב: {apk_mitm_path}")

            self.log_message.emit(f"--- מתחיל עריכה עמוקה עם apk-mitm על {self.apk_file.name} ---")

            startupinfo = None
            creationflags = 0
            if sys.platform == 'win32':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                creationflags = subprocess.CREATE_NO_WINDOW

            command = [str(apk_mitm_path), str(self.apk_file)]
            self.log_message.emit(f"מריץ פקודה: {' '.join(command)}")

            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                errors='replace',
                startupinfo=startupinfo,
                creationflags=creationflags
            )

            # Stream output in real-time
            for line in iter(process.stdout.readline, ''):
                self.log_message.emit(line.strip())

            process.stdout.close()
            return_code = process.wait()

            if return_code == 0 and final_apk_path.exists():
                self.log_message.emit("--- עריכה עמוקה הסתיימה בהצלחה ---")
                success_message = f"הצלחה! קובץ APK מתוקן נוצר בנתיב:\n{final_apk_path}"
                # MODIFIED: Emit the final path on success
                self.process_finished.emit(True, success_message, str(final_apk_path))
            else:
                self.log_message.emit(f"--- apk-mitm סיים עם קוד שגיאה: {return_code} ---")
                error_msg = ("העריכה העמוקה נכשלה. ודא ש-mitmproxy מותקן כראוי (`pip install mitmproxy`) ונסה שוב.\n"
                             "בדוק ביומן למעלה הודעות שגיאה מפורטות מ-apk-mitm.")
                # MODIFIED: Emit an empty path on failure
                self.process_finished.emit(False, error_msg, "")

        except Exception as e:
            self.log_message.emit(f"\n--- אירעה שגיאה קריטית ---\n{e}")
            # MODIFIED: Emit an empty path on failure
            self.process_finished.emit(False, "העריכה העמוקה נכשלה עקב שגיאה פנימית. בדוק את היומן לפרטים.", "")


# --- UI Classes ---

class UpdateDialog(QDialog):
    # ... [This class remains unchanged] ...
    def __init__(self, current_version, new_version, url, parent=None):
        super().__init__(parent)
        self.url = url
        self.setWindowTitle("עדכון זמין")
        self.setMinimumWidth(450)
        self.setModal(True)
        if parent and parent.windowIcon():
             self.setWindowIcon(parent.windowIcon())
        self.init_ui(current_version, new_version)
        self.apply_stylesheet()

    def init_ui(self, current_version, new_version):
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

class App(QWidget):
    def __init__(self):
        super().__init__()
        # Store essential paths
        self.base_path = get_base_path()
        self.script_dir = Path(__file__).parent.resolve()

        # State variables
        self.selected_apk_path = ""
        self.selected_keystore_path = ""
        # NEW: Store the path of the last successful output file
        self.last_output_path = ""
        self.start_time = 0 # To store the start time of the process

       #  Setup the QTimer for the stopwatch
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_timer_label)

        # Main window setup
        self.setWindowTitle("Netfree APK Patcher")
        self.setWindowIcon(QIcon(str(self.script_dir / "apk.ico")))
        self.setGeometry(100, 100, 650, 820)
        self.setAcceptDrops(True)

        # Initialize UI components and perform startup checks
        self.init_ui()
        self.apply_stylesheet()
        self.load_settings()
        self.check_dependencies()
        self.check_for_updates()

    # --- Configuration Methods ---
    # ... [load_settings, save_settings remain the same] ...
    def load_settings(self):
        config_path = self.base_path / CONFIG_FILE
        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    settings = json.load(f)
                ks_path = settings.get('keystore_path')
                if ks_path and Path(ks_path).exists():
                    self.selected_keystore_path = ks_path
                    self.keystore_path_label.setText(Path(ks_path).name)
                    self.clear_keystore_button.show()
                else:
                    self.clear_keystore_selection()
                self.ks_alias_input.setText(settings.get('key_alias', ''))
                self.debug_checkbox.setChecked(settings.get('make_debuggable', False))
                self.deep_edit_checkbox.setChecked(settings.get('use_deep_edit', False))
                self.update_advanced_options_state(self.deep_edit_checkbox.isChecked())
                self.append_log_message("הגדרות נטענו מקובץ config.json.", 'info')
            except Exception as e:
                self.append_log_message(f"שגיאה בטעינת הגדרות: {e}", 'error')

    def save_settings(self):
        settings = {
            'keystore_path': self.selected_keystore_path,
            'key_alias': self.ks_alias_input.text(),
            'make_debuggable': self.debug_checkbox.isChecked(),
            'use_deep_edit': self.deep_edit_checkbox.isChecked()
        }
        config_path = self.base_path / CONFIG_FILE
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(settings, f, indent=4)
        except Exception as e:
            print(f"Warning: Could not save configuration file: {e}")

    # --- Qt Event Overrides ---
    # ... [closeEvent, dragEnterEvent, dropEvent remain the same] ...
    def closeEvent(self, event):
        self.save_settings()
        event.accept()

    def dragEnterEvent(self, event):
        mime_data = event.mimeData()
        if mime_data.hasUrls() and len(mime_data.urls()) == 1:
            url = mime_data.urls()[0]
            if url.isLocalFile() and url.toLocalFile().lower().endswith('.apk'):
                event.acceptProposedAction()

    def dropEvent(self, event):
        file_path = event.mimeData().urls()[0].toLocalFile()
        self.set_apk_file(file_path)

    # --- UI Initialization ---
    # ... [init_ui and its sub-methods remain mostly the same] ...
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

        file_selection_layout = QHBoxLayout()
        self.selected_file_path_label = QLabel("גרור קובץ לכאן או לחץ לבחירה...")
        self.selected_file_path_label.setObjectName("filePath")
        self.clear_apk_button = QPushButton("נקה")
        self.clear_apk_button.setObjectName("clearButton")
        self.clear_apk_button.hide()
        self.clear_apk_button.clicked.connect(self.clear_apk_selection)
        file_selection_layout.addWidget(self.selected_file_path_label)
        file_selection_layout.addStretch()
        file_selection_layout.addWidget(self.clear_apk_button)

        file_card.layout().addWidget(self.select_button)
        file_card.layout().addLayout(file_selection_layout)

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
        self.open_folder_button = QPushButton("פתח את תיקיית התוצאות")
        self.open_folder_button.hide()
        self.open_folder_button.clicked.connect(self.open_output_folder)
        action_layout.addWidget(self.patch_button)

        action_layout.addStretch()
        action_layout.addWidget(self.open_folder_button)

        
        self.timer_box = QFrame()
        self.timer_box.setObjectName("timerBox")
        timer_box_layout = QHBoxLayout(self.timer_box)
        self.timer_label = QLabel("00.00")
        self.timer_box.setFixedSize(120, 70)
        self.timer_label.setObjectName("timerLabel")
        self.timer_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        timer_box_layout.addWidget(self.timer_label)
        self.timer_box.hide()

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.progress_bar.hide()

        log_label = QLabel("יומן התקדמות")
        log_label.setObjectName("header")
        self.log_area = QPlainTextEdit()
        self.log_area.setReadOnly(True)

        bottom_layout = QHBoxLayout()
        about_text = 'פותח על ידי <a href="https://mitmachim.top/user/cfopuser" style="color: #ab47bc; text-decoration: none;">@cfopuser</a>'
        about_label = QLabel(about_text)
        about_label.setOpenExternalLinks(True)
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
        main_layout.addWidget(self.timer_box) # Add the timer box to the layout
        main_layout.addWidget(self.progress_bar)
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

        keystore_title = QLabel("קובץ חתימה (Keystore)")
        keystore_title.setObjectName("subheader")
        layout.addWidget(keystore_title)

        self.keystore_select_button = QPushButton("בחר קובץ חתימה קיים...")
        self.keystore_select_button.clicked.connect(self.select_keystore_file)
        layout.addWidget(self.keystore_select_button)

        keystore_selection_layout = QHBoxLayout()
        self.keystore_path_label = QLabel("ברירת מחדל: יצירת debug.keystore אוטומטית")
        self.keystore_path_label.setObjectName("filePath")
        self.clear_keystore_button = QPushButton("נקה")
        self.clear_keystore_button.setObjectName("clearButton")
        self.clear_keystore_button.hide()
        self.clear_keystore_button.clicked.connect(self.clear_keystore_selection)
        keystore_selection_layout.addWidget(self.keystore_path_label)
        keystore_selection_layout.addStretch()
        keystore_selection_layout.addWidget(self.clear_keystore_button)
        layout.addLayout(keystore_selection_layout)

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

        # --- Separator and Deep Editing option ---
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(separator)

        deep_edit_title = QLabel("עריכה עמוקה (apk-mitm)")
        deep_edit_title.setObjectName("subheader")
        layout.addWidget(deep_edit_title)

        self.deep_edit_checkbox = QCheckBox("הפעל עריכה עמוקה, מומלץ במקרים שעריכה רגילה אינה מספקת.")
        self.deep_edit_checkbox.toggled.connect(self.update_advanced_options_state)
        layout.addWidget(self.deep_edit_checkbox)

        deep_edit_desc = QLabel(" אפשרות זו מצריכה חיבור פעיל לאינטרנט, ותיקח יותר זמן משמעותית.")
        deep_edit_desc.setObjectName("filePath")
        deep_edit_desc.setWordWrap(True)
        layout.addWidget(deep_edit_desc)

        return frame

    def toggle_advanced_options(self):
        if self.advanced_frame.isVisible():
            self.advanced_toggle_button.setText("אפשרויות מתקדמות ▼")
            self.advanced_frame.hide()
        else:
            self.advanced_toggle_button.setText("אפשרויות מתקדמות ▲")
            self.advanced_frame.show()

    def update_advanced_options_state(self, checked):
         """Disables and clears normal patching options when deep editing is selected."""
         is_normal_patching_enabled = not checked
 
         # Disable/Enable controls based on the checkbox state
         self.debug_checkbox.setEnabled(is_normal_patching_enabled)
         self.keystore_select_button.setEnabled(is_normal_patching_enabled)
         self.clear_keystore_button.setEnabled(is_normal_patching_enabled and bool(self.selected_keystore_path))
         self.ks_alias_input.setEnabled(is_normal_patching_enabled)
         self.ks_pass_input.setEnabled(is_normal_patching_enabled)
 
         if checked:
             # When deep editing is selected, clear all other advanced options.
             self.debug_checkbox.setChecked(False)
             self.clear_keystore_selection()
             self.ks_alias_input.clear()
             self.ks_pass_input.clear()
             self.patch_button.setText("התחל עריכה עמוקה")
         else:
             self.patch_button.setText("ערוך את ה-APK")
             
    def apply_stylesheet(self):
        self.setStyleSheet("""
            QWidget { background-color: #1e1e1e; color: #f0f0f0; font-family: "Segoe UI", "Arial"; }
            QLabel { background-color: transparent; border: none; }
            #title { font-size: 28px; font-weight: 900; color: #ffffff; padding-bottom: 10px; }
            #header { font-size: 16px; font-weight: 600; color: #ab47bc; padding-bottom: 5px; }
            #subheader { font-size: 14px; font-weight: 600; color: #ccc; padding-top: 5px; border-top: 1px solid #444; margin-top: 5px;}
            QFrame#card { background-color: #2d2d2d; border: 1px solid #4a4a4a; border-radius: 12px; }
            QPushButton { background-color: #3c3c3c; border: 1px solid #555; padding: 12px; font-size: 14px; font-weight: 500; border-radius: 8px; text-align: right; padding-right: 15px; }
            QPushButton:hover { background-color: #4a4a4a; border-color: #777; }
            #actionButton { background-color: #ab47bc; color: white; font-size: 16px; font-weight: bold; border: none; text-align: center; }
            #actionButton:disabled { background-color: #5f3a69; color: #9e9e9e; }
            #actionButton:hover { background-color: #9c27b0; }
            #toggleButton { text-align: center; background-color: transparent; border: none; color: #ab47bc; }
            #clearButton { padding: 4px 8px; font-size: 12px; text-align: center; max-width: 50px; }
            QPlainTextEdit { background-color: #121212; color: #e0e0e0; font-family: "Consolas", "Courier New"; border: 1px solid #4a4a4a; border-radius: 8px; padding: 10px; text-align: left; }
            #filePath { color: #9e9e9e; font-size: 13px; font-style: italic; padding-top: 5px; }
            QLineEdit { border: 1px solid #555; background-color: #3c3c3c; padding: 8px; border-radius: 4px; }
            QCheckBox { spacing: 10px; font-size: 14px; background-color: transparent; }
            QCheckBox::indicator { width: 20px; height: 20px; margin-left: 10px; }
            QCheckBox::indicator:unchecked { background-color: #3c3c3c; border: 1px solid #555; border-radius: 4px; }
            QCheckBox::indicator:checked { background-color: #ab47bc; border: 1px solid #9c27b0; border-radius: 4px; }
            #aboutLabel { font-size: 11px; color: #888; padding-top: 5px; }
            QProgressBar { border: 1px solid #555; border-radius: 8px; text-align: center; padding: 2px; background-color: #3c3c3c; color: #f0f0f0; font-weight: bold; }
            QProgressBar::chunk { background-color: #ab47bc; border-radius: 7px; }
            
            /* --- IMPROVEMENT: Styles for the new timer box --- */
            #timerBox {
                background-color: #2d2d2d;
                border: 1px solid #4a4a4a;
                border-radius: 8px;
                padding: 5px 0;
                margin-top: 5px;
            }
            #timerLabel {
                font-family: "Consolas", "Courier New", monospace;
                font-size: 20px;
                font-weight: bold;
                color: #e0e0e0;
                background-color: transparent;
                border: none;
            }
        """)

    def update_timer_label(self):
        # ... [this method is unchanged] ...
        elapsed = time.monotonic() - self.start_time
        seconds = int(elapsed)
        centiseconds = int((elapsed - seconds) * 100)
        self.timer_label.setText(f"{seconds:02d}.{centiseconds:02d}")

    def set_controls_enabled(self, enabled):
        # ... [this method is unchanged] ...
        self.select_button.setEnabled(enabled)
        self.clear_apk_button.setEnabled(enabled and bool(self.selected_apk_path))
        self.advanced_toggle_button.setEnabled(enabled)
        self.patch_button.setEnabled(enabled and bool(self.selected_apk_path))
        self.deep_edit_checkbox.setEnabled(enabled)
        if enabled:
            self.update_advanced_options_state(self.deep_edit_checkbox.isChecked())
        else:
            self.debug_checkbox.setEnabled(False)
            self.keystore_select_button.setEnabled(False)
            self.clear_keystore_button.setEnabled(False)
            self.ks_alias_input.setEnabled(False)
            self.ks_pass_input.setEnabled(False)

    def check_dependencies(self):
        # ... [this method is unchanged] ...
        self.append_log_message("בודק תלות ב-Java Development Kit (JDK)...", 'info')
        try:
            startupinfo = None
            if sys.platform == 'win32':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            subprocess.run(["java", "-version"], check=True, capture_output=True, text=True, startupinfo=startupinfo)
            subprocess.run(["keytool", "-help"], check=True, capture_output=True, text=True, startupinfo=startupinfo)
            self.append_log_message("נמצאה התקנת JDK תקינה. מוכן.", 'success')
        except (subprocess.CalledProcessError, FileNotFoundError):
            msg = "שגיאה קריטית: JDK אינו מותקן או אינו מוגדר בנתיב המערכת (PATH)."
            self.append_log_message(msg, 'error')
            QMessageBox.critical(self, "JDK לא נמצא", "אפליקציה זו דורשת התקנה מלאה של Java Development Kit (JDK).\nודא שהיא מותקנת ושהנתיב שלה (למשל, C:\\Program Files\\Java\\jdk-17\\bin) מוגדר במשתני הסביבה של המערכת.")
            self.patch_button.setEnabled(False)
            self.select_button.setEnabled(False)

    def check_for_updates(self):
        # ... [this method is unchanged] ...
        self.update_thread = UpdateCheckThread()
        self.update_thread.update_available.connect(self.show_update_dialog)
        self.update_thread.update_check_failed.connect(lambda msg: self.append_log_message(f"בדיקת עדכונים: {msg}", 'error'))
        self.update_thread.start()

    def show_update_dialog(self, version, url):
        # ... [this method is unchanged] ...
        update_dialog = UpdateDialog(VERSION, version, url, self)
        if update_dialog.exec() == QDialog.DialogCode.Accepted:
            QDesktopServices.openUrl(QUrl(url))

    def open_file_dialog(self):
        # ... [this method is unchanged] ...
        file_name, _ = QFileDialog.getOpenFileName(self, "בחר קובץ APK", "", "Android Package (*.apk *.xapk)")
        if file_name: self.set_apk_file(file_name)

    def set_apk_file(self, file_path):
        self.selected_apk_path = file_path
        self.selected_file_path_label.setText(Path(file_path).name)
        self.patch_button.setEnabled(True)
        self.clear_apk_button.show()
        self.open_folder_button.hide()
        self.last_output_path = "" # Clear previous result path

    def clear_apk_selection(self):
        # ... [this method is unchanged] ...
        self.selected_apk_path = ""
        self.selected_file_path_label.setText("גרור קובץ לכאן או לחץ לבחירה...")
        self.patch_button.setEnabled(False)
        self.clear_apk_button.hide()
        self.last_output_path = ""

    def select_keystore_file(self):
        # ... [this method is unchanged] ...
        file_name, _ = QFileDialog.getOpenFileName(self, "בחר קובץ חתימה", "", "Keystore files (*.keystore *.jks)")
        if file_name:
            self.selected_keystore_path = file_name
            self.keystore_path_label.setText(Path(file_name).name)
            self.clear_keystore_button.show()

    def clear_keystore_selection(self):
        # ... [this method is unchanged] ...
        self.selected_keystore_path = ""
        self.keystore_path_label.setText("ברירת מחדל: יצירת debug.keystore אוטומטית")
        self.clear_keystore_button.hide()

    # MODIFIED: Reworked logic to be simpler and more robust
    def open_output_folder(self):
        """Opens the folder containing the last generated APK."""
        if not self.last_output_path:
            # Fallback to base_path if no output path is set
            path_to_open = self.base_path
        else:
            output_path = Path(self.last_output_path)
            if not output_path.exists():
                 # Fallback if file was moved/deleted
                path_to_open = output_path.parent
            else:
                 # The primary logic
                if sys.platform == 'win32':
                    # On Windows, use 'explorer /select' to highlight the file
                    subprocess.run(['explorer', '/select,', str(output_path)])
                    return
                # For other OSes, just open the parent directory
                path_to_open = output_path.parent

        # Cross-platform way to open a directory
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path_to_open)))


    # --- Main Process Control ---
    def start_patching(self):
        if not self.selected_apk_path:
            QMessageBox.warning(self, "לא נבחר קובץ", "אנא בחר קובץ APK תחילה.")
            return

        self.set_controls_enabled(False)
        self.open_folder_button.hide()
        self.log_area.clear()

        # Reset and show progress UI
        self.timer_label.setText("00.00")
        self.progress_bar.setValue(0)
        self.timer_box.show() # Show the container box
        self.last_output_path = "" # Reset output path

        self.start_time = time.monotonic()
        self.timer.start(33) # Update roughly 30 times per second

        if self.deep_edit_checkbox.isChecked():
            self.progress_bar.hide()
            self.deep_editor = DeepEditThread(
                apk_file=self.selected_apk_path,
                base_path=self.base_path
            )
            self.deep_editor.log_message.connect(self.append_log_message)
            self.deep_editor.process_finished.connect(self.on_patching_finished)
            self.deep_editor.start()
        else:
            self.progress_bar.show()
            self.patcher = PatcherThread(
                apk_file=self.selected_apk_path,
                make_debuggable=self.debug_checkbox.isChecked(),
                keystore_path=self.selected_keystore_path,
                key_alias=self.ks_alias_input.text(),
                key_pass=self.ks_pass_input.text(),
                base_path=self.base_path
            )
            self.patcher.log_message.connect(self.append_log_message)
            self.patcher.progress_updated.connect(self.progress_bar.setValue)
            self.patcher.process_finished.connect(self.on_patching_finished)
            self.patcher.start()

    # MODIFIED: Major overhaul for better log formatting
    def append_log_message(self, message, message_type=None):
        """Parses and appends a styled log message to the log area."""
        if not message:
            return

        # Default styles
        color = '#E0E0E0' # Default info color
        style = 'margin: 1px 0;'
        
        # --- My own application messages ---
        if message_type == 'step': color = '#87CEEB' # Light blue
        elif message_type == 'success': color = '#90EE90' # Light green
        elif message_type == 'error': color = '#F08080' # Light red
        
        # --- Parsing apk-mitm output ---
        else:
            msg_strip = message.strip()
            # Major status lines like "[05:28:20] Decoding APK file [started]"
            if match := re.search(r'\[\d{2}:\d{2}:\d{2}\]\s(.*?)\s\[(started|completed|skipped)\]', msg_strip):
                action, status = match.groups()
                status_colors = {'completed': '#90EE90', 'started': '#87CEEB', 'skipped': '#9E9E9E'}
                color = status_colors.get(status, '#E0E0E0')
                style += 'font-weight: bold;'
            # Sub-steps like "→ Using Apktool 2.9.3 on app.apk"
            elif msg_strip.startswith('→'):
                color = '#B0B0B0' # Lighter grey for details
                style += 'margin-left: 15px;'
            # Successful patch applications
            elif 'Applied' in message and 'patch' in msg_strip:
                color = '#4CAF50' # Darker success green
                style += 'margin-left: 15px; font-weight: bold;'
            # The final "Done!" message
            elif 'Done!' in msg_strip:
                color = '#90EE90'
                style += 'font-weight: bold;'
            # The big warning block
            elif 'WARNING' in msg_strip:
                color = '#FFD700' # Gold/Yellow
                style += 'border: 1px solid #FFD700; padding: 5px; margin-top: 5px;'
            # De-emphasize verbose baksmaling/smaling lines
            elif 'Baksmaling' in msg_strip or 'Smaling' in msg_strip:
                color = '#777777' # Dark grey
                style += 'margin-left: 15px;'

        # Sanitize for HTML and format
        message_html = message.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        formatted_message = f'<pre style="color:{color}; {style} white-space: pre-wrap; word-wrap: break-word;">{message_html}</pre>'

        self.log_area.appendHtml(formatted_message)
        self.log_area.moveCursor(QTextCursor.MoveOperation.End)


    # MODIFIED: Signature changed to accept the final file path
    def on_patching_finished(self, success, message, final_path=""):
        self.timer.stop()
        self.update_timer_label() # Final update to show the precise end time

        self.progress_bar.hide()
        self.set_controls_enabled(True)
        self.last_output_path = final_path # Store the path for the "open folder" button

        self.append_log_message(f"\n{'='*20}", 'info')
        self.append_log_message(message, 'success' if success else 'error')

        if success:
            self.open_folder_button.show()
            QMessageBox.information(self, "הצלחה", message)
        else:
            self.timer_box.hide() # Hide timer on failure
            QMessageBox.critical(self, "כישלון", message)


# --- Application Entry Point ---
if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
    ex = App()
    ex.show()
    sys.exit(app.exec())
