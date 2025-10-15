# netfree-apk-editor
this is a python script designed to edit apk file to support external https certificates

this script reuierd java instalation.

--- 

זה הינו סקריפט פייתון שנועד להקל וליעל את תהליך עריכת קבצי apk עבור משתמשי נטפרי.
עבור סקריפט זה יש להתקין ג'אווה. 






עבור מי שרוצה לבנות את הסקריפט שיוריד את הrepo יתקין את `requirements.txt`.

מי שרוצה כexe אז Pyinstaller כמובן.

עם הפקודה
```
python -m PyInstaller
--onefile
--windowed
--icon="apk.ico"
--add-data "apksigner.jar:."
--add-data "apktool.jar:."
--add-data "zipalign.exe:."
--add-data "network_security_config.xml:."
--add-data "apk.ico:."
.\netfree_patcher.py
```

או עם קובץ ידני מה שנוח לכם תהנו.



<img width="360" height="420" alt="image" src="https://github.com/user-attachments/assets/e6af9683-b644-43b9-b988-33e210ea6d4d" />
