# netfree-apk-editor
this is a python script designed to edit apk file to support external https certificates

this script reuierd java instalation.

--- 

זה הינו סקריפט פייתון שנועד להקל וליעל את תהליך עריכת קבצי apk עבור משתמשי נטפרי.
עבור סקריפט זה יש להתקין ג'אווה. 



<img width="360" height="360" alt="image" src="https://github.com/user-attachments/assets/31353710-2fd2-4021-9866-e90242e7a548" />


עבור מי שרוצה לבנות את הסקריפט שיוריד את הrepo יתקין את `requirements.txt` ויהנה.`

מי שרוצה כexe אז Pyinstaller כמובן.

עם הפקודה
```
python -m PyInstaller
--onefile
--windowed
--icon="apk.ico"
--add-data "apksigner.jar:."
--add-data "apktool.jar:."
--add-data "keytool.exe:."
--add-data "zipalign.exe:."
--add-data "network_security_config.xml:."
--add-data "apk.ico:."
.\netfree_patcher.py
```

או עם קובץ ידני מה שנוח לכם תהנו.
