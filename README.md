# netfree-apk-editor
this is a python script designed to edit apk file to support external ssl certificates

part of this script is based on the [apk-mitm] project.
this script reuierd java instalation.

--- 

זה הינו סקריפט פייתון שנועד להקל וליעל את תהליך עריכת קבצי apk עבור משתמשי נטפרי.
**
שימו לב** תוכנה זו מצריכה ג'אווה (jdk לא מספיק jre) מותקנת במידה ולא התקנתם בעבר הורידו [מפה](https://adoptium.net/en-GB/download?link=https%3A%2F%2Fgithub.com%2Fadoptium%2Ftemurin25-binaries%2Freleases%2Fdownload%2Fjdk-25%252B36%2FOpenJDK25U-jdk_x64_windows_hotspot_25_36.msi&vendor=Adoptium)  או [מפה](https://adoptium.net/en-GB/temurin/releases).

**שימו לב** בעת שימוש בתכונה "עריכה עמוקה",
האנטי וירוס של ווינדוס עלול לזהות זאת כוירוס, זהו זיהוי [מוטעה](https://www.virustotal.com/gui/file/2148e815c365f50e5a6500838b6e729f2651d4c340dc8ab413fbfa3684aebecb/detection),
כבו את האנטי וירוס או אשרו את ההתראה לכשתבוא.





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





עבור החשדנים:
MD5: af06f271e0b1819d5fad85c2de2fbd9e52c60bcfdc91fabe310069f705853970
[virus total](https://www.virustotal.com/gui/file/af06f271e0b1819d5fad85c2de2fbd9e52c60bcfdc91fabe310069f705853970?nocache=1)

<img width="360" height="420" alt="image" src="https://github.com/user-attachments/assets/e6af9683-b644-43b9-b988-33e210ea6d4d" />
