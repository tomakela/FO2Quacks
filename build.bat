rmdir /s /q dist
rmdir /s /q build
pyinstaller --onefile --windowed --noconfirm --clean  --add-data="*.patch:." fo2_patcher.py
