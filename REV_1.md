# WRITEUP — SmartGPT Wrapper Reverse Engineering

## 1. ĐỀ
* **Hint:** *"Not Everything Was Removed Before Release. Sometime dev forget it."*
## 2. File Smartgpt

```bash
curl -sk -o smartgpt "https://94cee7a6-....nip.io/download"
file smartgpt
```
<img width="1889" height="123" alt="image" src="https://github.com/user-attachments/assets/a87fd5d9-64a9-4c84-a968-63a48f9e4cf3" />

## 3. Extract PyInstaller — pyinstxtractor

```bash
# lấy tool
curl -sL -o pyinstxtractor.py \
  https://raw.githubusercontent.com/extremecoders-re/pyinstxtractor/master/pyinstxtractor.py

python pyinstxtractor.py smartgpt
```
<img width="1830" height="67" alt="image" src="https://github.com/user-attachments/assets/7b618e6a-bb04-4d11-8886-57d6f406e7ed" />

Thư mục `smartgpt_extracted/` thu được:

| File | Vai trò |
|---|---|
| `smartgpt.pyc` |  **Code chính của app** (bytecode Python 3.8) |
| `PYZ-00.pyz` + `PYZ-00.pyz_extracted/` | Kho thư viện chuẩn Python (không quan trọng) |
| `libpython3.8.so.1.0`, `lib-dynload/` | Interpreter + extension đi kèm |
| `pyiboot01_bootstrap.pyc`, `pyimod0*.pyc` | Cơ chế bootstrap của PyInstaller |
---

## 4. strings file

```bash
strings smartgpt.pyc"
```
<img width="1430" height="418" alt="image" src="https://github.com/user-attachments/assets/d8ef6f3c-f101-4748-82c0-0551a33a5778" />

Thấy ngay các chuỗi base64 khả nghi:

```
ZmxhZ3s0YWY4MWM=                    → flag{4af81c               
Y2RjZmRhNDBkfQ==                    → cdcfda40d}                
ZmQtNDgxMi00NGI=                    → fd-4812-44b               
Ny1iMTNlLWIzNQ==                    → 7-b13e-b35                
```
## 5. Ghép flag
```
1: flag{4af81c
2: fd-4812-44b
3: 7-b13e-b35
4: cdcfda40d}
─────────────────────────────
flag{4af81cfd-4812-44b7-b13e-b35cdcfda40d}
```
