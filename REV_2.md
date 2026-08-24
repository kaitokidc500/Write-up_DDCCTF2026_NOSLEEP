# WRITEUP — ONNX Model Secrets

> **Mô tả:** *"Our AI research team deployed an emotion classification model for internal use... Something sensitive was embedded during the model's calibration process."*
---

## 1. Challenge

- `/model.onnx` — tải file model gốc
- `/api/info` — metadata dạng JSON

### 1.1. `/api/info`

```json
{"model_name":"EmotionNet-v2.1","version":"2.1.0","input_shape":[1,2304],
"output_classes":["angry","disgust","fear","happy","sad","surprise","neutral"],
"framework":"PyTorch 2.1","dataset":"FER-2013","accuracy":0.72}
```

### 1.2. Tải model

```bash
$ curl -s -k -o emotionnet_v2.onnx "https://<instance>/model.onnx"
```

File 2.430.204 bytes, input `1x2304` (ảnh grayscale 48×48 flatten), output 7 logits cảm xúc.

---

## 2. Phân tích sơ bộ
<img width="1646" height="832" alt="image" src="https://github.com/user-attachments/assets/99a48de6-cd2b-4d15-a2b3-468dae7e320a" />
<img width="491" height="674" alt="image" src="https://github.com/user-attachments/assets/961036d9-a3e3-492c-a3a7-65051c7e06fc" />

Model thực chất là một MLP:

```text
2304 -> 128 -> 64 -> 7
```
Input:

```text
shape = [1, 2304]
dtype = float32
```
Vì:

```text
2304 = 48 * 48
```
và metadata chỉ ra dataset FER-2013, input nhiều khả năng là ảnh grayscale `48 x 48` được flatten.

Output:

```text
shape = [1, 7]
dtype = float32
```
tương ứng 7 lớp cảm xúc.

---
# 3. Dump toàn bộ cấu trúc ONNX

Tạo file:

```text
inspect_onnx.py
```

```python
import onnx

MODEL = "emotionnet_v2.onnx"

model = onnx.load(MODEL)

print("=== MODEL ===")
print("IR version :", model.ir_version)
print("Graph name :", model.graph.name)
print("Producer   :", model.producer_name)
print("Domain     :", model.domain)

print("\n=== INPUT ===")
for x in model.graph.input:
    print(x)

print("\n=== OUTPUT ===")
for x in model.graph.output:
    print(x)

print("\n=== NODES ===")
for i, node in enumerate(model.graph.node):
    print(
        f"[{i:02d}]",
        node.op_type,
        list(node.input),
        "->",
        list(node.output),
    )

print("\n=== INITIALIZERS ===")
for tensor in model.graph.initializer:
    print(
        tensor.name,
        "shape=",
        list(tensor.dims),
        "dtype=",
        tensor.data_type,
    )

print("\n=== METADATA ===")
for item in model.metadata_props:
    print(f"{item.key} = {item.value}")
```

<img width="1799" height="774" alt="image" src="https://github.com/user-attachments/assets/3d2d44db-6736-4e38-8aa6-3d18000d6e2a" />

Các initializer quan trọng:

```text
fc1.weight     [128, 2304]
fc1.bias       [128]

fc2.weight     [64, 128]
fc2.bias       [64]

fc3.weight     [7, 64]
fc3.bias       [7]

fc1.weight_t   [2304, 128]
fc2.weight_t   [128, 64]
fc3.weight_t   [64, 7]
```

Điểm đáng chú ý:

```text
fc2.weight
```

và:

```text
fc2.weight_t
```

đều tồn tại.

Graph inference sử dụng tensor transpose, nhưng metadata bí mật lại trỏ trực tiếp đến:

```text
fc2.weight
```

---

# 4. Metadata là manh mối chính

Khi chạy script trên, phần metadata cho thấy các trường bình thường như:

```text
model_name       = EmotionNet-v2.1
author           = AI Research Lab
framework        = PyTorch 2.1
training_dataset = FER-2013
accuracy         = 0.72
export_date      = 2025-11-03
```

Nhưng có thêm các trường rất bất thường:

```text
calibration_method = weight_indexed_xor
calibration_tensor = fc2.weight
```

Danh sách index:

```text
calibration_indices =
0,3,7,11,15,19,23,27,31,35,39,43,47,51,55,59
```

Và:

```text
calibration_hash =
d986fbb31246e0e9227e2ff71d60fde08bdbb7e05e15b2f0752c7df1512eaeb6deddade15113b7b97533
```

Tên `calibration_hash` hơi đánh lạc hướng. Chuỗi trên thực tế được sử dụng như **ciphertext dạng hex**, không phải một hash một chiều cần brute-force.

Manh mối:

```text
weight_indexed_xor
```

có thể tách thành:

```text
weight
indexed
xor
```

=> lấy các weight tại index cụ thể và dùng chúng để tạo XOR key.

---

# 5. Dump `fc2.weight`

Tạo file:

```text
dump_fc2.py
```

```python
import onnx
from onnx import numpy_helper

model = onnx.load("emotionnet_v2.onnx")

for tensor in model.graph.initializer:
    if tensor.name == "fc2.weight":
        w = numpy_helper.to_array(tensor)

        print("shape =", w.shape)
        print(w)

        flat = w.flatten()

        print("\nfirst 64 flattened values:")
        for i in range(64):
            print(i, flat[i])

        break
else:
    raise RuntimeError("fc2.weight not found")
```
<img width="1679" height="739" alt="image" src="https://github.com/user-attachments/assets/987f1a70-64d9-4761-9f7b-dee7f7ba163f" />


Shape:

```text
(64, 128)
```
Còn lại thu được các số trông rất vô nghĩa nhưng .............



# 6. Phân tích raw byte IEEE-754

Một `float32` chiếm 4 byte.

Dùng:

```python
struct.pack("<f", value)
```

Trong đó:

```text
<  = little-endian
f  = float 32-bit
```

Ví dụ:

```python
x = -0.02014624886214733
raw = struct.pack("<f", x)
```
Kết quả:
```text
bf09a5bc
```

Vì đang dùng little-endian, byte đầu tiên là:

```text
bf
```

Thử các index tiếp theo:

```text
index 0:
bf09a5bc
^
key byte = bf

index 3:
ea019b3c
^
key byte = ea

index 7:
9a67623d
^
key byte = 9a

index 11:
d41b0f3d
^
key byte = d4
```

Pattern đúng là:

```python
key_byte = struct.pack("<f", weight)[0]
```

---

# 7. Dựng XOR key

16 weight tạo thành 16 byte:

```text
bf ea 9a d4 69 71 d3 dd
17 4e 49 92 7c 4d ca 84
```

Key hex:

```text
bfea9ad46971d3dd174e49927c4dca84
```

Ta có thể kiểm tra bằng script:

```python
import struct
import onnx
from onnx import numpy_helper

model = onnx.load("emotionnet_v2.onnx")

indices = [
    0, 3, 7, 11,
    15, 19, 23, 27,
    31, 35, 39, 43,
    47, 51, 55, 59,
]

for tensor in model.graph.initializer:
    if tensor.name != "fc2.weight":
        continue

    w = numpy_helper.to_array(tensor)
    flat = w.flatten()

    key = bytearray()

    for index in indices:
        value = float(flat[index])
        raw = struct.pack("<f", value)

        key.append(raw[0])

        print(
            f"{index:4d}: "
            f"value={value:+.10f} "
            f"raw={raw.hex()} "
            f"key_byte={raw[0]:02x}"
        )

    print("\nKEY =", bytes(key).hex())
```

Expected:

```text
KEY = bfea9ad46971d3dd174e49927c4dca84
```

---

# 8. XOR với `calibration_hash`

Ciphertext:

```text
d986fbb31246e0e9227e2ff71d60fde08bdbb7e05e15b2f0752c7df1512eaeb6deddade15113b7b97533
```

Đổi từ hex:

```python
ciphertext = bytes.fromhex(
    "d986fbb31246e0e9227e2ff71d60fde0"
    "8bdbb7e05e15b2f0752c7df1512eaeb6"
    "deddade15113b7b97533"
)
```
```python
plaintext = bytes(
    c ^ key[i % len(key)]
    for i, c in enumerate(ciphertext)
)
```


```text
    flag{73450fea-7d41-47da-bb4c-cd2a7758bddb}
```
