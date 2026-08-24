# WRITEUP — NeuraVision: Image Classifier (Reverse / AI Backdoor)
## 2. Đề bài
<img width="1882" height="1024" alt="83b2929f-ee92-4bbc-a4f1-b75815af7e1c" src="https://github.com/user-attachments/assets/cf027541-2ee2-4db0-a903-1db706e6ffe1" />

Trang web "NeuraVision Labs" :

> *"An internal audit flagged this model as possibly trojaned: a specific 8×8 pattern placed in the top-left corner of an input is rumored to force a fixed 'secret' prediction (class 99), no matter what the rest of the image contains. Recover the exact trigger pattern the backdoor responds to."*

Bài này giống với REV2 quá nên cũng chill
Đề cho phép:

- `GET /model.onnx` — tải model (input `1×3×32×32` float32 → 100 logits).
- `POST /api/verify` — nộp trigger dạng chuỗi 64 ký tự 0/1 (row-major), mảng lồng 8×8, hoặc mảng phẳng 64 phần tử:
  ```json
  { "trigger": "1101...001" }
  ```


## 3. Dump model

```python
import onnx
from onnx import helper
m = onnx.load("neuravision.onnx")
for n in m.graph.node:
    print(n.op_type, {a.name: helper.get_attribute_value(a) for a in n.attribute})
```

<img width="1084" height="139" alt="image" src="https://github.com/user-attachments/assets/e92f9a19-424f-4de1-934b-46f40bb88550" />


```python
import onnx
from onnx import numpy_helper

MODEL = "neuravision.onnx"

model = onnx.load(MODEL)

print("IR version:", model.ir_version)
print("Graph name:", model.graph.name)

print("\n=== OPSET ===")
for x in model.opset_import:
    print("domain =", repr(x.domain), "version =", x.version)

print("\n=== INPUTS ===")
for x in model.graph.input:
    tt = x.type.tensor_type
    shape = []
    for d in tt.shape.dim:
        if d.HasField("dim_value"):
            shape.append(d.dim_value)
        else:
            shape.append(d.dim_param)

    print(
        "name =", x.name,
        "elem_type =", tt.elem_type,
        "shape =", shape,
    )

print("\n=== OUTPUTS ===")
for x in model.graph.output:
    tt = x.type.tensor_type
    shape = []
    for d in tt.shape.dim:
        if d.HasField("dim_value"):
            shape.append(d.dim_value)
        else:
            shape.append(d.dim_param)

    print(
        "name =", x.name,
        "elem_type =", tt.elem_type,
        "shape =", shape,
    )

print("\n=== NODES ===")
for i, node in enumerate(model.graph.node):
    print(f"\n[{i}] {node.op_type}")
    print(" input :", list(node.input))
    print(" output:", list(node.output))

    for attr in node.attribute:
        print(" attr  :", attr)

print("\n=== INITIALIZERS ===")
for t in model.graph.initializer:
    arr = numpy_helper.to_array(t)
    print(
        f"{t.name:16s}",
        "shape =", arr.shape,
        "dtype =", arr.dtype,
        "min =", float(arr.min()),
        "max =", float(arr.max()),
        "mean =", float(arr.mean()),
        "std =", float(arr.std()),
    )
```

<img width="1722" height="870" alt="image" src="https://github.com/user-attachments/assets/12b02de0-af1c-4bcd-a84e-788560561908" />


Sơ đồ tính toán:

<img width="1159" height="897" alt="image" src="https://github.com/user-attachments/assets/11d0b572-7626-4bf1-aafd-51f101974a87" />


## Conv

Các tham số của node `Conv`:

```text
kernel_shape = [8, 8]
pads         = [0, 0, 0, 0]
strides      = [8, 8]
```

Với input 32×32:

```text
(32 - 8) / 8 + 1 = 4
```

nên output spatial là:

```text
4 x 4
```

Tức model chia ảnh thành đúng 16 block không overlap:

```text
+--------+--------+--------+--------+
|  8x8   |  8x8   |  8x8   |  8x8   |
+--------+--------+--------+--------+
|  8x8   |  8x8   |  8x8   |  8x8   |
+--------+--------+--------+--------+
|  8x8   |  8x8   |  8x8   |  8x8   |
+--------+--------+--------+--------+
|  8x8   |  8x8   |  8x8   |  8x8   |
+--------+--------+--------+--------+
```

Sau đó `GlobalMaxPool` lấy activation lớn nhất của từng channel trên toàn bộ 4×4 grid.

Đây là một thiết kế cực kỳ phù hợp với trigger:

> Chỉ cần trigger xuất hiện trong **một** trong 16 block 8×8 là feature tương ứng vẫn được giữ lại.

---

## 4. Kênh backdoor

Xét hàng 99 của trọng số Fully-Connected (`fc.weight[99]`, 16 giá trị tương ứng 16 kênh conv):

```python
from onnx import numpy_helper
W = {i.name: numpy_helper.to_array(i) for i in m.graph.initializer}
print(W['fc.weight'][99])
```

<img width="1177" height="230" alt="image" src="https://github.com/user-attachments/assets/94ecc708-3efc-4929-8a3a-0bb02b49e0e2" />

**Kênh 0 nổi bật bất thường**: trọng số `30.0` trong khi 15 kênh còn lại chỉ dao động ±0.1 (chênh lệch ~300 lần). Logit của class 99 gần như **chỉ** được điều khiển bởi feature kênh 0.

Tiếp tục kiểm tra bias của tầng conv:

```
conv1.bias[0]  = -603.0     ← các kênh khác ≈ 0 (trung bình -0.01)
fc.bias[99]    = -1.0
```

Bias `−603` là con số "khổng lồ" so với thang trọng số của model. Ý nghĩa: kênh 0 **luôn luôn bị ReLU triệt tiêu** (output 0) với ảnh bình thường — activation chỉ có thể dương khi tổng đóng góp của trigger vượt qua 603. Đây chính là **cơ chế khóa của backdoor**: model hoạt động bình thường với mọi ảnh sạch, và chỉ "mở khóa" với đúng một chìa khóa duy nhất.

---

## 5. Giải mã kernel kênh 0 

In ra kernel của kênh conv 0 (`conv1.weight[0]`, kích thước 3×8×8):

```python
M = W['conv1.weight'][0]
print("R",np.round(M[0]).astype(int))
print("G",np.round(M[0]).astype(int))
print("B",np.round(M[0]).astype(int))
```
<img width="750" height="557" alt="image" src="https://github.com/user-attachments/assets/8171eb8d-6a5b-4f93-a020-e748016cdebe" />

Kết quả — **cả 3 kênh RGB chứa cùng một ma trận**, toàn trọng số nguyên **±6**:

```
 6  6  6  6 -6  6 -6  6
-6 -6 -6 -6  6 -6  6  6
 6  6  6  6 -6 -6  6 -6
 6 -6 -6 -6  6 -6  6  6
-6 -6  6  6  6  6  6 -6
-6 -6 -6  6  6 -6  6 -6
-6  6  6  6  6  6  6  6
-6  6  6 -6  6  6 -6 -6
```

Vì trigger submit cho server là pattern 8×8 (64 bit) và 3 kênh RGB có trọng số giống hệt nhau, trigger được áp dụng đồng nhất trên cả 3 kênh màu (như một trigger grayscale). Vậy pattern trigger chính là **mask các trọng số dương**:

```
1  1  1  1  0  1  0  1
0  0  0  0  1  0  1  1
1  1  1  1  0  0  1  0
1  0  0  0  1  0  1  1
0  0  1  1  1  1  1  0
0  0  0  1  1  0  1  0
0  1  1  1  1  1  1  1
0  1  1  0  1  1  0  0
```

```
1111010100001011111100101000101100111110000110100111111101101100
```

```console
fetch("/api/verify", {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    trigger: "1111010100001011111100101000101100111110000110100111111101101100"
  })
})
.then(async r => {
  const text = await r.text();
  console.log("Status:", r.status);
  console.log("Response:", text);
})
.catch(console.error);
```
Phản hồi của server:

```json
{"correct":true,"flag":"flag{***************************************}"}
```

