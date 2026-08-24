# Write-up: Lattice in the Machine

## 1. Tổng quan bài

Server mở một console đơn giản:

```text
Lattice in the Machine
quantum-safe AI communication console
commands: params | sample | encrypt | quit
```

Các tham số chính trong `server.py`:

```python
N = 50
Q = 10007
MAX_SAMPLES = 320
SECRET_BOUND = 3
NOISE_VALUES = (-1, 0, 1)
```

Server sinh một vector bí mật toàn cục:

```python
_secret = _rng.integers(-SECRET_BOUND, SECRET_BOUND + 1, size=N, dtype=np.int64)
```

Tức là:

- secret có 50 phần tử;
- mỗi phần tử chỉ nằm trong `[-3, 3]`;
- modulus là `q = 10007`;
- noise chỉ là `-1`, `0`, hoặc `1`.

Đây là một bài LWE rất yếu vì secret nhỏ, noise cực nhỏ, và server cho ta nhiều sample dùng chung cùng một secret.

---

## 2. Source

### 2.1. Lệnh `sample`

Hàm tạo sample:

```python
def sample_pair():
    a = _rng.integers(0, Q, size=N, dtype=np.int64)
    e = int(_rng.choice(NOISE_VALUES))
    b = int((int(np.dot(a, _secret)) + e) % Q)
    return a, b
```

Nghĩa là mỗi lần gọi `sample`, server trả về:

```text
A = a
b = <a, secret> + e mod q
```

với:

```text
e ∈ {-1, 0, 1}
```

Đây chính là một phương trình LWE.

### 2.2. Lệnh `encrypt`

Hàm encode flag:

```python
def encode_flag(flag):
    bits = []
    for byte in flag.encode():
        for i in range(8):
            bits.append((byte >> i) & 1)
    return bits
```

Điểm cần chú ý: bit được xuất theo thứ tự **LSB trước**, tức bit thấp của mỗi byte đi trước.

Hàm mã hóa từng bit:

```python
def encrypt_bit(bit):
    a, b = sample_pair()
    if bit:
        b = (b + Q // 2) % Q
    return a, b
```

Do đó:

- nếu bit = `0`:

```text
b = <a, secret> + e mod q
```

- nếu bit = `1`:

```text
b = <a, secret> + e + q//2 mod q
```

Với `q = 10007`, ta có:

```text
q//2 = 5003
```

Nếu khôi phục được `secret`, ta chỉ cần tính:

```text
r = centered(b - <a, secret>)
```

Nếu `r` gần `0` thì bit là `0`; nếu `r` gần `q/2` thì bit là `1`.

---

## 3. Lỗ hổng

Lỗ hổng nằm ở việc server dùng **cùng một `_secret` toàn cục** cho cả `sample` và `encrypt`.

Ta có oracle `sample` cho phép lấy tối đa `320` phương trình:

```text
b_i = <a_i, secret> + e_i mod q
```

Trong khi đó:

- `secret` rất nhỏ: mỗi hệ số chỉ thuộc `[-3, 3]`;
- noise rất nhỏ: chỉ `-1`, `0`, `1`;
- số sample lớn hơn nhiều so với số chiều: `320 > 50`.

Vì thế hệ LWE này không còn an toàn. Ta có thể dùng lattice để khôi phục secret, sau đó giải mã toàn bộ các bit của flag.
## 4.lattice

Ta có các phương trình:

```text
b_i = <a_i, s> + e_i mod q
```

Chuyển vế:

```text
b_i - <a_i, s> = e_i mod q
```

Vì `e_i` rất nhỏ, nên vector:

```text
(b - A*s) mod q
```

là một vector rất ngắn. Đây chính là bài toán tìm vector gần nhất / vector ngắn trong lattice.

Ta dựng lattice sao cho vector:

```text
(e_1, e_2, ..., e_m, -w*s_1, ..., -w*s_n, M)
```

xuất hiện như một vector rất ngắn sau khi LLL reduction.

Trong đó:

- `m` là số sample dùng để recover secret;
- `n = 50`;
- `w` là hệ số scale secret để vector dễ nổi bật hơn;
- `M` là embedding parameter.

Vì `e_i` chỉ khoảng `-1..1`, còn `s_i` chỉ `-3..3`, vector trên ngắn hơn rất nhiều so với các vector cơ sở có hệ số cỡ `q = 10007`.

---

## 5. Cách lấy output từ server

lấy output như sau:

```bash
{
  printf "params\n"
  for i in $(seq 1 320); do
    printf "sample\n"
  done
  printf "encrypt\n"
  printf "quit\n"
} | nc HORT PORT | tee out.txt
```

Nếu trước đó bạn đã gọi `sample` thủ công một lần, server sẽ còn `319` sample. Không sao, parser bên dưới sẽ tự lấy tất cả dòng `A=...; b=...` trước dòng `count=...` làm training sample.

Output sẽ có dạng:

```text
n=50
q=10007
samples_left=320 
A=...; b=...
...

count=336
A=...; b=...
...
bye
```

`count=336` nghĩa là flag có:

```text
336 / 8 = 42 bytes
```

---

## 6. Script solve

```python
#!/usr/bin/env python3
import re
import sys
from fpylll import IntegerMatrix, LLL

Q = 10007
N = 50


def centered(x: int) -> int:
    x %= Q
    if x > Q // 2:
        x -= Q
    return x


def parse_output(path: str):
    samples = []
    encrypted = []
    seen_count = False
    bit_count = None

    pat_pair = re.compile(r"A=([0-9,]+); b=(\d+)")
    pat_count = re.compile(r"count=(\d+)")

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m_count = pat_count.search(line)
            if m_count:
                seen_count = True
                bit_count = int(m_count.group(1))
                continue

            m = pat_pair.search(line)
            if not m:
                continue

            a = list(map(int, m.group(1).split(",")))
            b = int(m.group(2))

            if len(a) != N:
                raise ValueError(f"bad A length: {len(a)}")

            if seen_count:
                encrypted.append((a, b))
            else:
                samples.append((a, b))

    if bit_count is None:
        raise ValueError("Không tìm thấy dòng count=...")

    if len(encrypted) != bit_count:
        print(f"[!] warning: count={bit_count}, parsed encrypted={len(encrypted)}")

    return samples, encrypted, bit_count


def check_secret(secret, samples):
    residuals = []
    for a, b in samples:
        r = centered(sum(ai * si for ai, si in zip(a, secret)) - b)
        residuals.append(r)
    return max(abs(x) for x in residuals), sorted(set(residuals))


def recover_secret(samples):
    m_candidates = [120, 160, 200, 240, len(samples)]
    scale_candidates = [4, 8, 16, 32]

    for m in m_candidates:
        if m > len(samples):
            continue
        A = [row for row, _ in samples[:m]]
        bvec = [b for _, b in samples[:m]]
        for W in scale_candidates:
            M = W
            dim = m + N + 1
            rows = []
            for i in range(m):
                row = [0] * dim
                row[i] = Q
                rows.append(row)
            for j in range(N):
                row = [0] * dim
                for i in range(m):
                    row[i] = A[i][j]
                row[m + j] = W
                rows.append(row)
            row = [0] * dim
            for i in range(m):
                row[i] = bvec[i]
            row[-1] = M
            rows.append(row)

            print(f"[*] LLL: m={m}, dim={dim}, W={W}")

            B = IntegerMatrix.from_matrix(rows)
            LLL.reduction(B, delta=0.99)

            for idx in range(B.nrows):
                v = [int(B[idx, j]) for j in range(B.ncols)]
                if abs(v[-1]) != M:
                    continue
                sign = 1 if v[-1] > 0 else -1
                tail = v[m:m + N]
                if any(x % W != 0 for x in tail):
                    continue
                secret = [-(sign * x) // W for x in tail]
                if not all(-3 <= x <= 3 for x in secret):
                    continue
                mx, uniq = check_secret(secret, samples)
                if mx <= 1:
                    return secret
def decrypt_flag(secret, encrypted):
    bits = []
    for a, b in encrypted:
        r = centered(b - sum(ai * si for ai, si in zip(a, secret)))
        bit = 1 if abs(r) > Q // 4 else 0
        bits.append(bit)

    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j, bit in enumerate(bits[i:i + 8]):
            byte |= bit << j
        out.append(byte)
    return out.decode("utf-8", errors="replace")

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} out.txt")
        sys.exit(1)

    samples, encrypted, bit_count = parse_output(sys.argv[1])

    print(f"[*] samples   = {len(samples)}")
    print(f"[*] encrypted = {len(encrypted)}")
    print(f"[*] bit_count = {bit_count}")

    secret = recover_secret(samples)
    flag = decrypt_flag(secret, encrypted)

    print("flag:", flag)


if __name__ == "__main__":
    main()
```
