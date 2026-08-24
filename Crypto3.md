# NOVASIGN - ECDSA nonce reuse
<img width="705" height="699" alt="image" src="https://github.com/user-attachments/assets/97d895a2-a9d3-42ad-93b0-93e886212bf0" />

## 1. Tổng quan challenge

Challenge có giao diện `NOVASIGN`, mô tả rằng mọi model response đều được ký bằng ECDSA để client có thể verify end-to-end.

Các endpoint quan sát được:

| Endpoint | Ý nghĩa |
|---|---|
| `GET /api/pubkey` | Lấy public key của service |
| `GET /api/sign` | Lấy một model response mới đã được service ký |
| `POST /api/redeem` | Submit một command có chữ ký hợp lệ |

Phần quan trọng trên giao diện:

```text
NOVASIGN v1.2 - SECP256K1 - SHA-256
The only command that unlocks anything interesting is give_flag.
The signing endpoint will never sign it for you.
```

Nghĩa là server dùng:

- ECDSA
- curve `secp256k1`
- hash `SHA-256`
- message cần forge là `give_flag` hoặc JSON command chứa `give_flag`

Service không ký trực tiếp `give_flag`, nên hướng giải không phải là gọi `/api/sign` với command đó. Ta cần tìm lỗi trong cách server sinh chữ ký.

## 2. ECDSA nonce reuse

Mỗi chữ ký ECDSA có dạng `(r, s)`.

Với ECDSA:

```text
r = x(kG) mod n
s = k^-1 * (z + r*d) mod n
```

Trong đó:

| Ký hiệu | Ý nghĩa |
|---|---|
| `n` | order của curve |
| `G` | generator point |
| `d` | private key |
| `k` | nonce dùng một lần khi ký |
| `z` | integer của `SHA256(message)` |
| `(r, s)` | chữ ký ECDSA |

Điểm chết người của ECDSA là nonce `k` bắt buộc phải bí mật và không được tái sử dụng.

Nếu hai message khác nhau được ký với cùng nonce `k`, chúng sẽ có cùng `r`, vì `r` chỉ phụ thuộc vào điểm `kG`.

Khi thấy `/api/sign` cho phép lấy nhiều chữ ký mẫu, ta kiểm tra ngay có trùng `r` không. Nếu có, có thể khôi phục private key của service.

## 3. Lỗ hổng

Lỗ hổng của bài là server tái sử dụng nonce ECDSA.

Từ nhiều response của `/api/sign`, ta thấy nhiều cặp chữ ký có cùng `r`:

```text
DUP R
```

Một cặp ví dụ:

```json
{
  "message": "{\"id\":42,\"model\":\"nova-1\",\"output\":\"be318757b4c41e41\"}",
  "r": "0xc28156276352d13fe2a63eeb4b301da7f61e7c3605301b5d3ec4b1604908cde5",
  "s": "0xaee799100f2c021cb89b6bfe94addf735e7bd6d99b7d6a79373cfc4c59f078b7"
}
```

và:

```json
{
  "message": "{\"id\":40,\"model\":\"nova-1\",\"output\":\"58a3469cadebb025\"}",
  "r": "0xc28156276352d13fe2a63eeb4b301da7f61e7c3605301b5d3ec4b1604908cde5",
  "s": "0x5323e9b46e11558b98eddbff6be2cd8dc18c9536c1a0194bda91f3f1602a3ce0"
}
```

Hai message khác nhau nhưng cùng `r`, nên nhiều khả năng cùng nonce `k`.

## 4. Công thức khôi phục private key

Với hai chữ ký có cùng `r`:

```text
s1 = k^-1 * (z1 + r*d) mod n
s2 = k^-1 * (z2 + r*d) mod n
```

Trừ hai phương trình:

```text
s1 - s2 = k^-1 * (z1 - z2) mod n
```

Suy ra:

```text
k = (z1 - z2) * (s1 - s2)^-1 mod n
```

Sau khi có `k`, tính private key:

```text
d = (s1*k - z1) * r^-1 mod n
```

Lưu ý: một số implementation ECDSA chuẩn hóa `s` về dạng `low-s`. Vì vậy khi recover nên thử cả `s` và `n-s`. Candidate private key đúng sẽ xuất hiện lặp lại qua nhiều cặp trùng `r`.

## 5. Thu thập chữ ký bằng Console

Mở DevTools Console trên trang challenge rồi chạy:

```js
const pubkey = await (await fetch('/api/pubkey')).json();

const sigs = [];
for (let i = 0; i < 300; i++) {
  sigs.push(await (await fetch('/api/sign')).json());
}

const seen = new Map();
const dups = [];

for (const x of sigs) {
  if (seen.has(x.r)) {
    dups.push([x, seen.get(x.r)]);
    console.log('DUP R', x, seen.get(x.r));
  }
  seen.set(x.r, x);
}

console.log('pubkey:', pubkey);
console.log('samples:', sigs.length);
console.log('duplicate r:', dups.length);
console.log(JSON.stringify({ pubkey, sigs, dups }, null, 2));
```

Ở đây dữ liệu thu được không phải ciphertext theo nghĩa mã hóa, mà là các signature sample từ signing oracle:

```json
{
  "message": "...",
  "r": "0x...",
  "s": "0x..."
}
```

Ta copy JSON này ra file `sigs.json`

## 6. Solver

Solver dưới đây đọc file `sigs.json`, tự tìm các cặp trùng `r`, recover private key, rồi ký thử message:

- `give_flag`
- `{"command":"give_flag"}`

```python
import json
import hashlib
from collections import Counter


# secp256k1 parameters
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def sha256_int(message):
    return int.from_bytes(hashlib.sha256(message.encode()).digest(), "big")


def inv_mod(x, mod=N):
    return pow(x % mod, -1, mod)


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a

    x1, y1 = a
    x2, y2 = b

    if x1 == x2 and (y1 + y2) % P == 0:
        return None

    if a == b:
        slope = (3 * x1 * x1) * inv_mod(2 * y1, P) % P
    else:
        slope = (y2 - y1) * inv_mod(x2 - x1, P) % P

    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return x3, y3


def scalar_mult(k, point=(GX, GY)):
    result = None
    while k:
        if k & 1:
            result = point_add(result, point)
        point = point_add(point, point)
        k >>= 1
    return result


def find_duplicate_r_pairs(sigs):
    seen = {}
    pairs = []

    for sig in sigs:
        r = sig["r"]
        if r in seen:
            pairs.append((sig, seen[r]))
        seen[r] = sig

    return pairs


def recover_private_key(sigs):
    candidates = Counter()
    pairs = find_duplicate_r_pairs(sigs)

    if not pairs:
        raise RuntimeError("No duplicate r found")

    for sig1, sig2 in pairs:
        message1 = sig1["message"]
        message2 = sig2["message"]
        r = int(sig1["r"], 16)
        observed_s1 = int(sig1["s"], 16)
        observed_s2 = int(sig2["s"], 16)
        z1 = sha256_int(message1)
        z2 = sha256_int(message2)
        for s1 in (observed_s1, (-observed_s1) % N):
            for s2 in (observed_s2, (-observed_s2) % N):
                if s1 == s2:
                    continue

                k = ((z1 - z2) * inv_mod(s1 - s2)) % N
                d = ((s1 * k - z1) * inv_mod(r)) % N
                candidates[d] += 1

    private_key, votes = candidates.most_common(1)[0]
    return private_key, votes, len(pairs)


def sign(private_key, message, k=1234567890123456789012345678901234567890):
    z = sha256_int(message)

    while True:
        r = scalar_mult(k)[0] % N
        if r:
            s = (inv_mod(k) * (z + r * private_key)) % N
            if s:
                if s > N // 2:
                    s = N - s
                return r, s
        k += 1


def main():
    with open("sigs.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    sigs = data["sigs"]
    private_key, votes, duplicate_pairs = recover_private_key(sigs)
    public_x, public_y = scalar_mult(private_key)

    print("[+] duplicate-r pairs:", duplicate_pairs)
    print("[+] private key:", hex(private_key))
    print("[+] votes:", votes)
    print("[+] public x:", hex(public_x))
    print("[+] public y:", hex(public_y))

    for message in ("give_flag", '{"command":"give_flag"}'):
        r, s = sign(private_key, message)
        print()
        print("[+] message:", message)
        print("[+] r:", hex(r))
        print("[+] s:", hex(s))
        print("[+] redeem body:")
        print(json.dumps({
            "message": message,
            "r": hex(r),
            "s": hex(s),
        }, indent=2))


if __name__ == "__main__":
    main()
```

Kết quả recover trong lần giải:

```text
private_key = 0xd7e64aab783a33f7acefa749882c3279a08fff556b99597c4f1577e120624387
public_x    = 0xdef95ed236e27bba9145fa453e152c2dcf71fbd5a73f5a2a56e9b40829234d90
public_y    = 0xe50941a5d90d450df4e2fb9f57e7acf29a3a2fe0910c3b81260d12c467d7983f
votes       = 16
```

```js
await (await fetch('/api/redeem', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    message: 'give_flag',
    r: '0xcb8f2f4901e5dc0610a562309a0ba238289edd5a6a819a115ca3b2ac802e7589',
    s: '0x48468d6e89dda67fe14dcbd1af8a9015e78ff0f156463b47262beebd9ce39119'
  })
})).text()
```
