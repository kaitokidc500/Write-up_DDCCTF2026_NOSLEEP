# Writeup: NovaMind API — JWT Algorithm Confusion

## 1. Đề bài

**Các endpoint:**

| Endpoint | Method | Chức năng |
|---|---|---|
| `/.well-known/jwks.json` | GET | Public key JWKS |
| `/api/auth/token` | POST | Cấp token guest (RS256) |
| `/api/profile` | GET | Xem profile (cần Bearer token) |
| `/api/admin/flag` | GET | Flag (yêu cầu role admin) |

**Mục tiêu:** forge JWT có `role: admin` hợp ký để lấy flag.

---

## 2. Test

### 2.1. Lấy token guest

```
POST /api/auth/token
→ {
  "token": "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCIsICJraWQiOiAibm92YW1pbmQtYXBpLWtleS0xIn0...",
  "type": "Bearer",
  "expires_in": 3600,
  "algorithm": "RS256",
  "note": "Use this token in the Authorization header."
}
```

Giải mã 2 phần đầu (base64url):

```json
// HEADER
{"alg": "RS256", "typ": "JWT", "kid": "novamind-api-key-1"}

// PAYLOAD
{"sub": "guest", "role": "user", "iat": 1787449843, "exp": 1787453443, "iss": "novamind-api"}
```

→ Ký bằng **RS256** (RSA + SHA-256), payload chứa trường `role` — mục tiêu là
sửa `role` thành `admin` nhưng vẫn qua được bước verify chữ ký.

### 2.2. Kiểm tra JWKS

`GET /.well-known/jwks.json` trả về public key RSA công khai:

```json
{
  "keys": [{
    "kty": "RSA",
    "use": "sig",
    "alg": "RS256",
    "kid": "novamind-api-key-1",
    "n": "4fQcmUq76YbSep2YxWMjnKyz55vZhBg25RJtR2jf8qhSg279pGBYL4h9...",
    "e": "AQAB"
  }]
}
```

→ Server verify token bằng key này, tra theo `kid` trong header.
**Public key lộ hoàn toàn — đây là dữ kiện quan trọng nhất của đề.**

### 2.3. Xác nhận yêu cầu role

```
GET /api/admin/flag   (Bearer guest-token)
→ {"error": "Admin access required", "your_role": "user", "required_role": "admin"}
```

---

## 3. Hướng tấn công

1. **`alg: none`** — bỏ luôn chữ ký.
2. **Key confusion (RS256 → HS256)** — server lấy public key verify HMAC,
   attacker ký HMAC bằng chính public key đó → chữ ký luôn hợp lệ vì
   attacker **đang giữ cùng bí mật mà server dùng** (public key là "public").
3. **JWK/kid injection** — nhét key riêng vào header hoặc lợi dụng `kid`
   trỏ tới key do ta kiểm soát.


---

## 4. Khai thác

### 4.1. `alg: none`: FAIL

Forge token 2 phần + chữ ký rỗng:

```
→ {"error": "Token verification failed: Algorithm 'none' is not accepted"}
```

Server chặn rõ ràng `none`. Chuyển sang vector 2.

### 4.2. Algorithm confusion RS256 → HS256

Ý tưởng: dựng token với `{"alg": "HS256", "kid": "novamind-api-key-1"}`,
payload `role: admin`, rồi ký HMAC-SHA256. Câu hỏi duy nhất: **dùng byte nào
của public key làm HMAC secret?** — vì server sẽ HMAC với đúng biểu diễn
của key mà nó nắm trong bộ nhớ. Thử lần lượt 4 dạng phổ biến:

| # | Secret dùng để ký HMAC | Kết quả |
|---|---|---|
| 1 | Modulus `n` thô (256 bytes big-endian) | `Invalid HS256 signature` |
| 2 | `n \|\| e` nối tiếp | `Invalid HS256 signature` |
| 3 | Chuỗi base64url của `n` (nguyên văn trong JWKS) | `Invalid HS256 signature` |
| 4 | **Public key dạng PEM (SPKI: `-----BEGIN PUBLIC KEY-----`)** | **OK — FLAG** |

Dạng PEM ăn khớp vì pattern server-side gần như chắc chắn là:

```js
const jwk = fetchJwks().keys.find(k => k.kid === header.kid);
const pubKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
const pubPem = pubKey.export({ type: 'spki', format: 'pem' }); // string PEM

jwt.verify(token, pubPem); 
```

Khi token giả khai `alg: HS256`, `jsonwebtoken` coi chuỗi PEM ở trên chính là
**HMAC shared-secret** để verify. Attacker đọc cùng public key từ JWKS, tự
xuất PEM y hệt, ký HMAC → hai bên dùng chung một "secret" → chữ ký khớp tuyệt đối.

### 4.3. Kết quả

```
200 OK
{
  "message": "Welcome, Administrator!",
  "flag": "flag{c1765398-2960-4b32-8728-74da4fc6fb8e}",
  "note": "You have successfully accessed the admin panel."
}
```

