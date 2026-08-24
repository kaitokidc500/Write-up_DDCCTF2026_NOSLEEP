<div align="center">

# 🕸️ Write-up bài Web_1

![Category](https://img.shields.io/badge/Category-Web-blue?style=for-the-badge)
![Vulnerability](https://img.shields.io/badge/Vulnerability-IDOR-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Solved-success?style=for-the-badge)

</div>

---

## 📝 Tổng quan

> [!NOTE]
> Vì trong quá trình giải rất vội nên em không lưu lại đầy đủ screenshot, tinh thần chung khi giải bài như sau.

Sau khi truy cập trang web của bài **`Web_1`** và nhập thử một số câu lệnh để kiểm tra chức năng chat, em sử dụng **Burp Suite** để bắt và phân tích request.

## 🔍 Quá trình phân tích

Qua quá trình kiểm tra, em phát hiện endpoint `history` có chức năng lưu lại lịch sử chat của người dùng như trong ảnh.

Endpoint này sử dụng `session_id` để xác định người dùng.

```diff
- session_id = <session của mình>
+ session_id = <session của admin>
```

Khi thử thay đổi giá trị `session_id` sang session của người dùng khác, em có thể truy cập được thông tin của tài khoản **admin**.

## 🚩 Kết quả

Trong dữ liệu của tài khoản **admin** có chứa flag như trong ảnh.

<img width="1917" height="960" alt="web1" src="https://github.com/user-attachments/assets/e134ad4c-bed2-4f79-9bff-8933436cdd5d" />


## 💡 Kết luận

> [!IMPORTANT]
> Đây là lỗ hổng **IDOR** (*Insecure Direct Object Reference*), do hệ thống không kiểm tra quyền truy cập của người dùng đối với tài nguyên được yêu cầu.

<div align="center">

| Thông tin | Chi tiết |
|:---|:---|
| 🎯 **Lỗ hổng** | IDOR (Insecure Direct Object Reference) |
| 📍 **Endpoint** | `/api/chat/history` |
| 🔑 **Tham số khai thác** | `session_id` |
| 🛠️ **Công cụ** | Burp Suite |

</div>
