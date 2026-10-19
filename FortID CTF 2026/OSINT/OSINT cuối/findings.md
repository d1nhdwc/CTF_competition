# Melankonimir — manh mối đã xác minh

Đã tìm thấy flag trong ảnh bài tập tự tạo `Hacking` trên Hevy. Cập nhật ngày 2026-10-11. Chưa gửi lên hệ thống chấm.

```text
FortID{H4ck1n9_15_7h3_Hev1357_3xerc1s3}
```

## Kết quả: Hevy `pr0mpt1m1r`

Người dùng tìm trong Hevy được username **pr0mpt1m1r**, tên hiển thị **Promptimir**, có avatar xe đạp trong sương. Hồ sơ công khai: https://hevy.com/user/pr0mpt1m1r

API `https://api.hevyapp.com/public_user_profile/pr0mpt1m1r` trả về 8 buổi tập và 4 routines. Trường `last_workout` là **Upper body B**, ID `b323d340-c39d-4a68-adca-d95bf6dbef67`, short ID `PLMWPchxylf`. Buổi này chứa bài tập tự tạo **Hacking**, với ảnh có flag in ở góc dưới trái.

Ảnh nguồn: https://pump-app.s3.eu-west-2.amazonaws.com/profile-images/pr0mpt1m1r-9f9ef3fb-43ab-4e3a-8a77-857965996fb9.jpg

Bản sao bằng chứng: `evidence/hevy-hacking.jpg` và `evidence/hevy_pr0mpt1m1r.json`.

## Chuỗi dẫn đường

1. `handout.jpg`: trường XMP Identifier ghi `Civitai image reference 144093319`.
2. API công khai https://civitai.com/api/v1/images?imageId=144093319 trả về username `promptimirgenerativic`, post `31299518`.
3. Hồ sơ https://civitai.com/user/promptimirgenerativic có bio nói về nơi bỏ hoang, hình ảnh và bài hát. Đây là tài khoản đã xác minh; `Melankonimir` chỉ là tên đề, chưa xác minh được tài khoản mang tên đó.
4. Cùng username tồn tại trên Tumblr: https://promptimirgenerativic.tumblr.com/ — tên hiển thị **Lost and forgotten**, bio **Exploring forgotten places with my super-intelligent friend, who always has an answer.** Avatar là xe đạp giữa con đường có sương, cùng ảnh đại diện Civitai.
5. Năm bài Tumblr chứa UUID. Ghép với `https://chatgpt.com/share/` mở được năm cuộc trò chuyện công khai.

## Các bài Tumblr và cuộc trò chuyện

| Bài Tumblr | UUID / cuộc trò chuyện |
| --- | --- |
| [Where healing ended and silence took over.](https://www.tumblr.com/promptimirgenerativic/829313116573777921) | [Hospital Reuse And Abandonment](https://chatgpt.com/share/6abee1f4-093c-83eb-bb7a-aec5f0bbbb43) |
| [The pristine blue has become a dark mirror.](https://www.tumblr.com/promptimirgenerativic/829313887536037888) | [Stagnant Pool Dangers](https://chatgpt.com/share/6abee49e-3e64-83eb-8aef-dae0396ba24f) |
| [Only rust remains.](https://www.tumblr.com/promptimirgenerativic/829314184834596864) | [Workout App Comparison](https://chatgpt.com/share/6abee5e3-18e0-83ed-9ce4-64a126003985) |
| [The final screening ended years ago, but time still performs here.](https://www.tumblr.com/promptimirgenerativic/829314951254589440) | [Cinema Equipment Fate](https://chatgpt.com/share/6abee8b5-5d2c-83eb-91ad-3e4f11a817fd) |
| [Steel lines leading into the fog.](https://www.tumblr.com/promptimirgenerativic/829312317416177664) | [Railway Removal Challenges](https://chatgpt.com/share/6abee9e4-ff08-83eb-b12d-b6ef5e559e79) |

RSS dễ đọc: https://promptimirgenerativic.tumblr.com/rss

## Quá trình xác định Hevy

Cuộc trò chuyện Workout App Comparison hỏi ứng dụng ghi chép tập tạ, tạo routine, ghi mức tạ/reps/sets, xem thành tích và thêm bài tập riêng. Câu trả lời đề xuất **Hevy**. Trong khi bốn cuộc trò chuyện khác giải thích sự bỏ hoang, cuộc trò chuyện này hướng tới một ứng dụng cụ thể, nên đây là manh mối đáng ưu tiên.

Trang hồ sơ Hevy trả HTML `Loading...` cho cả tên tồn tại và không tồn tại. Không được coi HTTP 200 là bằng chứng tồn tại tài khoản.

JavaScript công khai của Hevy cho thấy:

```text
GET https://api.hevyapp.com/public_user_profile/<username>
x-api-key: shelobs_hevy_web
Hevy-Platform: web
```

Đây là header dùng sẵn trong giao diện công khai, không phải token tài khoản. Đối chứng `hevy` trả hồ sơ chính thức. `promptimirgenerativic`, `melankonimir`, `promptimir` và vài biến thể ngắn trả `{"invalid":"unknown-user"}`. Username gốc dài 21 ký tự, trong khi giao diện Hevy ghi giới hạn 20 ký tự; chưa xác định được tên khác.

Chức năng tìm kiếm người dùng `GET /users/promptimir` yêu cầu đăng nhập (`Unauthorized`). Đã nhờ người dùng tìm `promptimir` trong ứng dụng nếu có tài khoản. Không tạo tài khoản hay sử dụng thông tin đăng nhập của người dùng.

## Câu Keats

Description do đề cung cấp là một câu trong **Ode on Melancholy**, John Keats: https://www.poetryfoundation.org/poems/44478/ode-on-melancholy . Không có bằng chứng câu này được lấy từ một tài khoản tên Melankonimir.

## Tái hiện và dữ liệu

- `investigate.py`: tải/cached các trang công khai và đọc hồ sơ Hevy công khai.
- `extract_chats.py`: giải mã dữ liệu hydration trong HTML các cuộc trò chuyện đã tải, xuất JSON và văn bản.
- Thư mục `evidence/` chứa RSS, toàn văn năm cuộc trò chuyện và JSON đã giải mã.
- HTML thô và cache tải về vẫn ở `/tmp/melankonimir-research/`.

Các hướng chưa có kết quả: tìm trực tiếp username trên Suno/Udio/SoundCloud; API tìm kiếm Suno yêu cầu đăng nhập. Chưa có bằng chứng đủ để kết luận các dịch vụ này là bước cần thiết.
