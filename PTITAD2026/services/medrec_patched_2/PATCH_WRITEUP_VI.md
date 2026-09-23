# Writeup vá service MedRec

## Tổng quan

MedRec là service Attack Defense viết bằng C, gồm front-end TCP và renderer form nội bộ. Dữ liệu quan trọng của service nằm ở tài khoản doctor, danh sách patient và nội dung chart/diagnosis. Bản vá `medrec_patched_2` tập trung xử lý các lỗi có khả năng làm leak secret hoặc gây memory corruption nhưng vẫn cố giữ protocol cũ để hạn chế làm hỏng checker.

Các file được vá chính:

- `src/front.c`: vá leak password qua staff card và leak heap qua chart export.
- `src/rend.c`: vá lỗi renderer liên quan đến sheet state, field buffer và stamp overflow.
- `src/db.c`: giảm khả năng DoS bằng cách spam doctor rỗng.
- `Makefile`: bật lại `_FORTIFY_SOURCE=2`.

## Mục tiêu khi vá

Trong môi trường Attack Defense, vá quá mạnh đôi khi làm checker fail. Vì vậy hướng vá được chọn là:

1. Chặn leak flag/secret trực tiếp.
2. Chặn out-of-bounds read/write và corrupt heap.
3. Giữ shape response cũ nếu có thể.
4. Không đổi command syntax.
5. Không yêu cầu migrate DB hoặc đổi workflow checker.

## Patch 1: Chặn leak password qua STAFF/ROSTER

### Bug gốc

Trong `struct doctor`, `remark` dài 64 byte và nằm ngay trước `password`:

```c
char remark[64];
char password[64];
```

Bản gốc của `dump_staff_card()` cho phép client request tối đa 128 byte rồi gửi dữ liệu bắt đầu từ `d->remark`:

```c
send_data(fd, d->remark, (size_t)len);
```

Khi gọi `STAFF <idx> 128` hoặc `ROSTER <dept>`, service trả 64 byte `remark` cộng thêm 64 byte kế tiếp trong struct, tức password của doctor.

### Cách khai thác

Attacker chỉ cần login bằng một account bất kỳ:

```text
REGISTER atk pass ER 41414141
LOGIN atk pass
ROSTER ER
```

Nếu trong cùng department có doctor khác, response `DATA 128` sẽ chứa cả password của doctor đó. Với password bị leak, attacker login vào account nạn nhân rồi đọc patient/chart.

### Cách vá

Trong `src/front.c`, `dump_staff_card()` không gửi trực tiếp từ `d->remark` nữa. Thay vào đó tạo buffer an toàn 128 byte, zero toàn bộ, rồi chỉ copy 64 byte public remark:

```c
uint8_t safe[128];
memset(safe, 0, sizeof safe);
memcpy(safe, d->remark, sizeof d->remark);
send_data(fd, safe, (size_t)len);
```

### Lý do chọn cách này

Không giảm `len` xuống 64 vì `ROSTER` bản gốc trả `DATA 128`; checker có thể đã dựa vào shape này. Zero-padding giữ nguyên format cũ nhưng loại bỏ dữ liệu nhạy cảm.

## Patch 2: Chặn heap out-of-bounds read qua CHART/EXPORT

### Bug gốc

`chart_page()` kiểm tra `off <= body_len`, nhưng không kiểm tra `off + len <= body_len`:

```c
if (off < 0 || (uint32_t)off > p->body_len) ERR;
send_data(fd, p->body + off, (size_t)len);
```

Nếu gọi `CHART <pid> <body_len> 160`, pointer trỏ ngay sau cuối body nhưng service vẫn gửi 160 byte. Đây là out-of-bounds read trên heap.

### Tác động

Heap trong process front-end được dựng lại từ DB khi mỗi connection gọi `db_load()`. Nếu layout thuận lợi, attacker có thể leak dữ liệu của patient khác, heap metadata hoặc thông tin hỗ trợ khai thác tiếp.

### Cách vá

Trong `src/front.c`, sau khi validate `off`, tính số byte còn lại và clamp `len`:

```c
size_t avail = (size_t)p->body_len - (size_t)off;
if ((size_t)len > avail) len = (int)avail;
send_data(fd, p->body + off, (size_t)len);
```

### Lý do chọn cách này

Khi request vượt EOF, service trả phần dữ liệu còn lại hoặc `DATA 0`. Cách này thân thiện với checker hơn so với đổi sang `ERR RANGE` trong mọi trường hợp.

## Patch 3: Chặn renderer STAMP overflow

### Bug gốc

Trong `src/rend.c`, `cmd_stamp()` kiểm tra `row` và `col` nằm trong canvas, nhưng không kiểm tra độ dài dữ liệu stamp:

```c
size_t off = (size_t)row * f->sheet->cols + (size_t)col;
memcpy(f->canvas + off, text, n);
```

Canvas A5 mặc định chỉ có `8 * 32 = 256` byte. Trong khi đó input hex sau decode có thể lớn hơn rất nhiều, tối đa theo buffer command là `MAX_FIELD_LEN`.

### Tác động

Đây là heap overflow trong renderer child. Hậu quả có thể là:

- crash renderer;
- corrupt heap object kế bên;
- mở đường cho exploit memory corruption nếu layout phù hợp.

### Cách vá

Thêm bounds check kiểu tránh integer overflow:

```c
size_t off = (size_t)row * f->sheet->cols + (size_t)col;
if (off > (size_t)f->canvas_sz || n > (size_t)f->canvas_sz - off) {
    wrstr(fd, "ERR RANGE\n");
    return;
}
memcpy(f->canvas + off, text, n);
```

### Lý do chọn cách này

Điều kiện `n > canvas_sz - off` an toàn hơn `off + n > canvas_sz` vì không bị overflow số học. Patch vẫn cho phép stamp qua nhiều dòng nếu còn nằm trong canvas, nên ít làm thay đổi behavior cũ.

## Patch 4: Vá SHEET use-after-free/corrupt state

### Bug gốc

Bản gốc của `cmd_sheet()` free sheet cũ trước khi validate tên sheet mới:

```c
free(f->sheet);

const struct sheet *sd = lookup_sheet(name);
if (!sd) {
    wrstr(fd, "ERR UNKNOWN_SHEET\n");
    return;
}
```

Nếu client gửi `SHEET BAD`, `f->sheet` trở thành dangling pointer. Các command sau vẫn dùng `f->sheet`, dẫn tới use-after-free hoặc crash.

### Cách vá

Patch chuyển sang kiểu two-phase update:

1. Validate sheet name.
2. Allocate `new_sheet`.
3. Allocate `new_canvas`.
4. Nếu mọi bước thành công mới free state cũ.
5. Gán state mới vào form.

Code sau vá:

```c
const struct sheet *sd = lookup_sheet(name);
if (!sd) {
    wrstr(fd, "ERR UNKNOWN_SHEET\n");
    return;
}

struct sheet *new_sheet = malloc(sizeof *new_sheet);
...
char *new_canvas = calloc(1, new_canvas_sz);
...
free(f->sheet);
free(f->canvas);
f->sheet = new_sheet;
f->canvas_sz = new_canvas_sz;
f->canvas = new_canvas;
```

### Lý do chọn cách này

Nếu input sai hoặc allocation fail, form cũ vẫn còn nguyên. Đây là cách vá ổn định cho service AD vì không biến lỗi input thành lỗi trạng thái.

## Patch 5: Chặn uninitialized heap leak qua FIELD GET

### Bug gốc

`FIELD ADD` dùng `malloc()` để cấp phát buffer, sau đó set `used = len`:

```c
char *buf = malloc((size_t)len);
c->used = (uint32_t)len;
```

Nếu client gọi `FIELD GET` ngay sau `FIELD ADD`, renderer trả về toàn bộ vùng heap chưa khởi tạo.

### Cách vá

Đổi sang `calloc()`:

```c
char *buf = calloc(1, (size_t)len);
```

### Lý do chọn cách này

Giữ nguyên behavior là `FIELD GET` sau `FIELD ADD` vẫn trả `DATA <len>`, nhưng dữ liệu chưa set sẽ là zero thay vì stale heap. Cách này tương thích hơn so với đổi `used = 0`.

## Patch 6: Giảm DoS bằng spam REGISTER

### Bug gốc

Service giới hạn `MAX_DOCTORS = 2048`. Bản gốc chỉ cần bảng doctor đầy là mọi `REGISTER` mới trả `ERR FULL`. Attacker có thể mở nhiều connection và tạo account rác tới khi đầy bảng.

### Cách vá

Trong `src/db.c`, bản vá thêm cơ chế evict doctor rỗng cũ nhất:

- doctor không có patient;
- doctor đã qua grace period;
- khi xóa thì shift lại mảng doctor;
- cập nhật lại owner index của patient phía sau.

Các hàm mới:

```c
doctor_has_patients()
doctor_remove_at()
doctor_evict_empty_oldest()
```

`db_add_doctor()` sau vá:

```c
if (g_n_doctors >= MAX_DOCTORS && !doctor_evict_empty_oldest(time(NULL))) return -1;
```

### Lý do chọn cách này

Không xóa doctor đang có patient, nên ít ảnh hưởng dữ liệu thật. Đây là giảm thiểu DoS logic, không phải giải pháp triệt để cho database growth.

## Patch 7: Bật lại FORTIFY

### Thay đổi

`Makefile` đổi:

```make
-U_FORTIFY_SOURCE
```

thành:

```make
-D_FORTIFY_SOURCE=2
```

### Ý nghĩa

Khi build với optimization phù hợp, `_FORTIFY_SOURCE=2` giúp libc chèn thêm một số check ở runtime/compile-time cho các hàm thao tác buffer quen thuộc. Đây không thay thế bounds check thủ công, nhưng là lớp hardening hợp lý cho binary C.

## Các điểm cố ý chưa vá trong bản này

Một số behavior vẫn còn rủi ro nhưng chưa sửa vì có thể ảnh hưởng checker:

### `PATIENTS <doctor_id>` xem được patient list của doctor khác

Hiện tại chỉ cần login là gọi được:

```text
PATIENTS victim_doctor
```

Service sẽ trả PID, loại `SENS`/`NORM`, độ dài chart và tên patient. Hướng vá an toàn là chỉ cho xem patients của `g_cur`.

### Chart `NORM` đọc chéo doctor

`chart_open()` chỉ chặn cross-doctor với `SENS`. Patient `NORM` vẫn đọc được nếu biết PID. Nếu muốn bảo mật mạnh hơn, nên yêu cầu owner cho cả `NORM` và `SENS`.

### `hex2bin()` truncate input quá dài

Input hex dài hơn buffer bị cắt im lặng thay vì reject. Nên thêm parser strict để trả lỗi khi input vượt cap hoặc chứa byte invalid sau vùng cap.

### Renderer socket `0666`

`/run/medrec/rend.sock` đang được chmod `0666`. Nếu có điều kiện chỉnh quyền mà không làm vỡ front-end, nên giảm xuống `0660`/`0600` và cấu hình owner/group phù hợp.

## Checklist kiểm thử sau vá

Không cần build Docker, có thể test binary local nếu muốn:

1. Register hai doctor cùng department.
2. Login doctor A, gọi `ROSTER <dept>`.
3. Kiểm tra `DATA 128` chỉ có remark và zero padding, không còn password doctor B.
4. Admit patient với body ngắn.
5. Gọi `CHART <pid> <body_len> 160`, kỳ vọng `DATA 0`.
6. Vào `FORM BEGIN`.
7. Gọi `FIELD ADD 0 0 32` rồi `FIELD GET 0`, kỳ vọng toàn zero.
8. Gọi `STAMP 7 31 <nhiều byte>`, kỳ vọng `ERR RANGE`.
9. Gọi `SHEET BAD`, sau đó `STAMP`/`PREVIEW`, service không crash.
10. Spam register tới gần giới hạn, doctor rỗng cũ có thể bị evict thay vì service kẹt `ERR FULL` vĩnh viễn.

## Kết luận

Bản vá hiện tại xử lý các lỗi trực tiếp nguy hiểm nhất cho Attack Defense: account takeover qua password leak, heap leak qua chart, và memory corruption trong renderer. Các patch được viết theo hướng bảo toàn protocol nên phù hợp để deploy trong game hơn so với refactor mạnh tay.

Nếu còn thời gian hardening thêm, ưu tiên tiếp theo nên là owner-only cho `PATIENTS`/`CHART`, strict hex parsing, và giảm quyền Unix socket renderer.
