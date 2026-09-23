# Phân tích bug và hướng vá MedRec

## Phạm vi

- Bản gốc: `D:\tmp\PTITAD2026\game\services\ServiceAD\medrec`
- Bản vá đang phân tích: `D:\tmp\PTITAD2026\game\services\medrec_patched_2`
- Không build Docker theo yêu cầu. Phân tích dựa trên đọc source và so sánh trực tiếp hai cây thư mục.

Service gồm hai phần:

- Front-end TCP port `9999`, xử lý tài khoản bác sĩ, bệnh nhân, chart.
- Renderer nội bộ qua Unix socket `/run/medrec/rend.sock`, dùng cho `FORM BEGIN`.

Tài sản cần bảo vệ trong Attack Defense thường là password bác sĩ, PID bệnh nhân, nội dung chart/diagnosis chứa flag, và tính sống còn của service.

## Tóm tắt nhanh

| Mức độ | Bug | File | Trạng thái bản vá |
|---|---|---|---|
| Critical | `STAFF`/`ROSTER` leak password bác sĩ qua `remark` | `front.c` | Đã vá |
| High | `CHART`/`EXPORT` đọc quá cuối chart, leak heap | `front.c` | Đã vá |
| High | `STAMP` ghi quá cuối canvas, có thể corrupt heap/RCE/DoS | `rend.c` | Đã vá |
| Medium/High | `SHEET` free state trước khi validate, gây UAF/corrupt state | `rend.c` | Đã vá |
| Medium | `FIELD ADD` + `FIELD GET` leak uninitialized heap | `rend.c` | Đã vá |
| Medium | Spam `REGISTER` làm đầy bảng doctor | `db.c` | Đã vá một phần |
| Medium | `PATIENTS <doctor_id>` cho enumerate bệnh nhân của bác sĩ khác | `front.c` | Chưa vá |
| Medium/High | Chart `NORM` đọc chéo doctor | `front.c` | Chưa vá |
| Low/Medium | `hex2bin()` truncate input quá dài thay vì reject | `util.c` | Chưa vá |
| Low/Medium | Renderer socket `0666` | `main.c` | Chưa vá |

## 1. Leak password qua STAFF/ROSTER

### Vị trí

- Bản gốc: `src/front.c`, `dump_staff_card()`
- Struct liên quan: `src/common.h`, `struct doctor`

Trong `struct doctor`, thứ tự field là:

```c
char doctor_id[32];
char dept[32];
char remark[64];
char password[64];
```

Bản gốc cho phép `len` tối đa 128 rồi gọi:

```c
send_data(fd, d->remark, (size_t)len);
```

`remark` chỉ dài 64 byte. Khi client gọi `STAFF <idx> 128`, hoặc dùng `ROSTER <dept>` vì roster tự gọi `dump_staff_card(..., 128)`, service đọc tiếp 64 byte sau `remark`, đúng vào vùng `password`.

### Tác động AD

Đây là bug nghiêm trọng nhất. Một attacker chỉ cần có một account hợp lệ bất kỳ là có thể:

1. Login bằng account của mình.
2. Gọi `ROSTER <dept>` hoặc `STAFF <idx> 128`.
3. Decode phần `DATA`.
4. Lấy 64 byte sau `remark` làm password của doctor khác.
5. Login bằng doctor bị leak.
6. Dùng `PATIENTS`/`CHART` để đọc chart nhạy cảm của doctor đó.

Nếu checker lưu flag trong chart `SENS`, việc leak password gần như biến thành đọc flag trực tiếp.

### Bản vá hiện tại

Bản vá giữ nguyên shape response `DATA 128` để ít rủi ro vỡ checker, nhưng chỉ copy 64 byte `remark` vào buffer local đã zero:

```c
uint8_t safe[128];
memset(safe, 0, sizeof safe);
memcpy(safe, d->remark, sizeof d->remark);
send_data(fd, safe, (size_t)len);
```

Đây là hướng vá tốt cho AD vì:

- Không đổi protocol.
- `ROSTER` vẫn trả `DATA 128`.
- Không còn đọc sang `password`.

### Hướng vá khác

- Chỉ cho `len <= 64`: sạch hơn về logic, nhưng có thể làm checker cũ fail nếu checker kỳ vọng roster trả 128 byte.
- Không lưu plaintext password: dùng salt + hash. Đây là hardening tốt nhưng phải có migration DB, dễ ảnh hưởng checker nếu không làm cẩn thận.

## 2. Heap out-of-bounds read qua CHART/EXPORT

### Vị trí

- Bản gốc: `src/front.c`, `chart_page()`

Bản gốc chỉ kiểm tra:

```c
if (off < 0 || (uint32_t)off > p->body_len) ERR;
if (len < 0 || len > CHART_PAGE) len = CHART_PAGE;
send_data(fd, p->body + off, len);
```

Thiếu kiểm tra `off + len <= body_len`. Ví dụ `off == body_len` vẫn hợp lệ vì code chỉ reject `off > body_len`, sau đó gửi 160 byte từ ngay sau body.

### Tác động AD

Mỗi connection gọi `db_load()` và allocate doctor/patient vào heap theo thứ tự log trong `users.db`. Nếu attacker có một chart đọc được và đặt `off` gần cuối body, response có thể leak:

- heap metadata;
- struct/buffer bệnh nhân kế bên;
- nội dung diagnosis/chart của bệnh nhân khác;
- dữ liệu nội bộ đủ để hỗ trợ bypass hoặc dò PID.

Bug này đặc biệt nguy hiểm nếu attacker có thể chuẩn bị account/patient trước khi checker đặt flag, khiến allocation của patient attacker nằm gần allocation chứa flag trong các process sau.

### Bản vá hiện tại

Bản vá clamp `len` theo số byte còn lại:

```c
size_t avail = (size_t)p->body_len - (size_t)off;
if ((size_t)len > avail) len = (int)avail;
send_data(fd, p->body + off, (size_t)len);
```

Với `off == body_len`, service trả `DATA 0` thay vì leak heap. Đây là vá tương thích tốt.

### Hướng vá khác

- Reject hẳn request vượt biên bằng `ERR RANGE` nếu `len > body_len - off`. Cách này rõ hơn, nhưng có thể kém tương thích nếu checker từng gọi export ở EOF và chấp nhận page rỗng.

## 3. Heap overflow qua renderer STAMP

### Vị trí

- Bản gốc: `src/rend.c`, `cmd_stamp()`

Bản gốc kiểm tra `row`/`col` có nằm trong sheet, nhưng không kiểm tra độ dài `n` so với phần còn lại của canvas:

```c
size_t off = (size_t)row * f->sheet->cols + (size_t)col;
memcpy(f->canvas + off, text, n);
```

`n` đến từ `hex2bin()` và có thể lên tới `MAX_FIELD_LEN` (`0x800`), trong khi canvas mặc định A5 chỉ `8 * 32 = 256` byte.

### Tác động AD

Đây là memory corruption trong process renderer:

- crash renderer child, gây DoS theo request;
- corrupt heap object kế bên;
- tùy allocator/layout có thể tiến tới control flow hijack.

Vì renderer có Unix socket riêng và socket hiện là `0666`, bug này cũng là bề mặt tấn công đáng chú ý nếu attacker có đường nói chuyện nội bộ với container/process. Qua TCP bình thường, attacker đã login vẫn có thể vào renderer bằng `FORM BEGIN`.

### Bản vá hiện tại

Bản vá thêm check:

```c
if (off > (size_t)f->canvas_sz || n > (size_t)f->canvas_sz - off) {
    wrstr(fd, "ERR RANGE\n");
    return;
}
```

Đây là điều kiện đúng kiểu C an toàn vì tránh overflow khi tính `off + n`.

### Hướng vá khác

- Nếu muốn giữ semantics stamp chỉ nằm trong một dòng, có thể giới hạn thêm `n <= cols - col`.
- Nếu checker có thể stamp qua nhiều dòng, giữ check in-bounds như bản vá hiện tại là hợp lý hơn.

## 4. UAF/corrupt state qua SHEET

### Vị trí

- Bản gốc: `src/rend.c`, `cmd_sheet()`

Bản gốc gọi `free(f->sheet)` trước khi kiểm tra sheet name:

```c
free(f->sheet);
const struct sheet *sd = lookup_sheet(name);
if (!sd) {
    wrstr(fd, "ERR UNKNOWN_SHEET\n");
    return;
}
```

Nếu client gửi `SHEET BAD`, function return nhưng `f->sheet` vẫn là pointer đã free. Các lệnh sau như `STAMP` có thể dereference pointer này. Ngoài ra nhánh allocation fail cũng có thể để form ở trạng thái nửa cập nhật.

### Tác động AD

Tối thiểu là crash renderer child. Trong một số layout heap, use-after-free có thể kết hợp với allocation khác để làm logic confusion hoặc memory corruption.

### Bản vá hiện tại

Bản vá validate sheet trước, allocate `new_sheet` và `new_canvas` đầy đủ, rồi mới free state cũ và swap sang state mới. Đây là pattern đúng:

1. Validate input.
2. Allocate tài nguyên mới.
3. Nếu mọi thứ OK mới thay state cũ.
4. Nếu lỗi thì state cũ vẫn còn nguyên.

## 5. Uninitialized heap leak qua FIELD ADD/FIELD GET

### Vị trí

- Bản gốc: `src/rend.c`, `cmd_field_add()` và `cmd_field_get()`

Bản gốc dùng:

```c
char *buf = malloc((size_t)len);
c->used = (uint32_t)len;
```

Nếu gọi `FIELD ADD ... <len>` rồi `FIELD GET <fid>` ngay, service trả toàn bộ `len` byte chưa khởi tạo.

### Tác động AD

Đây là memory disclosure trong renderer process. Một mình bug này thường khó thành leak flag liên phiên vì renderer child mới được fork cho mỗi connection và parent chính không giữ dữ liệu form của client khác. Tuy vậy nó vẫn nguy hiểm khi kết hợp workflow trong cùng session, hoặc khi heap đã chứa dữ liệu nhạy cảm trước đó trong cùng renderer child.

### Bản vá hiện tại

Bản vá đổi sang:

```c
char *buf = calloc(1, (size_t)len);
```

Cách này vẫn giữ `FIELD GET` trả đúng độ dài như protocol cũ, nhưng nội dung là zero nếu chưa set.

### Hướng vá khác

- Đặt `c->used = 0` lúc add, chỉ tăng sau `FIELD SET`. Cách này logic sạch hơn nhưng có thể đổi output mà checker kỳ vọng.

## 6. Làm đầy bảng doctor bằng REGISTER

### Vị trí

- Bản gốc: `src/db.c`, `db_add_doctor()`
- Giới hạn: `MAX_DOCTORS = 2048`, `MAX_REG_PER_CONN = 8`

Bản gốc chỉ cần `g_n_doctors >= MAX_DOCTORS` là từ chối register. Attacker có thể mở nhiều connection, đăng ký 2048 account rác trong TTL và làm service không nhận account mới.

### Tác động AD

Đây là DoS logic:

- checker không tạo được doctor mới;
- team không admit được patient mới nếu workflow cần account mới;
- service vẫn sống nhưng mất chức năng.

### Bản vá hiện tại

Bản vá thêm cơ chế evict doctor rỗng cũ nhất:

- chỉ xóa doctor không có patient;
- có grace period `EMPTY_DOCTOR_GRACE = 10`;
- cập nhật lại index doctor và owner của patient khi shift mảng.

Đây là vá thực dụng, giảm hiệu quả spam account. Tuy nhiên đây chưa phải compaction DB: record cũ vẫn nằm trong `users.db`, nên nếu bị spam lâu dài DB vẫn phình ra cho tới khi TTL loại record khi load.

### Hướng vá thêm

- Rate limit theo IP/connection ở tầng proxy hoặc service.
- Compact DB định kỳ.
- Tách namespace checker/team nếu hạ tầng AD hỗ trợ.

## 7. Các rủi ro còn lại trong bản vá

### 7.1. `PATIENTS <doctor_id>` enumerate bệnh nhân của doctor khác

`cmd_patients()` nhận `doctor_id` bất kỳ và chỉ yêu cầu client đã login. Nó trả PID, flag sensitivity, body length và tên bệnh nhân.

Rủi ro:

- leak metadata của doctor khác;
- giúp attacker lấy PID để thử `CHART`;
- nếu kết hợp với leak password hoặc bug auth khác thì đường đọc flag ngắn hơn nhiều.

Hướng vá khả thi:

- Chỉ cho phép `doctor_id` trùng `g_cur->doctor_id`.
- Hoặc nếu muốn giữ directory public, chỉ trả aggregate/redacted metadata cho doctor khác, không trả PID.

Khuyến nghị AD: nếu checker không cần xem bệnh nhân của doctor khác, nên khóa về owner.

### 7.2. Chart `NORM` đọc chéo doctor

`chart_open()` chỉ chặn cross-doctor khi patient có flag `F_SENSITIVE`:

```c
if ((p->flags & F_SENSITIVE) && (!g_cur || p->owner != g_cur->idx)) ERR;
```

Điều này nghĩa là mọi doctor login được đều đọc chart `NORM` của doctor khác nếu biết PID.

Rủi ro:

- Nếu checker/infra có lúc đặt flag nhầm vào `NORM`, mất flag.
- Nếu `NORM` chứa thông tin hỗ trợ tìm flag hoặc credentials, attacker đọc được.

Hướng vá:

- An toàn nhất: mọi `CHART`/`EXPORT` đều yêu cầu `p->owner == g_cur->idx`.
- Nếu business logic muốn public `NORM`, vẫn nên hạn chế `PATIENTS` để không lộ PID hàng loạt.

### 7.3. `hex2bin()` truncate input quá dài

`hex2bin()` hiện làm:

```c
n = strlen(hex) / 2;
if (n > cap) n = cap;
```

Sau đó nó chỉ parse phần nằm trong `cap`, phần dư bị bỏ qua. Hệ quả:

- input quá dài không bị reject;
- byte invalid sau vùng cap không bị phát hiện;
- client/checker có thể hiểu khác server về dữ liệu thực sự được lưu.

Hướng vá:

- Tạo helper strict, ví dụ `hex2bin_strict(hex, out, cap, &out_len)`.
- Nếu `strlen(hex)` lẻ, không phải hex, hoặc `strlen(hex)/2 > cap` thì trả lỗi.
- Đổi các command nhận hex sang `ERR TOO_LONG`/`ERR BAD_HEX` thay vì truncate im lặng.

Cần test checker vì một số checker có thể gửi remark/body dài và kỳ vọng bị truncate.

### 7.4. Unix renderer socket đang là `0666`

`main.c` tạo `/run/medrec/rend.sock` rồi `chmod(path, 0666)`. Điều này làm mọi user trong container có thể connect renderer.

Rủi ro:

- tăng blast radius nếu có bug khác cho phép chạy code hoặc thao tác local;
- làm lớp tách UID front/rend yếu đi.

Hướng vá:

- Dùng mode `0660` hoặc `0600`.
- Chown socket về user/group mà front thật sự cần dùng để connect.
- Giữ parent root accept socket như hiện tại, nhưng giảm quyền trên socket path.

Cần kiểm tra kỹ vì front process UID `1001` phải connect được renderer socket.

### 7.5. Password lưu plaintext

Service lưu password vào DB và trong memory dạng plaintext. Đây là lý do bug `STAFF` trở thành account takeover trực tiếp.

Hướng vá dài hạn:

- Lưu `salt + hash(password)`, ví dụ SHA-256/HMAC hoặc tốt hơn là KDF phù hợp nếu môi trường cho phép.
- Với CTF service C nhỏ, ít nhất có thể lưu SHA-256(password + salt) để giảm tác hại của memory disclosure.
- Cần migration hoặc reset DB, nên đây không phải vá nóng an toàn nhất trong AD.

## Ưu tiên vá đề xuất

1. Giữ bản vá `STAFF/ROSTER` zero-pad: ưu tiên cao nhất, chặn account takeover.
2. Giữ bản vá `CHART/EXPORT` clamp length: chặn heap leak quanh patient body.
3. Giữ bản vá `STAMP` bounds check và `SHEET` two-phase update: chặn memory corruption renderer.
4. Giữ `FIELD ADD` dùng `calloc`: giảm leak heap.
5. Nếu checker cho phép, vá tiếp `PATIENTS` chỉ cho xem bệnh nhân của chính mình.
6. Nếu checker cho phép, đổi `chart_open()` để mọi chart đều owner-only.
7. Thêm strict hex parser cho các command nhận hex.
8. Hạ quyền renderer socket từ `0666` xuống quyền tối thiểu mà front vẫn connect được.

## Nhận xét về bản vá hiện tại

Bản vá `medrec_patched_2` xử lý đúng các bug memory-safety chính mà không đổi protocol quá mạnh. Hai lựa chọn đáng khen trong bối cảnh AD là:

- `STAFF/ROSTER` vẫn giữ `DATA 128` nhưng zero phần không public, giảm nguy cơ checker fail.
- `CHART/EXPORT` trả page ngắn/zero ở EOF thay vì đổi sang lỗi cứng.

Các điểm chưa vá có vẻ được giữ lại vì rủi ro checker: cross-doctor `PATIENTS`, cross-doctor `NORM`, `hex2bin()` truncate, renderer socket `0666`. Nếu ưu tiên bảo mật hơn tương thích, đây là nhóm nên xử lý tiếp.
