import pandas as pd
import matplotlib.pyplot as plt

# Đọc dữ liệu từ file CSV
df = pd.read_csv('trackpad_deltas.csv')

# Khởi tạo tọa độ bắt đầu
current_x = 0
current_y = 0

plt.figure(figsize=(10, 6))

segment_x = []
segment_y = []

# Duyệt qua từng dòng dữ liệu
for index, row in df.iterrows():
    dx = row['dx']
    dy = row['dy']
    pen_down = row['pen_down']
    
    # Cập nhật tọa độ
    current_x += dx
    current_y += dy
    
    # Nếu đang nhấn để vẽ, thêm tọa độ vào đoạn hiện tại
    if pen_down == 1:
        segment_x.append(current_x)
        segment_y.append(current_y)
    else:
        # Nếu nhấc bút lên, vẽ đoạn vừa ghi nhận và làm trống danh sách
        if len(segment_x) > 0:
            plt.plot(segment_x, segment_y, color='blue')
            segment_x = []
            segment_y = []

# Vẽ đoạn cuối cùng nếu còn
if len(segment_x) > 0:
    plt.plot(segment_x, segment_y, color='blue')

# Đảo ngược trục Y để phù hợp với hệ tọa độ màn hình
plt.gca().invert_yaxis()
plt.title('Reconstructed Image')
plt.axis('equal') # Giữ đúng tỷ lệ khung hình
plt.show()