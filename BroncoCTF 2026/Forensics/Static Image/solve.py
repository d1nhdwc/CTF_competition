import cv2
import numpy as np

video = "/mnt/data/static.mp4"
cap = cv2.VideoCapture(video)

frames = []
while True:
    ret, frame = cap.read()
    if not ret:
        break
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    frames.append(gray > 127)

frames = np.stack(frames)

fps = 60
chars = []

for sec in range(25):
    start = sec * fps
    end = min((sec + 1) * fps, len(frames) - 2)

    eq = (frames[start:end] == frames[start+2:end+2]).mean(axis=0)

    img = np.clip((eq - eq.mean()) / eq.std() * 45 + 128, 0, 255).astype(np.uint8)
    cv2.imwrite(f"char_{sec:02}.png", img)
