from PIL import Image
import numpy as np

targets = [
    ("Tiger.png", 0, 0, "tiger_hidden.png"),  # R, bit 0
    ("Snake.png", 1, 2, "snake_hidden.png"),  # G, bit 2
    ("Crane.png", 2, 4, "crane_hidden.png"),  # B, bit 4
]

for filename, channel, bit, output in targets:
    image = np.array(Image.open(filename).convert("RGB"))
    plane = ((image[:, :, channel] >> bit) & 1) * 255
    Image.fromarray(plane.astype(np.uint8)).save(output)
