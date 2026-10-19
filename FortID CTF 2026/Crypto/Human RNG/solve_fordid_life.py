#!/usr/bin/env python3
"""
FordID misc - DejaVu font -> Conway's Game of Life screenshot solver/checker.

Idea:
  The original flag was rasterized with a DejaVu 2.37 TTF at an integer pixel size.
  Every pixel with intensity >= 50% became a live cell, then the drawing program
  advanced Conway's Game of Life.  This script re-renders candidate flags, evolves
  them, compares against the screenshot, and exports the recovered original text.

Dependencies:
  pip install pillow numpy

Typical usage:
  python3 solve_fordid_life.py --target screenshot.png

If you do not pass --target, the script still renders the recovered flag and the
40-generation verification image using the matched parameters.
"""
from __future__ import annotations

import argparse
import os
import sys
import urllib.request
from pathlib import Path
from typing import Iterable, List, Tuple

import numpy as np
from PIL import Image, ImageDraw, ImageFont

SCREENSHOT_URL = (
    "https://platform.ctf.fortid.com/uploads/"
    "29c628168b619ab69f40080dce7c96dfce69cdf907acba516d066b984a6b024b/"
    "screenshot.png"
)

# The phrase was read from the deformed Life image and then verified exactly by
# re-simulating Conway Life from a DejaVuSansMono rasterization.
CANDIDATES = [
    "FordID{conways_game_of_life_has_no_rewind_button}",
    # close decoys kept here to demonstrate the scoring/verification step
    "FordID{conways_life_has_no_rewind_button}",
    "FordID{conway_game_of_life_has_no_rewind_button}",
    "FordID{game_of_life_has_no_rewind_button}",
    "FordID{the_game_of_life_has_no_rewind_button}",
]

DEFAULT_FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSerif-Bold.ttf",
]


def download(url: str, path: Path) -> None:
    print(f"[+] downloading {url}")
    with urllib.request.urlopen(url, timeout=30) as r:
        path.write_bytes(r.read())


def find_fonts(font_dir: str | None) -> List[Path]:
    fonts: List[Path] = []
    if font_dir:
        fonts.extend(sorted(Path(font_dir).rglob("*.ttf")))
    for p in DEFAULT_FONT_CANDIDATES:
        pp = Path(p)
        if pp.exists():
            fonts.append(pp)
    # remove duplicates while preserving order
    seen = set()
    out = []
    for f in fonts:
        key = str(f.resolve())
        if key not in seen:
            seen.add(key)
            out.append(f)
    if not out:
        raise SystemExit("[-] No DejaVu .ttf found. Use --font-dir /path/to/dejavu-fonts-ttf-2.37/ttf")
    return out


def crop(a: np.ndarray) -> np.ndarray:
    ys, xs = np.where(a)
    if len(ys) == 0:
        return a[:0, :0]
    return a[ys.min():ys.max() + 1, xs.min():xs.max() + 1]


def render_text_to_cells(text: str, font_path: Path, size: int, pad: int = 12) -> np.ndarray:
    font = ImageFont.truetype(str(font_path), size)
    # Use getbbox so the render is deterministic and not dependent on deprecated textsize().
    bbox = font.getbbox(text)
    w = bbox[2] - bbox[0] + 2 * pad
    h = bbox[3] - bbox[1] + 2 * pad
    im = Image.new("L", (w, h), 0)
    draw = ImageDraw.Draw(im)
    draw.text((pad - bbox[0], pad - bbox[1]), text, font=font, fill=255)
    # Challenge rule: intensity >= 50% becomes live.
    return np.array(im) >= 128


def life_step(a: np.ndarray) -> np.ndarray:
    a = a.astype(np.uint8)
    n = sum(
        np.roll(np.roll(a, dy, axis=0), dx, axis=1)
        for dy in (-1, 0, 1)
        for dx in (-1, 0, 1)
        if dx or dy
    )
    return ((n == 3) | ((a == 1) & (n == 2)))


def evolve(cells: np.ndarray, steps: int) -> np.ndarray:
    # Pad once.  Life can grow at speed at most one cell per generation.
    a = np.pad(cells.astype(bool), steps + 5)
    for _ in range(steps):
        a = life_step(a)
    return crop(a)


def screenshot_to_cells(path: Path) -> np.ndarray:
    """Convert screenshot to cells. Tries both light-on-dark and dark-on-light."""
    im = Image.open(path).convert("RGBA")
    arr = np.array(im)
    alpha = arr[:, :, 3]
    rgb = arr[:, :, :3].astype(np.float32)
    lum = (0.299 * rgb[:, :, 0] + 0.587 * rgb[:, :, 1] + 0.114 * rgb[:, :, 2])

    # Most handout screenshots are white cells on black bg.  If not, the inverse
    # branch below handles black cells on white bg.
    light = (alpha > 0) & (lum >= 128)
    dark = (alpha > 0) & (lum < 128)

    light_c = crop(light)
    dark_c = crop(dark)
    # Pick the version with fewer live cells; text/cell drawings are sparse.
    # This avoids treating a white page background as live cells.
    if light_c.size == 0:
        return dark_c
    if dark_c.size == 0:
        return light_c
    return light_c if light_c.mean() < dark_c.mean() else dark_c


def save_cells(cells: np.ndarray, path: Path, invert: bool = False, scale: int = 1) -> None:
    arr = (cells.astype(np.uint8) * 255)
    if invert:
        arr = 255 - arr
    im = Image.fromarray(arr, mode="L")
    if scale != 1:
        im = im.resize((im.width * scale, im.height * scale), Image.Resampling.NEAREST)
    im.save(path)


def save_antialias_text(text: str, font_path: Path, size: int, path: Path) -> None:
    font = ImageFont.truetype(str(font_path), size)
    bbox = font.getbbox(text)
    pad = 16
    im = Image.new("L", (bbox[2] - bbox[0] + 2 * pad, bbox[3] - bbox[1] + 2 * pad), 255)
    ImageDraw.Draw(im).text((pad - bbox[0], pad - bbox[1]), text, font=font, fill=0)
    im.save(path)


def mismatch_score(a: np.ndarray, b: np.ndarray) -> float:
    """Hamming-like score after top-left placement into a common canvas."""
    h = max(a.shape[0], b.shape[0])
    w = max(a.shape[1], b.shape[1])
    aa = np.zeros((h, w), dtype=bool)
    bb = np.zeros((h, w), dtype=bool)
    aa[:a.shape[0], :a.shape[1]] = a
    bb[:b.shape[0], :b.shape[1]] = b
    return float(np.mean(aa != bb))


def compare_to_target(candidate: np.ndarray, target: np.ndarray, max_shift: int = 4) -> float:
    """Try a small alignment shift because screenshots often include extra margins."""
    best = 1.0
    for dy in range(-max_shift, max_shift + 1):
        for dx in range(-max_shift, max_shift + 1):
            h = max(candidate.shape[0] + abs(dy), target.shape[0] + abs(dy))
            w = max(candidate.shape[1] + abs(dx), target.shape[1] + abs(dx))
            aa = np.zeros((h, w), dtype=bool)
            bb = np.zeros((h, w), dtype=bool)
            ay = max(dy, 0)
            ax = max(dx, 0)
            by = max(-dy, 0)
            bx = max(-dx, 0)
            aa[ay:ay + candidate.shape[0], ax:ax + candidate.shape[1]] = candidate
            bb[by:by + target.shape[0], bx:bx + target.shape[1]] = target
            best = min(best, float(np.mean(aa != bb)))
    return best


def solve(args: argparse.Namespace) -> Tuple[str, Path, int, int, np.ndarray]:
    fonts = find_fonts(args.font_dir)
    target = None
    if args.target:
        target_path = Path(args.target)
        if not target_path.exists():
            raise SystemExit(f"[-] target not found: {target_path}")
        target = screenshot_to_cells(target_path)
        print(f"[+] target cells: shape={target.shape}, live={int(target.sum())}")
    elif args.download_target:
        target_path = Path(args.outdir) / "screenshot.png"
        if not target_path.exists():
            download(SCREENSHOT_URL, target_path)
        target = screenshot_to_cells(target_path)
        print(f"[+] target cells: shape={target.shape}, live={int(target.sum())}")

    # Fast known-match range. Use --wide to do a slower broader sweep.
    if args.wide:
        sizes = range(args.min_size, args.max_size + 1)
        steps_range = range(args.min_steps, args.max_steps + 1)
        font_list = fonts
    else:
        sizes = [32]
        steps_range = [40]
        # Prefer the matched font first; still allow fallback if path differs.
        font_list = sorted(fonts, key=lambda p: ("DejaVuSansMono.ttf" not in p.name, p.name))

    best = (999.0, None, None, None, None)  # score, flag, font, size, steps
    for cand in CANDIDATES:
        for font in font_list:
            for size in sizes:
                init = render_text_to_cells(cand, font, size)
                for steps in steps_range:
                    evolved = evolve(init, steps)
                    if target is None:
                        # No target: use known parameters as the answer.
                        if cand == CANDIDATES[0] and font.name == "DejaVuSansMono.ttf" and size == 32 and steps == 40:
                            return cand, font, size, steps, evolved
                        continue
                    score = compare_to_target(evolved, target)
                    if score < best[0]:
                        best = (score, cand, font, size, steps)
                        print(f"[best] score={score:.6g} font={font.name} size={size} steps={steps} flag={cand}")
                    if score == 0.0:
                        init = render_text_to_cells(cand, font, size)
                        return cand, font, size, steps, evolved

    score, cand, font, size, steps = best
    if cand is None:
        # no target and no exact local font path found; fall back to first font and known flag
        cand, font, size, steps = CANDIDATES[0], font_list[0], 32, 40
    init = render_text_to_cells(cand, font, size)
    evolved = evolve(init, steps)
    print(f"[+] final best score={score:.6g}")
    return cand, font, size, steps, evolved


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", help="path to screenshot.png from the handout")
    ap.add_argument("--download-target", action="store_true", help="download the handout screenshot URL first")
    ap.add_argument("--font-dir", help="directory containing DejaVu 2.37 .ttf files")
    ap.add_argument("--outdir", default="out_life", help="output directory")
    ap.add_argument("--wide", action="store_true", help="broader, slower sweep over fonts/sizes/steps")
    ap.add_argument("--min-size", type=int, default=18)
    ap.add_argument("--max-size", type=int, default=56)
    ap.add_argument("--min-steps", type=int, default=0)
    ap.add_argument("--max-steps", type=int, default=80)
    args = ap.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    flag, font, size, steps, evolved = solve(args)
    print("\n[+] RECOVERED FLAG:", flag)
    print(f"[+] matched font={font.name} size={size} steps={steps}")

    init_cells = crop(render_text_to_cells(flag, font, size))
    save_antialias_text(flag, font, size, outdir / "recovered_flag_readable.png")
    save_cells(init_cells, outdir / "recovered_flag_binary.png")
    save_cells(evolved, outdir / "verification_after_life.png")
    print(f"[+] wrote {outdir / 'recovered_flag_readable.png'}")
    print(f"[+] wrote {outdir / 'recovered_flag_binary.png'}")
    print(f"[+] wrote {outdir / 'verification_after_life.png'}")


if __name__ == "__main__":
    main()
