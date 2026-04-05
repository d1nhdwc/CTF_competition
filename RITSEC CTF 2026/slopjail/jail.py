import os
import sys
import tempfile
import time
import readline

print("slopjail is ai and can make mistakes. check important info.\n")

sys.stdout.write("gimme slop: ")
sys.stdout.flush()
inp = sys.stdin.buffer.readline().decode().strip()

try:
    data = bytes.fromhex(inp)
except:
    print("invalid slop")
    sys.exit(1)

if len(data) > 500000:
    print("ur slop is too big")
    sys.exit(1)

tmpdir = tempfile.mkdtemp()

for fname in ["config.json", "generation_config.json", "tokenizer.json", "tokenizer_config.json", "special_tokens_map.json"]:
    os.symlink(os.path.join(os.path.dirname(os.path.abspath(__file__)), fname), os.path.join(tmpdir, fname))

with open(f"{tmpdir}/model.safetensors", "wb") as f:
    f.write(data)

try:
    t1 = time.time()
    from transformers import AutoModelForCausalLM, PreTrainedTokenizerFast
    import torch
    tokenizer = PreTrainedTokenizerFast.from_pretrained(tmpdir)
    model = AutoModelForCausalLM.from_pretrained(
        tmpdir,
        dtype=torch.float32,
    )
    model.eval()

    input_ids = tokenizer.encode('<bos>', return_tensors="pt")

    with torch.no_grad():
        output_ids = model.generate(
            input_ids,
            max_new_tokens=256,
            do_sample=False,
            pad_token_id=tokenizer.pad_token_id,
            eos_token_id=tokenizer.eos_token_id,
        )

    generated = output_ids[0, input_ids.shape[1]:]
    slop = tokenizer.decode(generated, skip_special_tokens=True)
    output = eval(slop, {"__builtins__": {}})
    t2 = time.time()
    elapsed = int(t2-t1)
    print(f"thought for {elapsed}s: {output}")

except:
    print("slopjail's response could not be fully generated")
finally:
    for fname in os.listdir(tmpdir):
        os.unlink(os.path.join(tmpdir, fname))
    os.rmdir(tmpdir)
