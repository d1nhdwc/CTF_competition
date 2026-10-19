"""Decode public share-page hydration data cached during the CTF."""
import json
import pathlib
import re

CACHE = pathlib.Path('/tmp/melankonimir-research')
for path in CACHE.glob('https___chatgpt_com_share_*.html'):
    match = re.search(r'streamController\.enqueue\(("(?:[^"\\]|\\.)*")\)', path.read_text())
    if not match:
        continue
    table = json.loads(json.loads(match[1]))

    def decode(index, depth=0):
        if index < 0:
            return None
        if depth > 100:
            return '<depth limit>'
        value = table[index]
        if isinstance(value, dict):
            return {str(table[int(k[1:])]) if k.startswith('_') else k: decode(v, depth + 1)
                    for k, v in value.items()}
        if isinstance(value, list):
            return [decode(v, depth + 1) if isinstance(v, int) else v for v in value]
        return value

    data = decode(0)['loaderData']['routes/share.$shareId.($action)']['serverResponse']['data']
    path.with_suffix('.json').write_text(json.dumps(data, ensure_ascii=False, indent=2))
    lines = [str(data.get('title', path.stem))]
    for node in data.get('linear_conversation', []):
        message = node.get('message')
        if not message:
            continue
        content = message.get('content', {})
        if content.get('parts') and any(content['parts']):
            lines.append('\n' + message['author']['role'].upper() + '\n' +
                         '\n'.join(str(part) for part in content['parts']))
    path.with_suffix('.txt').write_text('\n'.join(lines))
    print(path.with_suffix('.txt'), data.get('title'))
