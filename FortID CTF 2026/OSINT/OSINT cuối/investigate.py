import concurrent.futures, html, json, pathlib, re, subprocess, sys

CACHE = pathlib.Path('/tmp/melankonimir-research')
CACHE.mkdir(exist_ok=True)

def fetch(url):
    p = subprocess.run(['curl', '-L', '-sS', '--max-time', '25', url], capture_output=True, text=True)
    return p.stdout

def extract(s):
    s = re.sub(r'<script.*?</script>|<style.*?</style>', ' ', s, flags=re.S|re.I)
    return re.sub(r'\s+', ' ', html.unescape(re.sub(r'<[^>]+>', ' ', s)))

if sys.argv[1] == 'profiles':
    urls = sys.argv[2:]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for url, s in zip(urls, pool.map(fetch, urls)):
            dest = CACHE / (re.sub(r'[^a-zA-Z0-9]', '_', url) + '.html')
            dest.write_text(s)
            print(url, len(s), extract(s)[:900], flush=True)
elif sys.argv[1] == 'hevy':
    def hevy(name):
        p = subprocess.run(['curl', '-sS', '--max-time', '20',
            'https://api.hevyapp.com/public_user_profile/' + name,
            '-H', 'x-api-key: shelobs_hevy_web', '-H', 'Hevy-Platform: web'],
            capture_output=True, text=True)
        (CACHE / ('hevy_' + name + '.json')).write_text(p.stdout)
        return name, p.stdout
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        for name, result in pool.map(hevy, sys.argv[2:]):
            print(name, result, flush=True)
elif sys.argv[1] == 'scripts':
    page = pathlib.Path(sys.argv[2]).read_text()
    base = sys.argv[3]
    paths = list(dict.fromkeys(re.findall(r'<script[^>]+src="([^"]+)"', page)))
    urls = [base+p if p.startswith('/') else p for p in paths]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for i, (url, s) in enumerate(zip(urls, pool.map(fetch, urls))):
            (CACHE / ('script_'+str(i)+'.js')).write_text(s)
            matches = re.findall(r'.{0,120}(?:search/|search\?|searchUsers|search_users|search-users|search_profiles|api\.suno|studio-api).{0,220}', s)
            if matches: print(url, '\n'+'\n'.join(matches[:30]), flush=True)
