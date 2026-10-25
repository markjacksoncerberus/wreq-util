#!/usr/bin/env python3
"""Compile native captures and explicitly derived desktop platform variants."""
import copy
import hashlib
import json
import pathlib
import argparse
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCES = ['https://www.chromium.org/updates/ua-reduction/',
           'https://github.com/brave/brave-browser/wiki/User-Agents',
           'https://wicg.github.io/ua-client-hints/']
SCENARIOS = {'/navigation':'navigation', '/clicked':'link', '/script.js':'script',
             '/style.css':'style', '/image.svg':'image', '/font.woff2':'font',
             '/fetch':'fetch', '/post':'post', '/cross-fetch':'cross-fetch',
             '/cross-script.js':'cross-script', '/after-hints':'hints'}
DYNAMIC = {'host','content-length','cookie','origin','referer',
           'sec-fetch-site','sec-fetch-mode','sec-fetch-user','sec-fetch-dest'}

def freeze(path):
    raw = json.loads(path.read_text())
    chromium_version = raw['browser_version']['product'].split('/')[-1]
    if raw['browser'] == 'edge':
        # CDP reports Edg/<product build>, not the embedded Chromium build.
        hints = raw['identity']['hints']['fullVersionList']
        chromium_version = next(b['version'] for b in hints if b['brand'] == 'Chromium')
        edge_version = next(b['version'] for b in hints if b['brand'] == 'Microsoft Edge')
        if edge_version != raw['browser_version']['product'].split('/')[-1]:
            raise ValueError('Edge CDP and Client Hints product builds disagree')
        if (raw.get('installation') or {}).get('version', edge_version) != edge_version:
            raise ValueError('installed and captured Edge versions disagree')

    if not re.fullmatch(r'\d+\.\d+\.\d+\.\d+', chromium_version):
        raise ValueError('invalid captured browser build')
    architecture = raw['environment']['architecture'].lower()
    architecture = {'amd64':'x86_64','aarch64':'arm64'}.get(architecture, architecture)
    if architecture not in ('x86_64','arm64'): raise ValueError('unsupported architecture')
    installation = raw.get('installation') or {}
    profile = {'schema_version':1,
               'profile_id':'', 'chromium_version':chromium_version, 'architecture':architecture,
               'capture_mode':'headless' if raw['environment']['headless'] else 'headed',
               'product_version':installation.get('version', edge_version if raw['browser'] == 'edge' else None), 'browser':raw['browser'], 'platform':raw['platform'],
               'verification':'native', 'captured_at':raw['captured_at'],
               'source_capture':path.name, 'source_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
               'browser_version':raw['browser_version']['product'], 'identity':raw['identity'],
               'transport_verification':'unverified: header fixtures do not certify TLS emulation',
               'sources':SOURCES + (['https://learn.microsoft.com/en-us/microsoft-edge/web-platform/user-agent-guidance'] if raw['browser'] == 'edge' else []), 'assumptions':[], 'samples':[], 'high_entropy_headers':{}}
    for capture in raw['captures']:
        found = set()
        for req in capture['requests']:
            fields = {k.lower():v for k,v in req['headers']}
            scenario = SCENARIOS.get(fields.get(':path',req.get('path')))
            if not scenario:
                continue
            if scenario in found:
                raise ValueError(f'duplicate scenario {scenario}')
            found.add(scenario)
            assert capture['connections'][req['connection']]['protocol'] == capture['protocol']
            high = {k:v for k,v in fields.items() if k.startswith('sec-ch-ua-') and k not in ('sec-ch-ua-mobile','sec-ch-ua-platform')}
            if scenario == 'hints':
                profile['high_entropy_headers'].update(high)
            headers = [[k,v] for k,v in req['headers'] if not k.startswith(':')
                       and k.lower() not in DYNAMIC and k.lower() not in high]
            profile['samples'].append({'protocol':capture['protocol'], 'scenario':scenario,
                                       'headers':headers,
                                       'order':[k for k,v in req['headers'] if not k.startswith(':')]})
        if found != set(SCENARIOS.values()):
            raise ValueError(f'missing scenarios: {set(SCENARIOS.values()) - found}')
    return profile

def variants(native):
    targets = [(native['platform'], None, None)]
    if native['platform'] == 'linux' and native['architecture'] == 'x86_64':
        targets += [('windows','Windows NT 10.0; Win64; x64','Win32'),
                    ('macos','Macintosh; Intel Mac OS X 10_15_7','MacIntel')]
    for target, token, js_platform in targets:
        p = copy.deepcopy(native)
        p['platform'] = target
        if target != native['platform']:
            p['verification'] = 'derived'
            p['assumptions'] = [
                'Desktop x86_64 variant derived from native Linux request samples.',
                'UA platform tokens and low-entropy platform hint follow cited primary sources.',
                'Header order, resource Accept values and brand order inherited from Linux; not native-verified.',
                'OS platformVersion is unknown and omitted, not invented.',
                'Exact full build version is not verified on this OS; full-version-list is omitted.',
                'Brave site-specific brand suppression is not covered by these generic fixtures.']
            if p['browser'] == 'edge':
                p['assumptions'][-1] = 'Edge site-specific UA overrides are not covered by these generic localhost captures.'
            ch_platform = 'Windows' if target == 'windows' else 'macOS'
            p['identity']['user_agent'] = p['identity']['user_agent'].replace('X11; Linux x86_64', token)
            p['identity']['platform'] = js_platform
            p['identity']['hints']['platform'] = ch_platform
            for key in ('platformVersion','fullVersionList','uaFullVersion'):
                p['identity']['hints'].pop(key, None)
            for key in ('sec-ch-ua-platform-version','sec-ch-ua-full-version-list'):
                p['high_entropy_headers'].pop(key, None)
            for sample in p['samples']:
                for pair in sample['headers']:
                    if pair[0].lower() == 'user-agent':
                        pair[1] = p['identity']['user_agent']
                    elif pair[0].lower() == 'sec-ch-ua-platform':
                        pair[1] = json.dumps(ch_platform)
        suffix = '-headless' if p['capture_mode'] == 'headless' else ''
        identity_version = p['product_version'] if p['browser'] == 'edge' else p['chromium_version']
        p['profile_id'] = f"{p['browser']}-{identity_version}-{target}-{p['architecture']}{suffix}"
        yield p


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixtures', type=pathlib.Path, default=ROOT/'fixtures')
    args = parser.parse_args()
    if args.fixtures.resolve() != (ROOT/'fixtures').resolve():
        raise ValueError('import native raw captures into fixtures/ before compiling the embedded catalogue')
    profiles = {}
    for path in sorted(args.fixtures.glob('*.raw.json')):
        native = freeze(path)
        if native['platform'] not in ('linux','windows','macos'):
            raise ValueError('unrecognized native platform')
        for p in variants(native):
            key = p['profile_id']
            prior = profiles.get(key)
            if prior and prior['verification'] == 'native':
                if p['verification'] == 'native' and prior['source_sha256'] != p['source_sha256']:
                    raise ValueError(f'duplicate native profile {key}; reconcile captures explicitly')
                continue
            profiles[key] = p
    catalog = []
    rust = ['// Generated by capture/freeze.py; do not edit.', 'use super::ProfileEntry;', 'pub static CATALOG: &[ProfileEntry] = &[']
    for key, p in sorted(profiles.items()):
        filename = key+'.json'
        (args.fixtures/filename).write_text(json.dumps(p,indent=2)+'\n')
        entry = {k:p[k] for k in ['profile_id','browser','chromium_version','product_version','platform','architecture','capture_mode','verification','source_capture','source_sha256']}
        entry['fixture'] = filename
        catalog.append(entry)
        fields = {k:p[k] for k in ['profile_id','browser','chromium_version','platform','architecture','capture_mode','verification']}
        product_version = 'Some(' + json.dumps(p['product_version']) + ')' if p['product_version'] else 'None'
        rust.append('    ProfileEntry { product_version: ' + product_version + ', '+', '.join(f'{k}: {json.dumps(v)}' for k,v in fields.items())+
                    f', json: include_str!("../../fixtures/{filename}")'+' },')
    rust.append('];')
    (args.fixtures/'catalog.json').write_text(json.dumps(catalog,indent=2)+'\n')
    generated=ROOT/'src/captured/catalog.rs'
    generated.parent.mkdir(exist_ok=True)
    generated.write_text('\n'.join(rust)+'\n')
    print(f'Frozen {len(catalog)} profiles ({sum(p["verification"]=="native" for p in catalog)} native).')

if __name__ == '__main__':
    main()
