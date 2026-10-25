#!/usr/bin/env python3
"""Compare actual wreq output to native browser wire captures over H1 and H2."""
import asyncio
import argparse
import json
import pathlib
import ssl
import subprocess
import tempfile
from capture import Collector

ROOT = pathlib.Path(__file__).resolve().parents[1]

async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', help='Exact catalogue ID; defaults to every native headed capture')
    parser.add_argument('--probe', type=pathlib.Path, help='Path to a built captured_probe binary')
    args = parser.parse_args()
    if args.probe is None:
        metadata = json.loads(subprocess.check_output(
            ['cargo', 'metadata', '--no-deps', '--format-version', '1'], cwd=ROOT))
        args.probe = pathlib.Path(metadata['target_directory'])/'debug/examples/captured_probe'
    catalog = json.loads((ROOT/'fixtures/catalog.json').read_text())
    selected = [p for p in catalog if p['verification']=='native' and p['capture_mode']=='headed'
                and (args.profile is None or p['profile_id']==args.profile)]
    if not selected: raise ValueError('no matching native headed profiles')
    failures = []
    checked = 0
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                        '-keyout',str(tmp/'key'),'-out',str(tmp/'cert'),'-subj','/CN=localhost'],
                       check=True,capture_output=True)
        for entry in selected:
            product = entry['profile_id']
            raw = json.loads((ROOT/'fixtures'/entry['source_capture']).read_text())
            for protocol in ('h2','http/1.1'):
                collector = Collector(protocol)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(tmp/'cert',tmp/'key')
                ctx.set_alpn_protocols([protocol])
                server = await asyncio.start_server(collector.connection,'127.0.0.1',0,ssl=ctx)
                port = server.sockets[0].getsockname()[1]
                try:
                    proc = await asyncio.create_subprocess_exec(str(args.probe.resolve()),
                        f'https://localhost:{port}/',product,protocol,
                        stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
                    stdout, stderr = await asyncio.wait_for(proc.communicate(),60)
                    if proc.returncode:
                        raise RuntimeError(stderr.decode())
                finally:
                    server.close()
                    await server.wait_closed()
                if len(collector.requests) != 14:
                    raise AssertionError(f'{product} {protocol}: expected 14 transmitted requests, got {len(collector.requests)}')
                native = next(c for c in raw['captures'] if c['protocol']==protocol)
                expected = {dict((k.lower(),v) for k,v in r['headers']).get(':path',r.get('path')):r for r in native['requests']}
                for request in collector.requests:
                    fields = {k.lower():v for k,v in request['headers']}
                    path = fields.get(':path',request.get('path'))
                    if path == '/exact':
                        extras = set(fields) - {':method',':authority',':scheme',':path','host','x-exact'}
                        if extras or fields.get('x-exact') != 'yes': failures.append((product,protocol,path,sorted(extras)))
                        checked += 1
                        continue
                    if path == '/forced':
                        if 'accept-encoding' in fields or fields.get('user-agent') != 'forced':
                            failures.append((product,protocol,path,fields))
                        checked += 1
                        continue
                    ref = expected[path]
                    # Authority/Referer/Origin contain ephemeral collector ports. All
                    # other regular header values and their relative order must match.
                    def normalize(req):
                        import re
                        return [(k.lower(), re.sub(r':\d+(?=/|$)', ':PORT',v) if k.lower() in ('host','referer','origin') else v)
                                for k,v in req['headers'] if not k.startswith(':')]
                    actual, wanted = normalize(request), normalize(ref)
                    if actual != wanted:
                        failures.append((product,protocol,path,{'actual':actual,'expected':wanted}))
                    checked += 1
        if failures:
            print(json.dumps(failures,indent=2))
            raise SystemExit(1)
        print(f'{checked} wire comparisons passed ({len(selected)} profiles × HTTP/1.1/HTTP/2; includes force/exact).')

asyncio.run(main())
