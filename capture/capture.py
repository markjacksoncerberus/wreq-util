#!/usr/bin/env python3
"""Capture ordered headers at the receiving TLS endpoint, not from a CDP dictionary.
Use a fresh headed browser profile. Dependencies: requirements.txt and openssl.
"""
import argparse
import asyncio
import datetime
import hashlib
import json
import pathlib
import platform
import ssl
import subprocess
import tempfile
from urllib.parse import urlsplit

import h2.config
import h2.connection
import h2.events
from playwright.async_api import async_playwright

HINTS = 'Sec-CH-UA-Full-Version-List, Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Platform-Version, Sec-CH-UA-Model, Sec-CH-UA-WoW64'

class Collector:
    def __init__(self, protocol):
        self.protocol = protocol
        self.requests = []
        self.connections = []
        self.port = 0

    def response(self, path):
        path = urlsplit(path).path
        headers = [('content-type', 'text/html'), ('cache-control', 'no-store'),
                   ('access-control-allow-origin', '*'), ('access-control-allow-headers', 'content-type')]
        status = 200
        body = b'<!doctype html><title>capture</title><a id="link" href="/clicked">click</a>'
        if path == '/redirect':
            status, body = 302, b''
            headers.append(('location', '/redirected'))
        elif path == '/hints':
            headers.append(('accept-ch', HINTS))
        elif path.endswith('.js'):
            headers[0] = ('content-type', 'application/javascript')
            body = b'window.captureScript = true;'
        elif path.endswith('.css'):
            headers[0] = ('content-type', 'text/css')
            body = b'body { color: black }'
        elif path.endswith('.svg'):
            headers[0] = ('content-type', 'image/svg+xml')
            body = b'<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>'
        elif path.endswith('.woff2'):
            headers[0] = ('content-type', 'font/woff2')
            body = b''  # Request headers are captured before decoding the font.
        headers.append(('content-length', str(len(body))))
        return status, headers, body

    async def connection(self, reader, writer):
        tls = writer.get_extra_info('ssl_object')
        connection = {'protocol': tls.selected_alpn_protocol(), 'settings': [],
                      'tls_version': tls.version(), 'cipher': tls.cipher()[0]}
        index = len(self.connections)
        self.connections.append(connection)
        try:
            if connection['protocol'] == 'h2':
                conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False, header_encoding='utf-8'))
                conn.initiate_connection()
                writer.write(conn.data_to_send())
                while data := await reader.read(65536):
                    for event in conn.receive_data(data):
                        if isinstance(event, h2.events.RemoteSettingsChanged):
                            connection['settings'].append([[int(k), v.new_value] for k, v in event.changed_settings.items()])
                        elif isinstance(event, h2.events.RequestReceived):
                            headers = list(event.headers)
                            self.requests.append({'connection': index, 'headers': headers})
                            status, response_headers, body = self.response(dict(headers)[':path'])
                            conn.send_headers(event.stream_id, [(':status', str(status))] + response_headers)
                            conn.send_data(event.stream_id, body, end_stream=True)
                        elif isinstance(event, h2.events.DataReceived):
                            conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    writer.write(conn.data_to_send())
                    await writer.drain()
            else:
                while True:
                    try:
                        block = await reader.readuntil(b'\r\n\r\n')
                    except asyncio.IncompleteReadError:
                        break
                    lines = block.decode('latin1').split('\r\n')
                    method, path, _ = lines[0].split(' ', 2)
                    headers = [line.split(': ', 1) for line in lines[1:] if line]
                    self.requests.append({'connection': index, 'method': method, 'path': path, 'headers': headers})
                    length = next((int(v) for k, v in headers if k.lower() == 'content-length'), 0)
                    if length:
                        await reader.readexactly(length)
                    status, response_headers, body = self.response(path)
                    response = f'HTTP/1.1 {status} OK\r\n' + ''.join(f'{k}: {v}\r\n' for k, v in response_headers) + '\r\n'
                    writer.write(response.encode() + body)
                    await writer.drain()
        except (ConnectionError, ssl.SSLError, h2.exceptions.ProtocolError):
            pass
        finally:
            writer.close()

async def capture(args):
    installation = json.loads(pathlib.Path(args.installation).read_text()) if args.installation else None
    if installation:
        if installation['product'] != args.product: raise ValueError('installation product mismatch')
        args.browser = installation['executable']
    if not args.browser: raise ValueError('--browser or --installation is required')
    output = pathlib.Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    collectors = []
    with tempfile.TemporaryDirectory(prefix='wreq-capture-') as temp:
        temp = pathlib.Path(temp)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-keyout', str(temp/'key.pem'), '-out', str(temp/'cert.pem'),
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'],
                       check=True, capture_output=True)
        pubkey = subprocess.run(['openssl', 'x509', '-in', str(temp/'cert.pem'), '-pubkey', '-noout'], check=True, capture_output=True).stdout
        der = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=pubkey, check=True, capture_output=True).stdout
        import base64
        spki = base64.b64encode(hashlib.sha256(der).digest()).decode()
        servers = []
        for protocol in ('h2', 'http/1.1'):
            collector = Collector(protocol)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(temp/'cert.pem', temp/'key.pem')
            ctx.set_alpn_protocols([protocol])
            server = await asyncio.start_server(collector.connection, '127.0.0.1', 0, ssl=ctx)
            collector.port = server.sockets[0].getsockname()[1]
            collectors.append(collector)
            servers.append(server)
        flags = ['--no-proxy-server', f'--ignore-certificate-errors-spki-list={spki}']
        if args.no_sandbox:
            flags.append('--no-sandbox')
        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch_persistent_context(
                    str(temp/'profile'), executable_path=args.browser, headless=args.headless,
                    args=flags, ignore_default_args=['--enable-automation'], no_viewport=True)
                page = browser.pages[0]
                for c in collectors:
                    base = f'https://localhost:{c.port}'
                    cross = f'https://127.0.0.1:{c.port}'
                    await page.goto(base+'/navigation')
                    await page.click('#link')
                    await page.goto(base+'/redirect')
                    await page.goto(base+'/resources')
                    await page.evaluate('''async cross => {
                        const load = (tag, attr, url, props={}) => new Promise(resolve => {
                            const el = document.createElement(tag); Object.assign(el, props);
                            el.onload = el.onerror = resolve; el[attr] = url; document.head.append(el);
                        });
                        await load('script','src','/script.js');
                        await load('link','href','/style.css',{rel:'stylesheet'});
                        await load('img','src','/image.svg');
                        try { await new FontFace('capture', 'url(/font.woff2)').load(); } catch {}
                        await fetch('/fetch');
                        await fetch('/post', {method:'POST',body:'hello',headers:{'Content-Type':'text/plain'}});
                        await fetch(cross+'/cross-fetch');
                        await load('script','src',cross+'/cross-script.js');
                    }''', cross)
                    await page.goto(base+'/hints')
                    await page.evaluate("fetch('/after-hints')")
                identity = await page.evaluate('''async () => ({user_agent:navigator.userAgent,
                    platform:navigator.platform, language:navigator.language, languages:navigator.languages,
                    hints:await navigator.userAgentData.getHighEntropyValues(['architecture','bitness','platformVersion','fullVersionList','model','wow64','uaFullVersion'])})''')
                session = await browser.new_cdp_session(page)
                version = await session.send('Browser.getVersion')
                await browser.close()
        finally:
            for server in servers:
                server.close()
                await server.wait_closed()
        result = {'schema_version': 1, 'browser': args.product, 'platform': {'Darwin':'macos','Windows':'windows','Linux':'linux'}[platform.system()],
                  'verification': 'native', 'captured_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'browser_version': version, 'identity': identity,
                  'installation': installation,
                  'environment': {'os': platform.platform(), 'architecture': platform.machine(),
                                  'headless': args.headless, 'flags': flags, 'automation': 'playwright persistent context; no UA/header overrides'},
                  'captures': [{'protocol': c.protocol, 'connections': c.connections, 'requests': c.requests} for c in collectors]}
        build = version['product'].split('/')[-1]
        arch = {'amd64':'x86_64','aarch64':'arm64'}.get(platform.machine().lower(), platform.machine().lower())
        expected_brand = {'brave':'Brave', 'chrome':'Google Chrome', 'edge':'Microsoft Edge'}[args.product]
        if expected_brand not in [b['brand'] for b in identity['hints']['brands']]:
            raise ValueError(f'browser identity does not match requested product: {identity}')
        mode_suffix = '-headless' if args.headless else ''
        path = output / f'{args.product}-{build}-{result["platform"]}-{arch}{mode_suffix}.raw.json'
        if path.exists() and not args.replace:
            raise FileExistsError(f'{path} already exists; use --replace for an intentional recapture')
        path.write_text(json.dumps(result, indent=2)+'\n')
        print(path)
        print([(c.protocol, len(c.requests)) for c in collectors])

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--browser')
    parser.add_argument('--installation', help='JSON provenance emitted by install.py')
    parser.add_argument('--replace', action='store_true')
    parser.add_argument('--product', choices=['chrome','brave','edge'], required=True)
    parser.add_argument('--output', default=str(pathlib.Path(__file__).resolve().parents[1]/'fixtures'))
    parser.add_argument('--headless', action='store_true')
    parser.add_argument('--no-sandbox', action='store_true')
    asyncio.run(capture(parser.parse_args()))
