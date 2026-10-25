#!/usr/bin/env python3
"""Install an official versioned browser in a user cache; never replace the system browser.
Chrome and Edge accept a milestone or full version; Brave accepts a release such as 1.95.101.
Prints a provenance JSON file path, suitable for capture.py --installation.
"""
import argparse
import gzip
import hashlib
import json
import os
import pathlib
import platform
import re
import subprocess
import urllib.request
import urllib.parse
import zipfile


def read(url):
    return urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent':'wreq-util-capture'}), timeout=120).read()


def install_edge(version, cache):
    """Extract an official Linux stable package; verify its published SHA-256."""
    if platform.system() != 'Linux' or platform.machine().lower() not in ('x86_64', 'amd64'):
        raise ValueError('Edge installer currently supports Linux x86_64 only')
    if not re.fullmatch(r'\d+(?:\.\d+\.\d+\.\d+)?', version):
        raise ValueError('Edge requires a major or full release version')
    source = 'https://packages.microsoft.com/repos/edge/dists/stable/main/binary-amd64/Packages.gz'
    packages = gzip.decompress(read(source)).decode()
    matches = []
    for block in packages.split('\n\n'):
        fields = dict(line.split(': ', 1) for line in block.splitlines()
                      if ': ' in line and not line.startswith(' '))
        release = fields.get('Version', '').split('-')[0]
        if fields.get('Package') == 'microsoft-edge-stable' and (release == version or release.startswith(version + '.')):
            matches.append(fields)
    if not matches:
        raise ValueError('no official Edge stable Linux release for this version')
    package = max(matches, key=lambda p: tuple(map(int, p['Version'].split('-')[0].split('.'))))
    version = package['Version'].split('-')[0]
    download = urllib.parse.urljoin('https://packages.microsoft.com/repos/edge/', package['Filename'])
    if urllib.parse.urlsplit(download).netloc != 'packages.microsoft.com':
        raise ValueError('unexpected Edge package host')
    expected = package['SHA256'].lower()
    if not re.fullmatch(r'[0-9a-f]{64}', expected):
        raise ValueError('invalid published package checksum')
    dest = cache / 'edge' / version / 'linux64-stable'
    dest.mkdir(parents=True, exist_ok=True)
    archive = dest / 'download.deb'
    if not archive.exists():
        temporary = dest / 'download.deb.part'
        with urllib.request.urlopen(download, timeout=120) as response, temporary.open('wb') as output:
            while block := response.read(1024 * 1024): output.write(block)
        temporary.replace(archive)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != expected: raise ValueError('official Edge package checksum mismatch')
    executable = dest / 'opt/microsoft/msedge/msedge'
    if not executable.exists():
        subprocess.run(['dpkg-deb', '-x', str(archive), str(dest)], check=True)
    if not executable.is_file(): raise ValueError('missing Edge executable')
    info = {'distribution':'microsoft-edge-stable', 'product':'edge', 'version':version,
            'platform':'linux64', 'source':source, 'download_url':download,
            'archive_sha256':digest, 'official_checksum_url':source,
            'official_checksum_sha256':expected, 'executable':str(executable.resolve())}
    manifest = dest / 'installation.json'
    manifest.write_text(json.dumps(info, indent=2) + '\n')
    return manifest

def install(product, version, cache):
    if product == 'edge': return install_edge(version, cache)
    system = platform.system()
    arch = platform.machine().lower()
    target = {'Linux':'linux64','Windows':'win64','Darwin':'mac-arm64' if arch in ('arm64','aarch64') else 'mac-x64'}[system]
    if system == 'Linux' and arch not in ('x86_64','amd64'):
        raise ValueError('this installer supports Linux x86_64 only')
    if product == 'chrome':
        if system != 'Linux':
            raise ValueError('historical regular Chrome installer is Linux-only; use an installed official browser with capture.py --browser on Windows/macOS. Chrome for Testing is not an interchangeable reference.')
        if version.isdigit():
            query = f'version>={version},version<{int(version)+1}'
        elif re.fullmatch(r'\d+\.\d+\.\d+\.\d+', version):
            query = f'version={version}'
        else: raise ValueError('invalid Chrome version')
        source = 'https://versionhistory.googleapis.com/v1/chrome/platforms/linux/channels/stable/versions?' + urllib.parse.urlencode({'filter':query})
        versions = json.loads(read(source))['versions']
        if not versions: raise ValueError('no official Linux stable release for this version')
        version = max((v['version'] for v in versions),key=lambda v:tuple(map(int,v.split('.'))))
        download = f'https://dl.google.com/linux/chrome/deb/pool/main/g/google-chrome-stable/google-chrome-stable_{version}-1_amd64.deb'
        checksum_url = None
    else:
        if not re.fullmatch(r'1\.\d+\.\d+', version): raise ValueError('Brave requires a release number, e.g. 1.96.59')
        source = 'https://api.github.com/repos/brave/brave-browser/releases/tags/v'+version
        release = json.loads(read(source))
        if not release['name'].startswith('Release '): raise ValueError('only Brave stable releases are accepted')
        asset = {'Linux':f'brave-browser-{version}-linux-amd64.zip',
                 'Windows':'brave-v'+version+'-win32-x64.zip',
                 'Darwin':'brave-v'+version+('-darwin-arm64.zip' if target=='mac-arm64' else '-darwin-x64.zip')}[system]
        assets = {a['name']:a['browser_download_url'] for a in release['assets']}
        if asset not in assets: raise ValueError(f'official release has no {asset}; available ZIPs: {[s for s in assets if s.endswith(".zip")]}')
        download, checksum_url = assets[asset], assets.get(asset+'.sha256')
    distribution = 'google-chrome-stable' if product == 'chrome' and system == 'Linux' else ('chrome-for-testing' if product == 'chrome' else 'brave-stable')
    dest = cache / product / version / (target+'-stable' if distribution == 'google-chrome-stable' else target)
    manifest = dest/'installation.json'
    if manifest.exists():
        info=json.loads(manifest.read_text())
        if pathlib.Path(info['executable']).is_file(): return manifest
    dest.mkdir(parents=True, exist_ok=True)
    archive=dest/('download.deb' if distribution == 'google-chrome-stable' else 'download.zip')
    if not archive.exists():
        temporary=archive.with_suffix(archive.suffix+'.part')
        with urllib.request.urlopen(urllib.request.Request(download,headers={'User-Agent':'wreq-util-capture'}),timeout=120) as response, temporary.open('wb') as f:
            while block:=response.read(1024*1024): f.write(block)
        temporary.replace(archive)
    digest=hashlib.sha256(archive.read_bytes()).hexdigest()
    if checksum_url:
        expected=read(checksum_url).decode().split()[0].lower()
        if digest!=expected: raise ValueError('official archive checksum mismatch')
    if distribution == 'google-chrome-stable':
        subprocess.run(['dpkg-deb','-x',str(archive),str(dest)],check=True)
    elif system == 'Darwin':
        subprocess.run(['ditto','-x','-k',str(archive),str(dest)],check=True)
    else:
        with zipfile.ZipFile(archive) as z:
            for item in z.infolist():
                output=(dest/item.filename).resolve()
                if not output.is_relative_to(dest.resolve()): raise ValueError('unsafe ZIP member')
                # Chrome for Testing archives contain regular files/directories.
                z.extract(item,dest)
                if system!='Windows' and not item.is_dir():
                    mode=item.external_attr>>16
                    if mode: output.chmod(mode & 0o777)
    if product=='chrome':
        relative={'Linux':'opt/google/chrome/google-chrome','Windows':'chrome-win64/chrome.exe',
                  'Darwin':f'chrome-{target}/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing'}[system]
        executable=dest/relative
    else:
        names={'Linux':['brave'],'Windows':['brave.exe'],'Darwin':['Brave Browser']}[system]
        candidates=[p for p in dest.rglob('*') if p.is_file() and p.name in names]
        if len(candidates)!=1: raise ValueError(f'ambiguous Brave executable: {candidates}')
        executable=candidates[0]
    if not executable.is_file(): raise ValueError(f'missing executable: {executable}')
    if system!='Windows': executable.chmod(executable.stat().st_mode | 0o111)
    info={'distribution':distribution,'product':product,'version':version,'platform':target,'source':source,'download_url':download,
          'archive_sha256':digest,'official_checksum_url':checksum_url,'executable':str(executable.resolve())}
    manifest.write_text(json.dumps(info,indent=2)+'\n')
    return manifest

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('product',choices=['chrome','brave','edge']);p.add_argument('version')
    p.add_argument('--cache',type=pathlib.Path,default=pathlib.Path.home()/'.cache/wreq-capture')
    args=p.parse_args()
    print(install(args.product,args.version,args.cache))
