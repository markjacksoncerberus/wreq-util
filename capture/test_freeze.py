"""Offline integrity and platform-derivation regression tests."""
import hashlib
import json
import pathlib
import unittest
from freeze import freeze, variants

ROOT=pathlib.Path(__file__).resolve().parents[1]

class FreezeTests(unittest.TestCase):
    def test_catalogue_hashes_and_identity_are_consistent(self):
        catalog=json.loads((ROOT/'fixtures/catalog.json').read_text())
        self.assertEqual(len(catalog),len({p['profile_id'] for p in catalog}))
        for entry in catalog:
            source=ROOT/'fixtures'/entry['source_capture']
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),entry['source_sha256'])
            profile=json.loads((ROOT/'fixtures'/entry['fixture']).read_text())
            self.assertEqual(profile['profile_id'],entry['profile_id'])
            for sample in profile['samples']:
                ua=dict((k.lower(),v) for k,v in sample['headers'])['user-agent']
                self.assertEqual(ua,profile['identity']['user_agent'])
            if profile['verification']=='derived':
                self.assertNotIn('sec-ch-ua-platform-version',profile['high_entropy_headers'])
                self.assertNotIn('sec-ch-ua-full-version-list',profile['high_entropy_headers'])

    def test_requested_version_matrix_is_complete(self):
        catalog=json.loads((ROOT/'fixtures/catalog.json').read_text())
        self.assertEqual(len(catalog),54)
        for product, majors in [('chrome',range(148,157)),('brave',range(150,155)),('edge',range(151,155))]:
            entries=[p for p in catalog if p['browser']==product]
            self.assertEqual({int(p['chromium_version'].split('.')[0]) for p in entries},set(majors))
            for major in majors:
                variants=[p for p in entries if p['chromium_version'].startswith(str(major)+'.')]
                self.assertEqual({p['platform'] for p in variants},{'linux','windows','macos'})
                self.assertEqual(sum(p['verification']=='native' for p in variants),1)

    def test_edge_keeps_product_and_chromium_versions_distinct(self):
        catalog=json.loads((ROOT/'fixtures/catalog.json').read_text())
        for entry in [p for p in catalog if p['browser']=='edge']:
            self.assertNotEqual(entry['product_version'],entry['chromium_version'])
            self.assertTrue(entry['profile_id'].startswith('edge-'+entry['product_version']+'-'))
            p=json.loads((ROOT/'fixtures'/entry['fixture']).read_text())
            self.assertIn('Edg/',p['identity']['user_agent'])
            self.assertIn('Microsoft Edge',[b['brand'] for b in p['identity']['hints']['brands']])

    def test_native_other_platform_does_not_get_derived_or_rewritten(self):
        p=freeze(ROOT/'fixtures/chrome-linux.raw.json')
        p['platform']='windows'  # synthetic input, never emitted as evidence
        p['identity']['platform']='Win32'
        output=list(variants(p))
        self.assertEqual(len(output),1)
        self.assertEqual(output[0]['verification'],'native')
        self.assertEqual(output[0]['identity'],p['identity'])

    def test_headless_and_architectures_have_distinct_ids(self):
        p=freeze(ROOT/'fixtures/chrome-linux.raw.json')
        headed=list(variants(p))[0]['profile_id']
        p['capture_mode']='headless'
        self.assertNotEqual(headed,list(variants(p))[0]['profile_id'])
        p['architecture']='arm64'
        output=list(variants(p))
        self.assertEqual(len(output),1)  # Never derive Intel Mac/Windows from ARM Linux.
        self.assertIn('arm64',output[0]['profile_id'])

if __name__=='__main__': unittest.main()
