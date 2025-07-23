#!/usr/bin/env python

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from string import Template
from subprocess import run
from tempfile import TemporaryDirectory
import urllib.request

from packaging.version import Version


def sync_db():
    run(['esp-idf-sbom', 'sync-db'])


def check(path: Path) -> dict:
    tmp_dir = TemporaryDirectory()
    tmp_dir_path = Path(tmp_dir.name)
    json_file_path = tmp_dir_path / 'output.json'

    run(['esp-idf-sbom',
         'manifest',
         'check',
         '--local-db',
         '--extended-scan',
         '--no-sync-db',
         '--format',
         'json',
         '--output-file',
         str(json_file_path),
         str(path)])

    with json_file_path.open("r", encoding="utf-8") as f:
        report = json.load(f)

    return report


def check_repository(repo: str, ref: str) -> dict:
    tmp_dir = TemporaryDirectory()
    tmp_dir_path = Path(tmp_dir.name)

    run(['git', 
         'clone',
         '--no-tags',
         '--depth=1',
         '--recurse-submodules',
         '--shallow-submodules',
         '--branch', ref,
         repo,
         str(tmp_dir_path)])

    report = check(tmp_dir_path)

    return report


def check_manifest(url: str) -> dict:
    tmp_dir = TemporaryDirectory()
    tmp_dir_path = Path(tmp_dir.name)
    manifest_path = tmp_dir_path / 'manifest.yml'

    urllib.request.urlretrieve(url, manifest_path)

    report = check(manifest_path)

    return report


sync_db()

ESP_IDF_REPO = 'https://github.com/espressif/esp-idf.git'
IDF_EXTRA_COMPONENTS_REPO = 'https://github.com/espressif/idf-extra-components.git'
RELEASED_MANIFEST_URL = 'https://raw.githubusercontent.com/espressif/esp-idf-sbom/refs/heads/master/aggregated_manifests'

reports = {
    'v6.0-next': check_repository(ESP_IDF_REPO, 'master'),
    'v5.5-next': check_repository(ESP_IDF_REPO, 'release/v5.5'),
    'v5.4-next': check_repository(ESP_IDF_REPO, 'release/v5.4'),
    'v5.3-next': check_repository(ESP_IDF_REPO, 'release/v5.3'),
    'v5.2-next': check_repository(ESP_IDF_REPO, 'release/v5.2'),
    'v5.1-next': check_repository(ESP_IDF_REPO, 'release/v5.1'),

    'extra-components': check_repository(IDF_EXTRA_COMPONENTS_REPO, 'master'),

    'v5.5.0': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.5.yml'),
    'v5.4.1': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.4.1.yml'),
    'v5.4.0': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.4.yml'),
    'v5.3.3': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.3.3.yml'),
    'v5.3.2': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.3.2.yml'),
    'v5.3.1': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.3.1.yml'),
    'v5.3.0': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.3.yml'),
    'v5.2.5': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.2.5.yml'),
    'v5.2.4': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.2.4.yml'),
    'v5.2.3': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.2.3.yml'),
    'v5.2.2': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.2.2.yml'),
    'v5.2.1': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.2.1.yml'),
    'v5.2.0': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.2.yml'),
    'v5.1.6': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.1.6.yml'),
    'v5.1.5': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.1.5.yml'),
    'v5.1.4': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.1.4.yml'),
    'v5.1.3': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.1.3.yml'),
    'v5.1.2': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.1.2.yml'),
    'v5.1.1': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.1.1.yml'),
    'v5.1.0': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.1.yml'),
    'v5.0.8': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.0.8.yml'),
    'v5.0.7': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.0.7.yml'),
    'v5.0.6': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.0.6.yml'),
    'v5.0.5': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.0.5.yml'),
    'v5.0.4': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.0.4.yml'),
    'v5.0.3': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.0.3.yml'),
    'v5.0.2': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.0.2.yml'),
    'v5.0.1': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.0.1.yml'),
    'v5.0.0': check_manifest(f'{RELEASED_MANIFEST_URL}/v5.0.yml'),
    'v4.4.8': check_manifest(f'{RELEASED_MANIFEST_URL}/v4.4.8.yml'),
    'v4.4.7': check_manifest(f'{RELEASED_MANIFEST_URL}/v4.4.7.yml'),
    'v4.4.6': check_manifest(f'{RELEASED_MANIFEST_URL}/v4.4.6.yml'),
    'v4.4.5': check_manifest(f'{RELEASED_MANIFEST_URL}/v4.4.5.yml'),
    'v4.4.4': check_manifest(f'{RELEASED_MANIFEST_URL}/v4.4.4.yml'),
    'v4.4.3': check_manifest(f'{RELEASED_MANIFEST_URL}/v4.4.3.yml'),
    'v4.4.2': check_manifest(f'{RELEASED_MANIFEST_URL}/v4.4.2.yml'),
    'v4.4.1': check_manifest(f'{RELEASED_MANIFEST_URL}/v4.4.1.yml'),
    'v4.4.0': check_manifest(f'{RELEASED_MANIFEST_URL}/v4.4.yml'),
    'v4.3.7': check_manifest(f'{RELEASED_MANIFEST_URL}/v4.3.7.yml'),
    'v4.3.6': check_manifest(f'{RELEASED_MANIFEST_URL}/v4.3.6.yml'),
    'v4.3.5': check_manifest(f'{RELEASED_MANIFEST_URL}/v4.3.5.yml'),
    'v4.3.4': check_manifest(f'{RELEASED_MANIFEST_URL}/v4.3.4.yml'),
    'v4.3.3': check_manifest(f'{RELEASED_MANIFEST_URL}/v4.3.3.yml'),
    'v4.3.2': check_manifest(f'{RELEASED_MANIFEST_URL}/v4.3.2.yml'),
    'v4.3.1': check_manifest(f'{RELEASED_MANIFEST_URL}/v4.3.1.yml'),
    'v4.3.0': check_manifest(f'{RELEASED_MANIFEST_URL}/v4.3.yml'),
}

rows = []
for release, report in reports.items():
    for record in report['records']:
        if record['vulnerable'] not in ('YES', 'NO', 'EXCLUDED', 'MAYBE'):
            continue

        cve_id = record['cve_id']
        cve_link = record['cve_link']
        cve_href = f'<a href="{cve_link}">{cve_id}</a>'

        description = '<p>' + record['cve_desc'] + '</p>'
        if record['vulnerable'] == 'EXCLUDED':
            description += '<p>Not Applicable: ' + record['exclude_reason'] + '</p>'

        row = {
            'release': release,
            'cve': cve_href,
            'vulnerable': record['vulnerable'],
            'severity': record['cvss_base_severity'],
            'package': record['pkg_name'],
            'version': record['pkg_version'],
            'description': description
        }

        rows.append(row)

page_templ_path = Path(__file__).resolve().parent / 'docs' / 'page.html.templ'
with page_templ_path.open("r", encoding="utf-8") as f:
    index_data = f.read()

formatted = Template(index_data).safe_substitute(
        {
            'rows': rows,
            'datetime': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        })

index_path = Path(__file__).resolve().parent / 'docs' / 'index.html'
with index_path.open("w", encoding="utf-8") as f:
    f.write(formatted)
