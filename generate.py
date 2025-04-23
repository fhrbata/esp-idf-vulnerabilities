#!/usr/bin/env python

import json
import sys
from pathlib import Path
from string import Template
from subprocess import run
from tempfile import TemporaryDirectory

from packaging.version import Version


def sync_db():
    run(['esp-idf-sbom', 'sync-db'])


def get_releases() -> dict:
    releases = {}
    releases_path = Path(__file__).resolve().parent / 'releases'
    manifest_files = releases_path.glob('*.yml')
    for manifest_file in manifest_files:
        releases[manifest_file.stem] = {'manifest': str(manifest_file)}

    return dict(sorted(releases.items(), key=lambda item: Version(item[0]),
                       reverse=True))


def check_releases(releases: dict) -> dict:
    tmp_dir = TemporaryDirectory()
    tmp_dir_path = Path(tmp_dir.name)

    for release, data in releases.items():
        print(f'scanning {release}', file=sys.stderr)
        manifest = data['manifest']
        json_file_path = (tmp_dir_path / release).with_suffix('.json')
        run(['esp-idf-sbom',
             'manifest',
             'check',
             '--local-db',
             '--no-sync-db',
             '--format',
             'json',
             '--output-file',
             str(json_file_path),
             manifest])

        with json_file_path.open("r", encoding="utf-8") as f:
            data['report'] = json.load(f)

    return releases


def generate_summary_page(releases: dict):
    content = '''<p>
    This page lists known vulnerabilities affecting the released versions of ESP-IDF.
    Additional insights into known vulnerabilities can be found in the
    <a href="https://docs.espressif.com/projects/esp-idf/en/latest/esp32/security/vulnerabilities.html">Vulnerabilities</a>
    page of the ESP-IDF Programming Guide.
    </p>'''

    content += '''
    <table class="summary-table">
            <tr>
                <th>Release</th>
                <th>Vulnerable</th>
                <th>CVE</th>
                <th>Severity</th>
                <th>Package</th>
                <th>Version</th>
            </tr>
            '''

    odd = False
    for release, data in releases.items():
        release_href = f'<a href="{release}.html">{release}</a>'
        odd = not odd
        row_bg = 'odd' if odd else 'even'
        records = data['report']['records']
        vulnerable_records = []
        for record in records:
            if record['vulnerable'] == 'YES':
                vulnerable_records.append(record)

        vulnerabilities_nr = len(vulnerable_records)

        if vulnerabilities_nr == 0:
            vulnerable = '<div class="green">no</div>'
            content += f'''
            <tr class={row_bg}>
                <td class="center">{release_href}</td>
                <td class="center">{vulnerable}</td>
                <td class="center"></td>
                <td class="center"></td>
                <td class="center"></td>
                <td class="center"></td>
            </tr>
            '''
            continue

        if vulnerabilities_nr == 1:
            vulnerable = '<div class="red">yes</div>'
            record = vulnerable_records[0]
            cve_id = record['cve_id']
            cve_link = record['cve_link']
            cve_href = f'<a href="{cve_link}">{cve_id}</a>'
            cve_severity = record['cvss_base_severity'].lower()
            package = record['pkg_name']
            package_ver = record['pkg_version']
            content += f'''
            <tr class={row_bg}>
                <td class="center">{release_href}</td>
                <td class="center">{vulnerable}</td>
                <td class="center">{cve_href}</td>
                <td class="center">{cve_severity}</td>
                <td class="center">{package}</td>
                <td class="center">{package_ver}</td>
            </tr>
            '''
            continue

        vulnerable = '<div class="red">yes</div>'

        content += f'''
            <tr class={row_bg}>
                <td rowspan="{vulnerabilities_nr + 1}" class="center">{release_href}</td>
                <td rowspan="{vulnerabilities_nr + 1}" class="center">{vulnerable}</td>
                <td class="center"></td>
                <td class="center"></td>
                <td class="center"></td>
                <td class="center"></td>
            </tr>
            '''

        for record in vulnerable_records:
            cve_id = record['cve_id']
            cve_link = record['cve_link']
            cve_href = f'<a href="{cve_link}">{cve_id}</a>'
            cve_severity = record['cvss_base_severity'].lower()
            package = record['pkg_name']
            package_ver = record['pkg_version']
            content += f'''
            <tr class={row_bg}>
                <td class="center">{cve_href}</td>
                <td class="center">{cve_severity}</td>
                <td class="center">{package}</td>
                <td class="center">{package_ver}</td>
            </tr>
            '''

    content += '''
    </table>
    '''

    page_templ_path = Path(__file__).resolve().parent / 'docs' / 'page.html.templ'
    with page_templ_path.open("r", encoding="utf-8") as f:
        index_data = f.read()

    formatted = Template(index_data).safe_substitute({'content': content})

    index_path = Path(__file__).resolve().parent / 'docs' / 'index.html'
    with index_path.open("w", encoding="utf-8") as f:
        f.write(formatted)


def generate_release_page(release: str, data: dict):
    content = f'''
    <h3>{release}</h3>
    <table class="release-table">
    '''

    def add_tag_value_row(tag: str, value: str, bg: str):
        nonlocal content
        content += f'<tr class={bg}><td>{tag}:</td><td>{value}</td></tr>\n'

    records = data['report']['records']
    vulnerable_records = []
    for record in records:
        if record['vulnerable'] in ('YES', 'EXCLUDED'):
            vulnerable_records.append(record)

    odd = False
    for record in vulnerable_records:
        odd = not odd
        row_bg = 'odd' if odd else 'even'

        content += f'<tr class={row_bg}><td></td><td></td></tr>\n'

        cve_id = record['cve_id']
        cve_link = record['cve_link']
        cve_href = f'<a href="{cve_link}">{cve_id}</a>'
        add_tag_value_row('ID', cve_href, row_bg)

        if record['vulnerable']  == 'YES':
            add_tag_value_row('Vulnerable', '<div class="red">yes</div>', row_bg)
        else:
            add_tag_value_row('Vulnerable', '<div class="green">no</div>', row_bg)
            add_tag_value_row('Not Applicable', record['exclude_reason'], row_bg)

        add_tag_value_row('Package', record['pkg_name'], row_bg)
        add_tag_value_row('Package Version', record['pkg_version'], row_bg)

        add_tag_value_row('CVSS Version', record['cvss_version'], row_bg)
        add_tag_value_row('CVSS Score', record['cvss_base_score'], row_bg)
        add_tag_value_row('CVSS Severity', record['cvss_base_severity'], row_bg)
        add_tag_value_row('CVSS Vector String', record['cvss_vector_string'], row_bg)

        add_tag_value_row('CPE', record['cpe'], row_bg)
        add_tag_value_row('Description', record['cve_desc'], row_bg)

        content += f'<tr class={row_bg}><td></td><td></td></tr>\n'

    content += '''
    </table>
    '''

    page_templ_path = Path(__file__).resolve().parent / 'docs' / 'page.html.templ'
    with page_templ_path.open("r", encoding="utf-8") as f:
        index_data = f.read()

    formatted = Template(index_data).safe_substitute({'content': content})

    index_path = Path(__file__).resolve().parent / 'docs' / f'{release}.html'
    with index_path.open("w", encoding="utf-8") as f:
        f.write(formatted)


sync_db()
releases = get_releases()
releases = check_releases(releases)
generate_summary_page(releases)
for release, data in releases.items():
    generate_release_page(release, data)
