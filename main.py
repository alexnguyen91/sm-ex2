#!/usr/bin/env python3

import json
import sys

import requests

BASE_URL='https://quay.io/api/v1'


def err_print(msg):
    print(msg, file=sys.stderr)


def main():
    output = []
    failure = []

    if len(sys.argv) > 1:
        try:
            f = open(sys.argv[1], 'r')
        except Exception as e:
            err_print(e)
            exit(1)
    else:
        f = sys.stdin

    try:
        repos = json.load(f)
    except Exception as e:
        err_print(e)
        exit(1)

    for index, entry in enumerate(repos):
        try:
            org = entry['Organisation']
            repo = entry['Repository']
            tag = entry['Tag']
        except KeyError as e:
            err_print(f'missing key {e} in entry {index}, skip this entry')
            failure.append(entry)
            continue

        try:
            r = requests.get(BASE_URL + f'/repository/{org}/{repo}/tag/', params={'specificTag': tag})
            r.raise_for_status()
            tags_data = r.json()
            for tag in tags_data['tags']:
                digest = tag['manifest_digest']
                entry['Manifest'] = digest
                try:
                    r = requests.get(BASE_URL + f'/repository/{org}/{repo}/manifest/{digest}/security', params={'vulnerabilities': 'true'})
                    r.raise_for_status()
                except Exception as e:
                    err_print(e)
                    continue
                d = r.json()
                entry['Vulnerabilities'] = []
                for pkg in d['data']['Layer']['Features']:
                    for v in pkg['Vulnerabilities']:
                        v['PackageName'] = pkg['Name']
                        entry['Vulnerabilities'].append(v)
                output.append(entry)
        except Exception as e:
            failure.append(entry)
            err_print(e)
            continue

    print(output)

    if failure:
        with open('failure.json', 'w') as f:
            json.dump(failure, f, indent=2)

if __name__ == '__main__':
    main()
