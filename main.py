import private

import requests
import json

OK = 200
VIRUS_TOTAL_URL = 'https://www.virustotal.com/vtapi/v2/file/report'


def get_text_from_virustotal(hash_file):
    response = None
    text = None
    params = {'apikey': private.api_key, 'resource': hash_file}
    try:
        response = requests.get(VIRUS_TOTAL_URL, params=params)
    except Exception as e:
        print('Could not get response from VirusTotal. Error: {}.'.format(e))
    if response and response.status_code == OK:
        print('Successfully received data from VirusTotal on hash file: {}.'.format(hash_file))
        text = json.loads(response.text)

    return text


def parse_text(text):
    print('Parsing text from VirusTotal.')
    scanned_file = dict()
    results = dict()
    scans = dict()

    scanned_file['MD5'] = text['md5']
    scanned_file['SHA-1'] = text['sha1']
    scanned_file['SHA-256'] = text['sha256']

    results['Total Scans'] = len(text['scans'])

    positive_scans = 0
    for scan_origin, scan_result in text['scans'].items():
        if scan_result['detected']:
            positive_scans += 1
        scans[scan_origin] = scan_result['result']

    results['Positive Scans'] = positive_scans

    return scanned_file, results, scans


def create_md_file(scanned_file, results, scans):
    file_name = 'output.md'
    print('Creating {} file from VirusTotal parsed results.'.format(file_name))
    with open(file_name, 'w+') as md_file:
        create_table(md_file, scanned_file, header='## Scanned File\n')
        create_table(md_file, results, header='## Results\n')
        write_scans_table(md_file, scans)

        return md_file


def create_table(md_file, data, header):
    md_file.write(header)
    header_line = ''
    value_line = ''
    table_line = '| ------ ' * len(data.keys()) + '|\n'
    for key, value in data.items():
        header_line += '| _{}_ '.format(key)
        value_line += '| {} '.format(value)
    md_file.write(header_line + '| \n')
    md_file.write(table_line)
    md_file.write(value_line + '| \n')
    md_file.write('\n')


def write_scans_table(md_file, scans):
    md_file.write('## Scans\n')
    header_line = ' | _Scan Origin_ |  _Scan Result_ | \n'
    table_line = '| ------ | ------ |\n'
    md_file.write(header_line)
    md_file.write(table_line)
    for key, value in scans.items():
        value_line = '| {} | {} | \n'.format(key, value)
        md_file.write(value_line)
    md_file.write('\n')


def run(hash_file):
    markdown_table = None
    if not hash_file:
        print('Error: Can not run on empty hash file.')
    else:
        text = get_text_from_virustotal(hash_file)
        if text:
            scanned_file, results, scans = parse_text(text)
            markdown_file = create_md_file(scanned_file, results, scans)
            with open(markdown_file.name, 'r') as file:
                markdown_table = file.read()
            print('Successfully created markdown table.')
        else:
            print('Could not extract text from VirusTotal response.')

    return markdown_table


if __name__ == '__main__':
    markdown_table = run(private.hash)
    # print(markdown_table)

