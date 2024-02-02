import requests
import json
import argparse
import os
import time
import copy
import csv

def main():
    parser = argparse.ArgumentParser(
                    prog='Prisma Cloud SBOM / Vuln Helper',
                    description='This script uses the Prisma Cloud API to list top vulnerabilities in source packages',
                    epilog='Copyright 2024 Palo Alto Networks')
    parser.add_argument('--top_cvss', action='store_true')
    parser.add_argument('--list_repos', action='store_true')
    parser.add_argument('--code_issues', action='store_true')
    parser.add_argument('--csv', action='store_true')
    parser.add_argument('--repo_id', default="", type=str)
    parser.add_argument('--endpoint', default='api.gov', type=str)
    args = parser.parse_args()
    base_url = 'https://' + args.endpoint + '.prismacloud.io'

    if args.top_cvss:
        list_top_cvss(base_url)
    if args.list_repos:
        list_repositories(base_url)
    if args.code_issues:
        if args.repo_id == "":
            print("ERROR: must provide value to --repo_id when using the --code_issues flag")
            exit(1)
        list_code_issues(base_url, args.repo_id, args.csv)
    
    

def get_auth_token(base_url, local_token_ttl_seconds=60):
    fetch_new_token = is_token_expired_or_absent(local_token_ttl_seconds)
    if fetch_new_token:
        payload = ""
        with open('access-key-credentials.json', 'r') as file:
            payload = file.read().replace('\n', '')
        url = base_url + '/login'
        headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
        }
        response = requests.request("POST", url, headers=headers, data=payload)
        response_json = json.loads(response.text)
        f = open("auth-token.txt", 'w')
        f.write(response_json["token"])
        f.close()
    
    auth_token = ""
    with open('auth-token.txt', 'r') as file:
        auth_token = file.read()
    return auth_token

def is_token_expired_or_absent(seconds_threshold):
    if not os.path.isfile("auth-token.txt"):
        return True # the auth-token file is absent
    file_last_modified_time = os.path.getmtime("auth-token.txt")
    current_time = time.time()
    if current_time - file_last_modified_time >= seconds_threshold:
        return True
    return False

def list_top_cvss(base_url):
    token = get_auth_token(base_url)
    url = base_url + '/code/api/v2/dashboard/top-cvss'
    payload = json.dumps({
    "repositories": [
        "1f5f51d5-86cb-4482-9aa8-6bd2398e6d5a"
    ],
    "severities": [
        "CRITICAL"#, "HIGH", "MEDIUM", "LOW", "INFO"
    ],
    "size": 0
    })
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'authorization': token
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    response_json = json.loads(response.text)
    for d in response_json["data"]:
        print(d)

def list_repositories(base_url):
    token = get_auth_token(base_url)
    url = base_url + '/code/api/v1/repositories'
    headers = {
    'Accept': 'application/json',
    'authorization': token
    }
    response = requests.request("GET", url, headers=headers)
    response_json = json.loads(response.text)
    print(json.dumps(response_json, indent=2))

def list_code_issues(base_url, repo_id, write_csv_outfile):
    token = get_auth_token(base_url)

    # first, get the list of all packages in this repo
    url = base_url + '/bridgecrew/api/v1/vulnerabilities/packages/search'
    payload = json.dumps({"q":"",
                          "repositories":[repo_id],
                          "statuses":["OPEN"],
                          "include":["fixableErrorCount"],
                          "sortBy":["fixableError"],
                          "filter":{"fixableOnly":False},
                          "limit":100,
                          "offset":0}
                        )
    headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'authorization': token
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    package_json = json.loads(response.text)
    #print(json.dumps(package_json, indent=2))

    # next, for each package, get the list of vulnerabilities
    vuln_list = []
    for p in package_json["packages"]:
        package_id = p["packageId"]
        package_dict = {"packageName": p["packageName"],
                        "packageVersion": p["packageVersion"],
                        "packageLicenses": '|'.join(p["packageLicenses"]),
                        "packageId": p["packageId"]}

        url = base_url + '/code/api/v1/vulnerabilities/packages/' + package_id + '/cves'
        headers = {
        'Accept': 'application/json',
        'authorization': token
        }
        response = requests.request("GET", url, headers=headers)
        vuln_json = json.loads(response.text)
        #print(json.dumps(vuln_json, indent=2))
        for v in vuln_json["data"]:
            vuln_dict = copy.deepcopy(package_dict)
            vuln_dict.update({"cveId": v["cveId"],
                              "cvss": v["cvss"],
                              "cveStatus": v["cveStatus"],
                              "severity": v["severity"],
                              "sourceId": v["sourceId"],
                              "resourceId": v["resourceId"],
                              })
            print(vuln_dict)
            vuln_list.append(vuln_dict)
    
    if write_csv_outfile:
        timestr = time.strftime("%Y%m%d-%H%M%S")
        filename = "sbom_"+timestr+".csv"
        with open(filename, 'w') as csvfile:
            fieldnames = ["packageId",
                          "packageName",
                          "packageVersion",
                          "packageLicenses",
                          "packageId",
                          "cveId",
                          "cvss",
                          "cveStatus",
                          "severity",
                          "sourceId",
                          "resourceId"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for r in vuln_list:
                writer.writerow(r)


if __name__ == '__main__':
    main()