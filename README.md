# sbom-vulns-python

## Prerequisites
* [Connect your code repos to Prisma Cloud](https://docs.prismacloud.io/en/classic/appsec-admin-guide/get-started/connect-your-repositories/code-repositories/code-repositories)
* Generate [Prisma Cloud Access Key](https://docs.prismacloud.io/en/classic/appsec-admin-guide/get-started/generate-access-keys) and store the values in access-key-credentials.json

## Flags
Required
* --list_repos: JSON output of the repos onboarded to Prisma Cloud. Get the Repo ID
* --top_cvss: JSON output of the highest severity CVE's in a code repo. Must use --repo_id flag.
* --code_issues: Generates SBOM with vulnerabilities. Must use with --repo_id flag. Use --csv flag to generate output file in current directory called "sbom_timestamp.csv"

Optional
* --endpoint: Which Prisma Cloud API endpoint to use (e.g., api2, api.eu, etc). Default value is api.gov

## Example Usage
List code repos:

```python3 prismacloud-sbom-vulns.py --list_repos```

Then copy the repo id you want and store it in an environment variable.

```export REPO_ID=e6af6306-4534-482a-bfd2-fcadb00ed54a```

List the highest severity score CVE's in that repo:

```python3 prismacloud-sbom-vulns.py --top_cvss --repo_id=$REPO_ID```

Generate an SBOM for that repo listing all packages and all vulnerabilities in those packages, and write it to a CSV output file:

```python3 prismacloud-sbom-vulns.py --code_issues --repo_id=$REPO_ID```