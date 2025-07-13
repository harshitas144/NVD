import requests
import time

NVD_API_KEY = "67c8425c-18c0-4bbe-bee7-818174cd122f"

def normalize_product(product):
    """
    Maps raw product names to more effective search terms for NVD.
    """
    product = product.lower().strip()
    alias_map = {
        "apache httpd": "apache",
        "httpd": "apache",
        "openssh": "openssh",
        "mysql server": "mysql",
    }
    return alias_map.get(product, product)

def clean_version(version):
    """
    Truncates extra suffixes like '7.9p1' -> '7.9'
    """
    return version.split('p')[0].strip()

def search_cves(product, version):
    product = normalize_product(product)
    version = clean_version(version)
    results = []

    def query_nvd(keyword):
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {"apiKey": NVD_API_KEY}
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 5,
            "startIndex": 0
        }
        response = requests.get(url, headers=headers, params=params)
        if response.status_code != 200:
            print(f"❌ NVD request failed: {response.status_code}")
            return []
        return response.json().get("vulnerabilities", [])

    # Primary search: product + version
    keyword = f"{product} {version}"
    print(f"🔍 Searching NVD for: '{keyword}'")
    vulnerabilities = query_nvd(keyword)

    # Fallback search: only product
    if not vulnerabilities:
        keyword = product
        print(f"⚠️ No CVEs found. Retrying with: '{keyword}'")
        vulnerabilities = query_nvd(keyword)

    # Parse results
    for item in vulnerabilities:
        cve = item["cve"]
        cve_id = cve["id"]
        description = cve["descriptions"][0]["value"]
        cvss_data = cve.get("metrics", {}).get("cvssMetricV31", [])
        if cvss_data:
            score = cvss_data[0]["cvssData"]["baseScore"]
            severity = cvss_data[0]["cvssData"]["baseSeverity"]
        else:
            score, severity = "N/A", "N/A"

        results.append({
            "cve_id": cve_id,
            "description": description,
            "score": score,
            "severity": severity
        })

    print(f"✅ Found {len(results)} CVEs for '{product} {version}'")
    time.sleep(1)  # avoid API rate-limiting
    return results

