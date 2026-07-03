import httpx
import os
import base64
from models import CheckResult
from checkings.static_rules import extract_url, extract_domain, is_ip_address, strip_port
import asyncio

async def check_virustotal(text: str) -> CheckResult:
    api_key = os.getenv("VIRUS_API_KEY")
    urls = extract_url(text)

    if not urls:
        return CheckResult(name = "virus_total",
                           passed = True,
                           score = 0,
                           detail = "No URLs found to check")

    domain = extract_domain(urls[0])
    domain_id = strip_port(domain)

    endpoint_type = "ip_addresses" if is_ip_address(domain_id) else "domains"

    async with httpx.AsyncClient() as client:
        response = await client.get(f"https://www.virustotal.com/api/v3/{endpoint_type}/{domain_id}",
            headers={"x-apikey": api_key})

    if response.status_code != 200:
            return CheckResult(name = "virus_total",
                               passed = True,
                               score = 0,
                               detail = f"VirusTotal check failed: {response.status_code}")

    data = response.json()
    malicious = (
    data.get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
        .get("malicious", 0)
)

    if malicious > 2:
        return CheckResult(
            name="virus_total",
            passed=False,
            score=40,
            detail=f"Flagged by {malicious} security vendors on VirusTotal"
        )

    return CheckResult(
        name="virus_total",
        passed=True,
        score=0,
        detail=f"Domain appears clean ({malicious} flags on VirusTotal)"
    )

async def check_urlhaus(text: str) -> CheckResult:
    api_key = os.getenv("URL_HAUS_KEY")
    urls = extract_url(text)

    if not urls:
        return CheckResult(name = "urlhaus",
                           passed = True,
                           score = 0,
                           detail = "No URLs found to check")

    try:

        async with httpx.AsyncClient(timeout = 10.0) as client:
           response = await client.post(
               "https://urlhaus-api.abuse.ch/v1/url/",
               data={"url": urls[0]},
               headers={
                    "Auth-Key": api_key,
                    "Content-Type": "application/x-www-form-urlencoded"
                       })


        if response.status_code != 200:
            return CheckResult(name = "urlhaus",
                            passed = True,
                            score = 0,
                            detail = f"URLhaus check failed: {response.status_code}")

        data = response.json()
        query_status = data.get("query_status")

        if query_status == "ok" and data.get("url_status") == "online":
            return CheckResult(
                name="urlhaus",
                passed=False,
                score=50,
                detail="URL is listed as active malware on URLhaus"
            )

        return CheckResult(
            name="urlhaus",
            passed=True,
            score=0,
            detail="URL not found in URLhaus database"
        )

    except Exception as e:

        return CheckResult(name="urlhaus",
                           passed=True,
                           score=0,
                           detail=f"URLhaus error: {str(e)}")


async def url_scan(text: str) -> CheckResult:
    api_key = os.getenv("URL_SCAN_KEY")
    urls = extract_url(text)

    if not urls:
        return CheckResult(name = "url_scan",
                           passed = True,
                           score = 0,
                           detail = "No Url to check")

    url = urls[0]

    try:
        async with httpx.AsyncClient(timeout=10, headers={"API-Key": api_key, "Content-Type": "application/json"}) as client:
            response = await client.post("https://urlscan.io/api/v1/scan/",
                                         json={"url": url, "visibility": "public"})

            if response.status_code == 400:
                error_message = response.json().get("message", "")
                if "blacklisted" in error_message.lower():
                    return CheckResult(name = "url_scan",
                                       passed = False,
                                       score = 45,
                                       detail = "URL is blocked by urlscan.io as is known for malicious infrastructure")

                return CheckResult(name = "url_scan",
                                   passed = True,
                                   score = 0,
                                   detail = f"urlscan.io could not process URL: {error_message}")

            if response.status_code != 200:
                return CheckResult(name = "url_scan",
                                   passed = True,
                                   score = 0,
                                   detail = f"urlscan.io submission failed: {response.status_code}")

            scan = response.json().get("uuid")
            if not scan:
                return CheckResult(name = "url_scan",
                                   passed = True,
                                   score = 0,
                                   detail = "urlscan.io did not return a scan id")

            result_url = f"https://urlscan.io/api/v1/result/{scan}/"

            intervals = [2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5]
            for attempt, wait in enumerate(intervals):
                await asyncio.sleep(wait)
                response = await client.get(result_url)
                if response.status_code == 200:
                    break
            else:
                return CheckResult(name = "url_scan",
                                    passed = True,
                                    score = 0,
                                    detail = "urlscan.io scan did not finish in time")

            data = response.json()
            malicious = data.get("verdicts", {}).get("overall", {}).get("malicious", False)
            matched_brands = data.get("verdicts", {}).get("urlscan", {}).get("brands", [])

            if malicious:
                brand_note = f", impersonating: {', '.join(matched_brands)}" if matched_brands else ""
                return CheckResult(name="url_scan",
                                    passed=False,
                                    score=45,
                                    detail=f"Flagged as malicious by urlscan.io{brand_note}")

        return CheckResult(name="url_scan",
                            passed=True,
                            score=0,
                            detail="No malicious behavior detected by urlscan.io sandbox")

    except Exception as e:
        return CheckResult(name="url_scan",
                           passed=True,
                           score=0,
                           detail=f"urlscan.io error: {str(e)}")


async def run_external_checks(text: str) -> list[CheckResult]:
    vt_result, uh_result, us_result = await asyncio.gather(check_virustotal(text), check_urlhaus(text), url_scan(text))
    return [vt_result, uh_result, us_result]
