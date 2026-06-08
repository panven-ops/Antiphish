import httpx
import os
import base64
from models import CheckResult
from checkings.static_rules import extract_url, extract_domain
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
    domain_id = domain

    async with httpx.AsyncClient() as client:
        response = await client.get(f"https://www.virustotal.com/api/v3/domains/{domain_id}",
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
            name="virustotal",
            passed=False,
            score=40,
            detail=f"Flagged by {malicious} security vendors on VirusTotal"
        )

    return CheckResult(
        name="virustotal",
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

        if query_status == "is_listed" and data.get("url_status") == "online":
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

async def run_external_checks(text: str) -> list[CheckResult]:
    vt_result, uh_result = await asyncio.gather(check_virustotal(text), check_urlhaus(text))
    return [vt_result, uh_result]
