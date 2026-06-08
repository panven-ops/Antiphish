from checkings.static_rules import run_static_checks
from models import AnalyzeRequest, AnalyzeResponse, CheckResult
from checkings.external_apis import run_external_checks
import asyncio


SCORE_THRESHOLDS = {
    "safe": 20,
    "suspicious": 50,
}


def calculate_verdict(score: int) -> str:

    if score <= SCORE_THRESHOLDS["safe"]:
        return "safe"

    elif SCORE_THRESHOLDS["safe"] < score <= SCORE_THRESHOLDS["suspicious"]:
        return "suspicious"

    return "dangerous"

def aggregate_score(checks: list[CheckResult]) -> int:

    return sum(check.score for check in checks)


async def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    if request.input_type == "phone":
        static_check = await asyncio.to_thread(run_static_checks, request.text, request.input_type)
        all_checks = static_check
    else:

        static_check, external_check = await asyncio.gather(asyncio.to_thread(run_static_checks, request.text, request.input_type),
                                                        run_external_checks(request.text))
        all_checks = static_check + external_check
    total_score = min(aggregate_score(all_checks), 100)
    verdict = calculate_verdict(total_score)

    return AnalyzeResponse(verdict = verdict,
                           total_score = total_score,
                           checks = all_checks)
