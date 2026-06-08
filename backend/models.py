from pydantic import BaseModel
from enum import Enum


class InputType(str, Enum):
    email = "email"
    number = "phone"

class AnalyzeRequest(BaseModel):
    text: str
    input_type: InputType

class CheckResult(BaseModel):
    name: str
    passed: bool
    score: int
    detail: str

class AnalyzeResponse(BaseModel):
    verdict: str
    total_score: int
    checks: list[CheckResult]
