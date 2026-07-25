from typing import Literal

from pydantic import BaseModel, Field


class DriftReview(BaseModel):
    action: Literal["investigate", "approve_adaptation", "reject_change", "dismiss"]
    comment: str = Field(default="", max_length=2000)
