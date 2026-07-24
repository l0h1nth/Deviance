from typing import Literal

from pydantic import BaseModel, Field


AlertStatus = Literal["open", "investigating", "confirmed_threat", "false_positive", "closed"]


class AlertUpdate(BaseModel):
    status: AlertStatus
    analyst: str = Field(min_length=1, max_length=100)
    comment: str = Field(default="", max_length=2000)

