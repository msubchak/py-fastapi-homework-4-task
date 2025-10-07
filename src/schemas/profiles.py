from datetime import date
from typing import Optional
from pydantic import BaseModel, Field, field_validator
from pydantic import ConfigDict

from validation import validate_name, validate_gender, validate_birth_date


class ProfileCreateSchema(BaseModel):
    first_name: str = Field(..., max_length=50)
    last_name: str = Field(..., max_length=50)
    gender: Optional[str] = Field(None)
    date_of_birth: Optional[date]
    info: str = Field(..., max_length=500)

    model_config = ConfigDict(from_attributes=True)

    @field_validator("first_name", "last_name")
    @classmethod
    def validate_names(cls, value):
        return validate_name(value)

    @field_validator("gender")
    @classmethod
    def check_gender(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        return validate_gender(value)

    @field_validator("date_of_birth")
    @classmethod
    def check_date_of_birth(cls, value: Optional[date]) -> Optional[date]:
        if value is None:
            return value
        return validate_birth_date(value)

    @field_validator("info")
    @classmethod
    def validate_info(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Info field cannot be empty or contain only spaces.")
        return value


class ProfileResponseSchema(BaseModel):
    id: int
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    gender: Optional[str] = None
    date_of_birth: Optional[date] = None
    info: Optional[str] = None
    avatar: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
