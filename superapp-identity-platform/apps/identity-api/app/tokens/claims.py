'''(AED)--> This file defines the AccessTokenClaims model using Pydantic's BaseModel. 
This model represents the claims contained in an access token, including standard 
JWT claims and custom application-specific claims.'''

from pydantic import BaseModel, Field, ValidationError, model_validator
from typing import List, Optional, Union

class AccessTokenClaims(BaseModel):
    iss: str
    sub: str
    aud: Union[str, List[str]]
    exp: int
    iat: int
    jti: str

    scope: str
    sid: str
    cid: str
    device_id: Optional[str] = None

    acr: str = "1"
    amr: List[str] = Field(default_factory=list)

    roles: List[str] = Field(default_factory=lambda: ["user"])
    tenant: Optional[str] = None
    ver: int = 1

    @model_validator(mode="before")
    def _normalize_aud(cls, values):
        # Ensure audience is always a list
        aud = values.get("aud")
        if isinstance(aud, str):
            values["aud"] = [aud]
        return values

    @model_validator(mode="after")
    def _post_checks(self):
        # roles must not be empty
        if not self.roles:
            raise ValidationError([{"loc": ("roles",), "msg": "roles must not be empty", "type": "value_error"}], model=type(self))
        # acr should be a string numeric value
        if not isinstance(self.acr, str) or not self.acr.isnumeric():
            raise ValidationError([{"loc": ("acr",), "msg": "acr must be numeric string", "type": "value_error"}], model=type(self))
        return self