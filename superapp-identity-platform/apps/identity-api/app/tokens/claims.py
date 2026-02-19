'''(AED)--> This file defines the AccessTokenClaims model using Pydantic's BaseModel. 
This model represents the claims contained in an access token, including standard 
JWT claims and custom application-specific claims.'''

from pydantic import BaseModel, Field
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