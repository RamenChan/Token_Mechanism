'''(AED)--> This file defines the Pydantic models for the authentication endpoints of the SuperApp Identity Platform.
It includes input models for user registration and login, as well as an output model for the issued
tokens. These models are used for request validation and response serialization in the authentication API.
'''
from pydantic import BaseModel, Field

class RegisterIn(BaseModel):
    username: str
    password: str

class LoginIn(BaseModel):
    username: str
    password: str
    device_id: str = Field(min_length=6)
    client_id: str = "mobile"

class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int
    acr: str