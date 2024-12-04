from pydantic import BaseModel
from datetime import datetime


class UserModel(BaseModel):
    email: str
    password: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class PostModel(BaseModel):
    title: str
    content: str
    tags: list[str]
