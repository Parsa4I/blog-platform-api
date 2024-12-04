from pydantic import BaseModel
from datetime import datetime


class UserModel(BaseModel):
    username: str
    password: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class PostModel(BaseModel):
    title: str
    content: str
    tags: list[str]


class PostUpdateModel(BaseModel):
    title: str = None
    content: str = None
    tags: list[str] = None


class CommentModel(BaseModel):
    content: str
