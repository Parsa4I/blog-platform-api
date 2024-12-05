import jwt
from datetime import datetime, timedelta
import os
import bcrypt
from sqlalchemy.orm import Session
from database import User, Role


SECRET_KEY = os.environ.get("SECRET_KEY")


def create_access_token(subject: dict) -> str:
    for key, value in subject.items():
        subject[key] = str(value)

    if "exp" not in subject:
        subject["exp"] = datetime.utcnow() + timedelta(minutes=60)
    access_token = jwt.encode(subject, SECRET_KEY, "HS256")
    return access_token


def create_refresh_token(subject: dict) -> str:
    for key, value in subject.items():
        subject[key] = str(value)

    if "exp" not in subject:
        subject["exp"] = datetime.utcnow() + timedelta(days=1)
    refresh_token = jwt.encode(subject, SECRET_KEY, "HS256")
    return refresh_token


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, ["HS256"])
    except:
        return None


def hash_password(plain_password: str) -> str:
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(plain_password.encode(), salt)
    return hashed_password.decode()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())


def is_admin(session: Session, username: str) -> bool:
    return (
        session.query(User)
        .join(User.roles)
        .filter(User.username == username, Role.name == "admin")
    ).first() is not None


def is_author(session: Session, username: str) -> bool:
    return (
        session.query(User)
        .join(User.roles)
        .filter(User.username == username, Role.name == "author")
    ).first() is not None


def get_current_user(session: Session, token):
    decoded_token = decode_token(token)
    user_id = decoded_token["sub"]
    return session.query(User).filter(User.id == user_id).first()
