from fastapi import FastAPI, HTTPException, Depends
from models import UserModel, RefreshTokenRequest
from database import SessionLocal, User
import re
from utils import (
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
    decode_token,
)
from sqlalchemy import exists
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime


app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@app.post("/signup", summary="Create new user")
def create_user(data: UserModel):
    with SessionLocal() as session:
        if not re.match(r"[^@]+@[^@]+\.[^@]+", data.email):
            raise HTTPException(status_code=422, detail="Invalid email address")

        if session.query(exists().where(User.email == data.email)).scalar():
            raise HTTPException(status_code=422, detail="Email already exists.")

        if len(data.password) < 8:
            raise HTTPException(
                status_code=422, detail="Password must at least be 8 characters long."
            )

        new_user = User(
            email=data.email,
            password=hash_password(data.password),
        )
        session.add(new_user)
        session.commit()
        session.refresh(new_user)

    access_token = create_access_token({"sub": new_user.id})
    refresh_token = create_refresh_token({"sub": new_user.id})

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
    }


@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    with SessionLocal() as session:
        user = session.query(User).filter(User.email == form_data.username).first()

        if user and verify_password(form_data.password, user.password):
            access_token = create_access_token({"sub": user.id})
            refresh_token = create_refresh_token({"sub": user.id})

            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
            }
        else:
            raise HTTPException(status_code=403, detail="Invalid email/password")


@app.post("/refresh_token")
def refresh_token(refresh_token_request: RefreshTokenRequest):
    decoded_token = decode_token(refresh_token_request.refresh_token)
    if (
        decoded_token is not None
        and datetime.fromtimestamp(decoded_token["exp"]) > datetime.utcnow()
    ):
        user_id = decoded_token["sub"]
        access_token = create_access_token({"sub": user_id})
        return {"access_token": access_token}
    raise HTTPException(status_code=403, detail="Invalid token")
