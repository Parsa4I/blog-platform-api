from fastapi import FastAPI, HTTPException, Depends, Query
from models import UserModel, RefreshTokenRequest, PostModel
from database import SessionLocal, User, Role, Post, Tag, UserRole
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
        session.expire_on_commit = False

        if session.query(exists().where(User.username == data.username)).scalar():
            raise HTTPException(status_code=422, detail="Username already exists.")

        if len(data.password) < 8:
            raise HTTPException(
                status_code=422, detail="Password must at least be 8 characters long."
            )

        new_user = User(
            username=data.username,
            password=hash_password(data.password),
        )
        session.add(new_user)
        session.commit()

        reader = session.query(Role).filter(Role.name == "reader").first()
        new_user.roles.append(reader)
        session.commit()

    access_token = create_access_token({"sub": new_user.id})
    refresh_token = create_refresh_token({"sub": new_user.id})

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
    }


@app.post("/token", summary="Get JWT access and refresh tokens")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    with SessionLocal() as session:
        user = session.query(User).filter(User.username == form_data.username).first()

        if user and verify_password(form_data.password, user.password):
            access_token = create_access_token({"sub": user.id})
            refresh_token = create_refresh_token({"sub": user.id})

            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
            }
        else:
            raise HTTPException(status_code=403, detail="Invalid username/password")


@app.post("/refresh_token", summary="Get a new access token")
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


@app.post("/post", summary="Create a new post")
def create_post(post: PostModel, token: str = Depends(oauth2_scheme)):
    title = post.title
    content = post.content
    tags = post.tags

    decoded_token = decode_token(token)
    user_id = decoded_token["sub"]
    with SessionLocal() as session:
        session.expire_on_commit = False

        current_user = session.query(User).filter(User.id == user_id).first()
        author_role = session.query(Role).filter(Role.name == "author").first()
        admin_role = session.query(Role).filter(Role.name == "admin").first()
        if current_user is not None and (
            author_role in current_user.roles or admin_role in current_user.roles
        ):
            new_post = Post(
                title=title,
                content=content,
                author_id=user_id,
                create_datetime=datetime.utcnow(),
                update_datetime=datetime.utcnow(),
            )
            session.add(new_post)
            session.commit()

            for tag in tags:
                if not session.query(exists().where(Tag.name == tag)).scalar():
                    new_tag = Tag(name=tag)
                    session.add(new_tag)
                    session.commit()
                    new_post.tags.append(new_tag)
                    session.commit()
                else:
                    existing_tag = session.query(Tag).where(Tag.name == tag).first()
                    new_post.tags.append(existing_tag)
                    session.commit()

            return new_post
        else:
            raise HTTPException(
                status_code=401, detail="You are a reader and cannot create posts."
            )


@app.get("/post", summary="List posts")
def list_posts(
    page: int = 1,
    tags: str = Query(
        "",
        description="comma-separated tags",
    ),
    author: str = None,
    start_date: str = Query(None, description="Start date in YYYY-MM-DD format"),
    end_date: str = Query(None, description="End date in YYYY-MM-DD format"),
):
    with SessionLocal() as session:
        posts = session.query(Post)
        if tags:
            str_tags = tags.split(",")
            str_tags = list(map(str.strip, str_tags))
            tag_objs = []
            for str_tag in str_tags:
                tag_obj = session.query(Tag).filter(Tag.name == str_tag).first()
                if tag_obj:
                    tag_objs.append(tag_obj)

            posts = (
                posts.join(Post.tags)
                .filter(Tag.id.in_([tag.id for tag in tag_objs]))
                .distinct()
            )

        if author:
            author_objs = (
                session.query(User).filter(User.username.ilike(f"%{author}%")).all()
            )
            authors_ids = [a.id for a in author_objs]
            posts = posts.filter(Post.author_id.in_(authors_ids))

        if start_date:
            try:
                start_datetime = datetime.strptime(start_date, "%Y-%m-%d")
                posts = posts.filter(Post.create_datetime >= start_datetime)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid start_date format")

        if end_date:
            try:
                end_datetime = datetime.strptime(end_date, "%Y-%m-%d")
                posts = posts.filter(Post.create_datetime <= end_datetime)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid end_date format")

        return posts.all()[(page - 1) * 10 : page * 10]
