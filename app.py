from fastapi import FastAPI, HTTPException, Depends, Query
from models import (
    UserModel,
    RefreshTokenRequest,
    PostModel,
    PostUpdateModel,
    CommentModel,
)
from database import SessionLocal, User, Role, Post, Tag, Comment
from utils import (
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
    decode_token,
    is_admin,
    is_author,
    get_current_user,
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

    with SessionLocal() as session:
        session.expire_on_commit = False

        current_user = get_current_user(session, token)
        user_id = current_user.id

        if is_admin(session, current_user.username) or is_author(
            session, current_user.username
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

            return {"message": "Post created successfully.", "post_id": new_post.id}
        else:
            raise HTTPException(
                status_code=401, detail="You are a reader and cannot create posts."
            )


@app.get("/post", summary="List posts")
def list_posts(
    page: int = 1,
    tags: str = Query("", description="comma-separated tags"),
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


@app.put("/post/{post_id}", summary="Update a post")
def update_post(
    post_data: PostUpdateModel,
    post_id: int,
    token: str = Depends(oauth2_scheme),
):
    with SessionLocal() as session:
        post = session.query(Post).filter(Post.id == post_id).first()
        if not post:
            raise HTTPException(status_code=404, detail="Post not found")

        current_user = get_current_user(session, token)

        if not is_admin(session, current_user.username) and not (
            is_author(session, current_user.username) and post.author == current_user
        ):
            raise HTTPException(
                status_code=401, detail="You do not have access to edit this post."
            )

        if post_data.title is not None:
            post.title = post_data.title

        if post_data.content is not None:
            post.content = post_data.content

        if post_data.tags is not None:
            new_tag_names = set(post_data.tags)
            current_tag_names = {tag.name for tag in post.tags}

            tags_to_add = new_tag_names - current_tag_names
            tags_to_remove = current_tag_names - new_tag_names

            post.tags = [tag for tag in post.tags if tag.name not in tags_to_remove]

            for tag_name in tags_to_add:
                tag_obj = session.query(Tag).filter(Tag.name == tag_name).first()
                if not tag_obj:
                    tag_obj = Tag(name=tag_name)
                    session.add(tag_obj)
                post.tags.append(tag_obj)

        session.commit()

        return {"message": "Post updated successfully", "post_id": post.id}


@app.delete("/post/{post_id}", summary="Delete a post with its ID")
def delete_post(
    post_id: int,
    token: str = Depends(oauth2_scheme),
):
    with SessionLocal() as session:
        post = session.query(Post).filter(Post.id == post_id).first()
        if not post:
            raise HTTPException(status_code=404, detail="Post not found")

        current_user = get_current_user(session, token)

        if not is_admin(session, current_user.username) and not (
            is_author(session, current_user.username) and post.author == current_user
        ):
            raise HTTPException(
                status_code=401, detail="You do not have access to edit this post."
            )

        post_comments = session.query(Comment).filter(Comment.post_id == post.id).all()
        for comment in post_comments:
            session.delete(comment)
        session.delete(post)
        session.commit()

        return {"message": "Post successfully deleted."}


@app.post("/comment/{post_id}", summary="Comment on a post")
def create_comment(
    post_id: int, comment_data: CommentModel, token: str = Depends(oauth2_scheme)
):
    with SessionLocal() as session:
        post = session.query(Post).filter(Post.id == post_id).first()
        if not post:
            raise HTTPException(status_code=404, detail="Post not found")

        current_user = get_current_user(session, token)

        comment = Comment(
            content=comment_data.content,
            post_id=post_id,
            user_id=current_user.id,
        )
        session.add(comment)
        session.commit()

        return {"message": "Comment created successfully.", "comment_id": comment.id}


@app.get("/comment/{post_id}", summary="List comments for a post")
def list_comments(post_id: int):
    with SessionLocal() as session:
        post = session.query(Post).filter(Post.id == post_id).first()
        if not post:
            raise HTTPException(status_code=404, detail="Post not found")

        comments = session.query(Comment).filter(Comment.post == post).all()
        return comments
