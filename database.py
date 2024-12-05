from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import os

DATABASE = os.environ.get("DATABASE")

Base = declarative_base()


class User(Base):
    __tablename__ = "blog_user"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    roles = relationship("Role", secondary="blog_user_role")


class Role(Base):
    __tablename__ = "blog_role"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    users = relationship("User", secondary="blog_user_role")


class UserRole(Base):
    __tablename__ = "blog_user_role"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("blog_user.id"))
    role_id = Column(Integer, ForeignKey("blog_role.id"))


class Post(Base):
    __tablename__ = "post"

    id = Column(Integer, primary_key=True)
    title = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    author_id = Column(Integer, ForeignKey("blog_user.id"), nullable=False)
    create_datetime = Column(DateTime, nullable=False)
    update_datetime = Column(DateTime, nullable=False)
    author = relationship("User")
    tags = relationship("Tag", secondary="post_tag")
    comments = relationship("Comment")


class Tag(Base):
    __tablename__ = "tag"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    posts = relationship("Post", secondary="post_tag")


class PostTag(Base):
    __tablename__ = "post_tag"

    id = Column(Integer, primary_key=True)
    post_id = Column(Integer, ForeignKey("post.id"))
    tag_id = Column(Integer, ForeignKey("tag.id"))


class Comment(Base):
    __tablename__ = "comment"

    id = Column(Integer, primary_key=True)
    content = Column(String, nullable=False)
    post_id = Column(Integer, ForeignKey("post.id"))
    user_id = Column(Integer, ForeignKey("blog_user.id"))
    post = relationship("Post")
    user = relationship("User")


from sqlalchemy import create_engine

engine = create_engine(DATABASE)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

if __name__ == "__main__":
    Base.metadata.create_all(engine)

    with SessionLocal() as session:
        admin_role = Role(name="admin")
        author_role = Role(name="author")
        reader_role = Role(name="reader")

        session.add_all([admin_role, author_role, reader_role])
        session.commit()
