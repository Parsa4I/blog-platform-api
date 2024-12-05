from app import app, get_db
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, StaticPool
from sqlalchemy.orm import sessionmaker, Session
from database import Base, User
import pytest
from database import Role
from utils import hash_password, create_access_token, create_refresh_token, decode_token


DATABASE = "sqlite:///:memory:"


engine = create_engine(
    DATABASE,
    connect_args={
        "check_same_thread": False,
    },
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

client = TestClient(app)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture()
def create_tables():
    Base.metadata.create_all(engine)
    with TestingSessionLocal() as session:
        admin_role = Role(name="admin")
        author_role = Role(name="author")
        reader_role = Role(name="reader")

        session.add_all([admin_role, author_role, reader_role])
        session.commit()
    yield
    Base.metadata.drop_all(engine)


def create_test_user(session: Session, username: str, password: str):
    new_user = User(
        username=username,
        password=hash_password(password),
    )
    session.add(new_user)
    session.commit()
    return new_user


def test_create_user_success(create_tables):
    response = client.post(
        "/signup/", json={"username": "testuser", "password": "testpass"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    session = TestingSessionLocal()
    user = session.query(User).filter(User.username == "testuser").first()
    assert user is not None
    session.close()


def test_create_user_short_password(create_tables):
    response = client.post(
        "/signup/", json={"username": "testuser", "password": "pass"}
    )
    assert response.status_code == 422


def test_create_user_existing_username(create_tables):
    session = TestingSessionLocal()
    create_test_user(session, "testuser", "testpass")
    response = client.post(
        "/signup/", json={"username": "testuser", "password": "pass"}
    )
    assert response.status_code == 422
    session.close()


def test_login_success(create_tables):
    session = TestingSessionLocal()
    create_test_user(session, "testuser", "testpass")
    response = client.post(
        "/token/", data={"username": "testuser", "password": "testpass"}
    )

    data = response.json()

    assert response.status_code == 200
    assert "access_token" in data
    assert "refresh_token" in data

    session.close()
    return data["access_token"]


def test_login_wrong_password(create_tables):
    session = TestingSessionLocal()
    create_test_user(session, "testuser", "testpass")
    response = client.post(
        "/token/", data={"username": "testuser", "password": "wrongpass"}
    )

    data = response.json()

    assert response.status_code == 403
    assert "access_token" not in data
    assert "refresh_token" not in data

    session.close()


def test_refresh_token(create_tables):
    refresh_token = create_refresh_token({"sub": 1})
    response = client.post("/refresh_token/", json={"refresh_token": refresh_token})

    data = response.json()

    assert response.status_code == 200
    assert "access_token" in data


def test_create_post(create_tables):
    session = TestingSessionLocal()
    test_user = create_test_user(session, "testuser", "testpass")
    session.add(test_user)
    session.commit()
    access_token = create_access_token({"sub": test_user.id})

    author_role = session.query(Role).filter(Role.name == "author").first()
    test_user.roles.append(author_role)
    session.commit()

    response = client.post(
        "/post/",
        json={
            "title": "test title",
            "content": "test content",
            "tags": ["1", "2", "3"],
        },
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 200


def test_create_post_by_reader(create_tables):
    session = TestingSessionLocal()
    test_user = create_test_user(session, "testuser", "testpass")
    session.add(test_user)
    session.commit()
    access_token = create_access_token({"sub": test_user.id})

    response = client.post(
        "/post/",
        json={
            "title": "test title",
            "content": "test content",
            "tags": ["1", "2", "3"],
        },
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 401
