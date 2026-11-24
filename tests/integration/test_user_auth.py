# tests/integration/test_user_auth.py

import pytest
from uuid import UUID
import pydantic_core
from sqlalchemy.exc import IntegrityError
from app.models.user import User
import uuid
from fastapi.testclient import TestClient
from app.main import app
import asyncio
import runpy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException
from jose import jwt as jose_jwt
import app.auth.redis as redis_module
from app.auth import jwt as auth_jwt
from app.core.config import settings
from app.schemas.token import TokenType
from app.schemas.user import UserCreate, PasswordUpdate


def test_password_hashing(db_session, fake_user_data):
    """Test password hashing and verification functionality"""
    original_password = "TestPass123"  # Use known password for test
    hashed = User.hash_password(original_password)
    
    user = User(
        first_name=fake_user_data['first_name'],
        last_name=fake_user_data['last_name'],
        email=fake_user_data['email'],
        username=fake_user_data['username'],
        password=hashed
    )
    
    assert user.verify_password(original_password) is True
    assert user.verify_password("WrongPass123") is False
    assert hashed != original_password

def test_user_registration(db_session, fake_user_data):
    """Test user registration process"""
    fake_user_data['password'] = "TestPass123"
    
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    assert user.first_name == fake_user_data['first_name']
    assert user.last_name == fake_user_data['last_name']
    assert user.email == fake_user_data['email']
    assert user.username == fake_user_data['username']
    assert user.is_active is True
    assert user.is_verified is False
    assert user.verify_password("TestPass123") is True

def test_duplicate_user_registration(db_session):
    """Test registration with duplicate email/username"""
    # First user data
    user1_data = {
        "first_name": "Test",
        "last_name": "User1",
        "email": "unique.test@example.com",
        "username": "uniqueuser1",
        "password": "TestPass123"
    }
    
    # Second user data with same email
    user2_data = {
        "first_name": "Test",
        "last_name": "User2",
        "email": "unique.test@example.com",  # Same email
        "username": "uniqueuser2",
        "password": "TestPass123"
    }
    
    # Register first user
    first_user = User.register(db_session, user1_data)
    db_session.commit()
    db_session.refresh(first_user)
    
    # Try to register second user with same email
    with pytest.raises(ValueError, match="Username or email already exists"):
        User.register(db_session, user2_data)

def test_user_authentication(db_session, fake_user_data):
    """Test user authentication and token generation"""
    # Use fake_user_data from fixture
    fake_user_data['password'] = "TestPass123"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    # Test successful authentication
    auth_result = User.authenticate(
        db_session,
        fake_user_data['username'],
        "TestPass123"
    )
    
    assert auth_result is not None
    assert "access_token" in auth_result
    assert "token_type" in auth_result
    assert auth_result["token_type"] == "bearer"
    assert "user" in auth_result

def test_user_last_login_update(db_session, fake_user_data):
    """Test that last_login is updated on authentication"""
    fake_user_data['password'] = "TestPass123"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    # Authenticate and check last_login
    assert user.last_login is None
    auth_result = User.authenticate(db_session, fake_user_data['username'], "TestPass123")
    db_session.refresh(user)
    assert user.last_login is not None

def test_unique_email_username(db_session):
    """Test uniqueness constraints for email and username"""
    # Create first user with specific test data
    user1_data = {
        "first_name": "Test",
        "last_name": "User1",
        "email": "unique_test@example.com",
        "username": "uniqueuser",
        "password": "TestPass123"
    }
    
    # Register and commit first user
    User.register(db_session, user1_data)
    db_session.commit()
    
    # Try to create user with same email
    user2_data = {
        "first_name": "Test",
        "last_name": "User2",
        "email": "unique_test@example.com",  # Same email
        "username": "differentuser",
        "password": "TestPass123"
    }
    
    with pytest.raises(ValueError, match="Username or email already exists"):
        User.register(db_session, user2_data)

def test_short_password_registration(db_session):
    """Test that registration fails with a short password"""
    # Prepare test data with a 5-character password
    test_data = {
        "first_name": "Password",
        "last_name": "Test",
        "email": "short.pass@example.com",
        "username": "shortpass",
        "password": "Shor1"  # 5 characters, should fail
    }
    
    # Attempt registration with short password
    with pytest.raises(ValueError, match="Password must be at least 6 characters long"):
        User.register(db_session, test_data)

def test_invalid_token():
    """Test that invalid tokens are rejected"""
    invalid_token = "invalid.token.string"
    result = User.verify_token(invalid_token)
    assert result is None

def test_token_creation_and_verification(db_session, fake_user_data):
    """Test token creation and verification"""
    fake_user_data['password'] = "TestPass123"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    # Create token
    token = User.create_access_token({"sub": str(user.id)})
    
    # Verify token
    decoded_user_id = User.verify_token(token)
    assert decoded_user_id == user.id

def test_authenticate_with_email(db_session, fake_user_data):
    """Test authentication using email instead of username"""
    fake_user_data['password'] = "TestPass123"
    user = User.register(db_session, fake_user_data)
    db_session.commit()
    
    # Test authentication with email
    auth_result = User.authenticate(
        db_session,
        fake_user_data['email'],  # Using email instead of username
        "TestPass123"
    )
    
    assert auth_result is not None
    assert "access_token" in auth_result

def test_user_model_representation(test_user):
    """Test the string representation of User model"""
    expected = f"<User(name={test_user.first_name} {test_user.last_name}, email={test_user.email})>"
    assert str(test_user) == expected

def test_missing_password_registration(db_session):
    """Test that registration fails when no password is provided."""
    test_data = {
        "first_name": "NoPassword",
        "last_name": "Test",
        "email": "no.password@example.com",
        "username": "nopassworduser",
        # Password is missing
    }
    
    # Adjust the expected error message
    with pytest.raises(ValueError, match="Password must be at least 6 characters long"):
        User.register(db_session, test_data)


# Endpoint tests: POST /users/register and POST /users/login
@pytest.fixture
def api_client():
    return TestClient(app)


@pytest.fixture
def api_user_payload():
    """A valid registration payload with a unique username/email for every test."""
    suffix = uuid.uuid4().hex[:12]
    return {
        "first_name": "Test",
        "last_name": "User",
        "email": f"user_{suffix}@example.com",
        "username": f"user_{suffix}",
        "password": "SecurePass123!",
        "confirm_password": "SecurePass123!",
    }


def _get_user_by_username(db_session, username):
    db_session.expire_all()
    return db_session.query(User).filter(User.username == username).first()


def test_endpoint_register_creates_user_with_hashed_password(api_client, db_session, api_user_payload):
    response = api_client.post("/users/register", json=api_user_payload)

    assert response.status_code == 201
    body = response.json()
    assert body["username"] == api_user_payload["username"]
    assert body["email"] == api_user_payload["email"]
    assert body["is_active"] is True
    assert "password" not in body  # never returned

    # Verify the data in the database: the row exists and the password is hashed
    user = _get_user_by_username(db_session, api_user_payload["username"])
    assert user is not None
    assert str(user.id) == body["id"]
    assert user.password != api_user_payload["password"]
    assert user.verify_password(api_user_payload["password"]) is True


def test_endpoint_register_duplicate_user_returns_400(api_client, api_user_payload):
    assert api_client.post("/users/register", json=api_user_payload).status_code == 201

    response = api_client.post("/users/register", json=api_user_payload)

    assert response.status_code == 400
    assert "already exists" in response.json()["detail"]


@pytest.mark.parametrize(
    "changes",
    [
        {"confirm_password": "SecurePass123?"},                              # passwords differ
        {"password": "weakpass", "confirm_password": "weakpass"},            # weak password
        {"email": "not-an-email"},                                           # invalid email
        {"username": "ab"},                                                  # username too short
    ],
    ids=["password-mismatch", "weak-password", "invalid-email", "short-username"],
)
def test_endpoint_register_invalid_data_returns_422(api_client, db_session, api_user_payload, changes):
    api_user_payload.update(changes)

    response = api_client.post("/users/register", json=api_user_payload)

    assert response.status_code == 422
    assert _get_user_by_username(db_session, api_user_payload["username"]) is None  # nothing saved


def test_endpoint_login_success_returns_tokens(api_client, db_session, api_user_payload):
    api_client.post("/users/register", json=api_user_payload)

    response = api_client.post(
        "/users/login",
        json={"username": api_user_payload["username"], "password": api_user_payload["password"]},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"] and body["refresh_token"]
    assert body["username"] == api_user_payload["username"]
    assert _get_user_by_username(db_session, api_user_payload["username"]).last_login is not None


def test_endpoint_login_wrong_password_returns_401(api_client, api_user_payload):
    api_client.post("/users/register", json=api_user_payload)

    response = api_client.post(
        "/users/login",
        json={"username": api_user_payload["username"], "password": "WrongPass123!"},
    )

    assert response.status_code == 401


def test_endpoint_login_unknown_user_returns_401(api_client):
    response = api_client.post(
        "/users/login", json={"username": "no_such_user", "password": "SecurePass123!"}
    )
    assert response.status_code == 401


def test_endpoint_login_invalid_payload_returns_422(api_client):
    response = api_client.post("/users/login", json={"username": "someuser"})  # no password
    assert response.status_code == 422


# Coverage: app/main.py (health, lifespan, form login, token expiry, __main__)
def test_endpoint_health_returns_ok(api_client):
    response = api_client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_lifespan_runs_on_startup(api_client):
    # Using TestClient as a context manager runs the app's startup/shutdown (lifespan) code.
    with TestClient(app) as lifespan_client:
        assert lifespan_client.get("/health").status_code == 200


def test_endpoint_form_login_returns_bearer_token(api_client, api_user_payload):
    api_client.post("/users/register", json=api_user_payload)

    response = api_client.post(
        "/auth/token",
        data={"username": api_user_payload["username"], "password": api_user_payload["password"]},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]


def test_endpoint_form_login_wrong_password_returns_401(api_client, api_user_payload):
    api_client.post("/users/register", json=api_user_payload)

    response = api_client.post(
        "/auth/token",
        data={"username": api_user_payload["username"], "password": "WrongPass123!"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password"


def test_endpoint_login_makes_naive_expiry_timezone_aware(api_client):
    """If authenticate() returns a naive expires_at, the endpoint marks it as UTC."""
    fake_user = SimpleNamespace(
        id=uuid.uuid4(), username="naiveuser", email="naive@example.com",
        first_name="Naive", last_name="User", is_active=True, is_verified=False,
    )
    fake_result = {
        "access_token": "access", "refresh_token": "refresh", "token_type": "bearer",
        "expires_at": datetime(2030, 1, 1, 12, 0, 0), "user": fake_user,
    }

    with patch.object(User, "authenticate", return_value=fake_result):
        response = api_client.post(
            "/users/login", json={"username": "naiveuser", "password": "SecurePass123!"}
        )

    assert response.status_code == 200
    assert response.json()["expires_at"] in ("2030-01-01T12:00:00Z", "2030-01-01T12:00:00+00:00")


def test_endpoint_login_missing_expiry_falls_back_to_15_minutes(api_client):
    """If authenticate() returns no usable expires_at, the endpoint defaults to ~15 minutes."""
    fake_user = SimpleNamespace(
        id=uuid.uuid4(), username="noexpiry", email="noexpiry@example.com",
        first_name="No", last_name="Expiry", is_active=True, is_verified=False,
    )
    fake_result = {
        "access_token": "access", "refresh_token": "refresh", "token_type": "bearer",
        "expires_at": None, "user": fake_user,
    }
    before = datetime.now(timezone.utc)

    with patch.object(User, "authenticate", return_value=fake_result):
        response = api_client.post(
            "/users/login", json={"username": "noexpiry", "password": "SecurePass123!"}
        )

    assert response.status_code == 200
    expires_at = datetime.fromisoformat(response.json()["expires_at"].replace("Z", "+00:00"))
    assert before + timedelta(minutes=14) < expires_at < before + timedelta(minutes=16)


def test_main_module_starts_uvicorn_when_run_as_script():
    with patch("uvicorn.run") as mock_run:
        runpy.run_module("app.main", run_name="__main__")

    mock_run.assert_called_once()
    assert mock_run.call_args.args[0] == "app.main:app"

# Coverage: app/models/user.py
def test_user_init_accepts_hashed_password_keyword():
    user = User(
        first_name="Hash", last_name="Kw", email="hash.kw@example.com",
        username="hash_kw", hashed_password="already-hashed-value",
    )
    assert user.password == "already-hashed-value"
    assert user.hashed_password == "already-hashed-value"


def test_user_update_sets_fields_and_refreshes_updated_at():
    user = User(
        first_name="Old", last_name="Name", email="old.name@example.com",
        username="old_name", password="x",
    )

    result = user.update(first_name="New", last_name="Person")

    assert result is user
    assert user.first_name == "New"
    assert user.last_name == "Person"
    assert user.updated_at is not None


def test_verify_token_without_subject_returns_none():
    token = jose_jwt.encode({"foo": "bar"}, settings.JWT_SECRET_KEY, algorithm=settings.ALGORITHM)
    assert User.verify_token(token) is None


def test_verify_token_with_non_uuid_subject_returns_none():
    token = jose_jwt.encode({"sub": "not-a-uuid"}, settings.JWT_SECRET_KEY, algorithm=settings.ALGORITHM)
    assert User.verify_token(token) is None


# Coverage: app/auth/jwt.py
def _not_blacklisted():
    return patch("app.auth.jwt.is_blacklisted", new_callable=AsyncMock, return_value=False)


def test_create_token_with_custom_expiry_and_uuid_subject():
    user_id = uuid.uuid4()

    token = auth_jwt.create_token(user_id, TokenType.ACCESS, expires_delta=timedelta(minutes=5))

    payload = jose_jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert payload["sub"] == str(user_id)
    assert payload["type"] == "access"
    assert payload["exp"] - payload["iat"] == pytest.approx(300, abs=2)


def test_create_token_encode_failure_returns_500():
    with patch.object(auth_jwt.jwt, "encode", side_effect=Exception("boom")):
        with pytest.raises(HTTPException) as exc_info:
            auth_jwt.create_token(uuid.uuid4(), TokenType.ACCESS)

    assert exc_info.value.status_code == 500
    assert "Could not create token" in exc_info.value.detail


def test_decode_token_valid_access_token():
    user_id = uuid.uuid4()
    token = auth_jwt.create_token(user_id, TokenType.ACCESS)

    with _not_blacklisted():
        payload = asyncio.run(auth_jwt.decode_token(token, TokenType.ACCESS))

    assert payload["sub"] == str(user_id)
    assert payload["type"] == "access"


def test_decode_token_wrong_token_type_returns_401():
    # Signed with the access secret but labelled as a refresh token.
    claims = {
        "sub": str(uuid.uuid4()), "type": "refresh", "jti": "abc123",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    token = jose_jwt.encode(claims, settings.JWT_SECRET_KEY, algorithm=settings.ALGORITHM)

    with _not_blacklisted():
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(auth_jwt.decode_token(token, TokenType.ACCESS))

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid token type"


def test_decode_token_revoked_token_returns_401():
    token = auth_jwt.create_token(uuid.uuid4(), TokenType.ACCESS)

    with patch("app.auth.jwt.is_blacklisted", new_callable=AsyncMock, return_value=True):
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(auth_jwt.decode_token(token, TokenType.ACCESS))

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Token has been revoked"


def test_decode_token_expired_token_returns_401():
    token = auth_jwt.create_token(uuid.uuid4(), TokenType.ACCESS, expires_delta=timedelta(seconds=-30))

    with _not_blacklisted():
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(auth_jwt.decode_token(token, TokenType.ACCESS))

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Token has expired"


def test_decode_token_garbage_token_returns_401():
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(auth_jwt.decode_token("not.a.jwt", TokenType.ACCESS))

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Could not validate credentials"


def test_jwt_get_current_user_returns_user(db_session, test_user):
    token = auth_jwt.create_token(test_user.id, TokenType.ACCESS)

    with _not_blacklisted():
        user = asyncio.run(auth_jwt.get_current_user(token=token, db=db_session))

    assert user.id == test_user.id


def test_jwt_get_current_user_unknown_user_returns_401(db_session):
    token = auth_jwt.create_token(uuid.uuid4(), TokenType.ACCESS)  # no such user in the DB

    with _not_blacklisted():
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(auth_jwt.get_current_user(token=token, db=db_session))

    assert exc_info.value.status_code == 401
    assert "User not found" in exc_info.value.detail


def test_jwt_get_current_user_inactive_user_returns_401(db_session, test_user):
    test_user.is_active = False
    db_session.commit()
    token = auth_jwt.create_token(test_user.id, TokenType.ACCESS)

    with _not_blacklisted():
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(auth_jwt.get_current_user(token=token, db=db_session))

    assert exc_info.value.status_code == 401
    assert "Inactive user" in exc_info.value.detail


def test_jwt_get_current_user_invalid_token_returns_401(db_session):
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(auth_jwt.get_current_user(token="not.a.jwt", db=db_session))

    assert exc_info.value.status_code == 401


# ======================================================================================
# Coverage: app/auth/redis.py (the Redis client is mocked, no Redis server needed)
# ======================================================================================
def test_get_redis_creates_client_once_and_caches_it():
    fake_redis = MagicMock()
    if hasattr(redis_module.get_redis, "redis"):
        delattr(redis_module.get_redis, "redis")

    try:
        with patch("app.auth.redis.aioredis.from_url", new=AsyncMock(return_value=fake_redis)) as from_url:
            first = asyncio.run(redis_module.get_redis())
            second = asyncio.run(redis_module.get_redis())
    finally:
        if hasattr(redis_module.get_redis, "redis"):
            delattr(redis_module.get_redis, "redis")

    assert first is fake_redis
    assert second is fake_redis
    from_url.assert_awaited_once()


def test_blacklist_helpers_use_redis():
    fake_redis = MagicMock()
    fake_redis.set = AsyncMock()
    fake_redis.exists = AsyncMock(return_value=1)

    with patch.object(redis_module, "get_redis", new=AsyncMock(return_value=fake_redis)):
        asyncio.run(redis_module.add_to_blacklist("jti-1", 60))
        result = asyncio.run(redis_module.is_blacklisted("jti-1"))

    fake_redis.set.assert_awaited_once_with("blacklist:jti-1", "1", ex=60)
    fake_redis.exists.assert_awaited_once_with("blacklist:jti-1")
    assert result

# Coverage: app/schemas/user.py (password rules and PasswordUpdate)
def _user_create_kwargs(password):
    return {
        "first_name": "Test", "last_name": "User", "email": "schema.user@example.com",
        "username": "schema_user", "password": password, "confirm_password": password,
    }


@pytest.mark.parametrize(
    "password, message",
    [
        ("ALLUPPERCASE1!", "lowercase"),
        ("NoDigitsHere!!", "digit"),
        ("NoSpecial1234", "special character"),
    ],
    ids=["no-lowercase", "no-digit", "no-special-char"],
)
def test_user_create_rejects_weak_passwords(password, message):
    with pytest.raises(pydantic_core.ValidationError, match=message):
        UserCreate(**_user_create_kwargs(password))


def test_user_create_password_length_rule_called_directly():
    # Field(min_length=8) normally stops short passwords first, so call the validator itself.
    short = UserCreate.model_construct(password="Ab1!", confirm_password="Ab1!")
    with pytest.raises(ValueError, match="at least 8 characters"):
        short.validate_password_strength()


def test_password_update_valid():
    update = PasswordUpdate(
        current_password="OldPass123!", new_password="NewPass123!", confirm_new_password="NewPass123!"
    )
    assert update.new_password == "NewPass123!"


def test_password_update_confirmation_mismatch_rejected():
    with pytest.raises(pydantic_core.ValidationError, match="do not match"):
        PasswordUpdate(
            current_password="OldPass123!", new_password="NewPass123!", confirm_new_password="Different123!"
        )


def test_password_update_same_as_current_rejected():
    with pytest.raises(pydantic_core.ValidationError, match="must be different"):
        PasswordUpdate(
            current_password="OldPass123!", new_password="OldPass123!", confirm_new_password="OldPass123!"
        )
        