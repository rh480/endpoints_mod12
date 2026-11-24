# tests/integration/test_user_auth.py

import pytest
from uuid import UUID
import pydantic_core
from sqlalchemy.exc import IntegrityError
from app.models.user import User
import uuid
from fastapi.testclient import TestClient
from app.main import app

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


# ======================================================================================
# Endpoint tests: POST /users/register and POST /users/login
# ======================================================================================
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