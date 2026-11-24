import pytest
import uuid
from fastapi.testclient import TestClient
from app.main import app

from app.models.calculation import (
    Calculation,
    Addition,
    Subtraction,
    Multiplication,
    Division,
)

# Helper function to create a dummy user_id for testing.
def dummy_user_id():
    return uuid.uuid4()

def test_addition_get_result():
    """
    Test that Addition.get_result returns the correct sum.
    """
    inputs = [10, 5, 3.5]
    addition = Addition(user_id=dummy_user_id(), inputs=inputs)
    result = addition.get_result()
    assert result == sum(inputs), f"Expected {sum(inputs)}, got {result}"

def test_subtraction_get_result():
    """
    Test that Subtraction.get_result returns the correct difference.
    """
    inputs = [20, 5, 3]
    subtraction = Subtraction(user_id=dummy_user_id(), inputs=inputs)
    # Expected: 20 - 5 - 3 = 12
    result = subtraction.get_result()
    assert result == 12, f"Expected 12, got {result}"

def test_multiplication_get_result():
    """
    Test that Multiplication.get_result returns the correct product.
    """
    inputs = [2, 3, 4]
    multiplication = Multiplication(user_id=dummy_user_id(), inputs=inputs)
    result = multiplication.get_result()
    assert result == 24, f"Expected 24, got {result}"

def test_division_get_result():
    """
    Test that Division.get_result returns the correct quotient.
    """
    inputs = [100, 2, 5]
    division = Division(user_id=dummy_user_id(), inputs=inputs)
    # Expected: 100 / 2 / 5 = 10
    result = division.get_result()
    assert result == 10, f"Expected 10, got {result}"

def test_division_by_zero():
    """
    Test that Division.get_result raises ValueError when dividing by zero.
    """
    inputs = [50, 0, 5]
    division = Division(user_id=dummy_user_id(), inputs=inputs)
    with pytest.raises(ValueError, match="Cannot divide by zero."):
        division.get_result()

def test_calculation_factory_addition():
    """
    Test the Calculation.create factory method for addition.
    """
    inputs = [1, 2, 3]
    calc = Calculation.create(
        calculation_type='addition',
        user_id=dummy_user_id(),
        inputs=inputs,
    )
    # Check that the returned instance is an Addition.
    assert isinstance(calc, Addition), "Factory did not return an Addition instance."
    assert calc.get_result() == sum(inputs), "Incorrect addition result."

def test_calculation_factory_subtraction():
    """
    Test the Calculation.create factory method for subtraction.
    """
    inputs = [10, 4]
    calc = Calculation.create(
        calculation_type='subtraction',
        user_id=dummy_user_id(),
        inputs=inputs,
    )
    # Expected: 10 - 4 = 6
    assert isinstance(calc, Subtraction), "Factory did not return a Subtraction instance."
    assert calc.get_result() == 6, "Incorrect subtraction result."

def test_calculation_factory_multiplication():
    """
    Test the Calculation.create factory method for multiplication.
    """
    inputs = [3, 4, 2]
    calc = Calculation.create(
        calculation_type='multiplication',
        user_id=dummy_user_id(),
        inputs=inputs,
    )
    # Expected: 3 * 4 * 2 = 24
    assert isinstance(calc, Multiplication), "Factory did not return a Multiplication instance."
    assert calc.get_result() == 24, "Incorrect multiplication result."

def test_calculation_factory_division():
    """
    Test the Calculation.create factory method for division.
    """
    inputs = [100, 2, 5]
    calc = Calculation.create(
        calculation_type='division',
        user_id=dummy_user_id(),
        inputs=inputs,
    )
    # Expected: 100 / 2 / 5 = 10
    assert isinstance(calc, Division), "Factory did not return a Division instance."
    assert calc.get_result() == 10, "Incorrect division result."

def test_calculation_factory_invalid_type():
    """
    Test that Calculation.create raises a ValueError for an unsupported calculation type.
    """
    with pytest.raises(ValueError, match="Unsupported calculation type"):
        Calculation.create(
            calculation_type='modulus',  # unsupported type
            user_id=dummy_user_id(),
            inputs=[10, 3],
        )

def test_invalid_inputs_for_addition():
    """
    Test that providing non-list inputs to Addition.get_result raises a ValueError.
    """
    addition = Addition(user_id=dummy_user_id(), inputs="not-a-list")
    with pytest.raises(ValueError, match="Inputs must be a list of numbers."):
        addition.get_result()

def test_invalid_inputs_for_subtraction():
    """
    Test that providing fewer than two numbers to Subtraction.get_result raises a ValueError.
    """
    subtraction = Subtraction(user_id=dummy_user_id(), inputs=[10])
    with pytest.raises(ValueError, match="Inputs must be a list with at least two numbers."):
        subtraction.get_result()

def test_invalid_inputs_for_division():
    """
    Test that providing fewer than two numbers to Division.get_result raises a ValueError.
    """
    division = Division(user_id=dummy_user_id(), inputs=[10])
    with pytest.raises(ValueError, match="Inputs must be a list with at least two numbers."):
        division.get_result()

# ======================================================================================
# Endpoint tests: calculation BREAD (Browse, Read, Edit, Add, Delete)
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


@pytest.fixture
def auth_headers(api_client, api_user_payload):
    """Register + log in a new user and return the Authorization header."""
    assert api_client.post("/users/register", json=api_user_payload).status_code == 201
    login = api_client.post(
        "/users/login",
        json={"username": api_user_payload["username"], "password": api_user_payload["password"]},
    )
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def _get_calc(db_session, calc_id):
    db_session.expire_all()
    return db_session.query(Calculation).filter(Calculation.id == uuid.UUID(calc_id)).first()


@pytest.mark.parametrize(
    "calc_type, inputs, expected",
    [
        ("addition", [10.5, 3, 2], 15.5),
        ("subtraction", [10, 3, 2], 5),
        ("multiplication", [2, 3, 4], 24),
        ("division", [100, 2, 5], 10),
    ],
)
def test_endpoint_add_calculation(api_client, db_session, auth_headers, calc_type, inputs, expected):
    response = api_client.post(
        "/calculations", json={"type": calc_type, "inputs": inputs}, headers=auth_headers
    )

    assert response.status_code == 201
    body = response.json()
    assert body["type"] == calc_type
    assert body["result"] == pytest.approx(expected)

    row = _get_calc(db_session, body["id"])  # verify it was saved
    assert row is not None
    assert row.result == pytest.approx(expected)


def test_endpoint_browse_read_edit_delete(api_client, db_session, auth_headers):
    # Add
    created = api_client.post(
        "/calculations", json={"type": "multiplication", "inputs": [3, 4]}, headers=auth_headers
    ).json()
    calc_id = created["id"]
    assert created["result"] == 12

    # Browse
    listing = api_client.get("/calculations", headers=auth_headers)
    assert listing.status_code == 200
    assert calc_id in [c["id"] for c in listing.json()]

    # Read
    read = api_client.get(f"/calculations/{calc_id}", headers=auth_headers)
    assert read.status_code == 200
    assert read.json()["inputs"] == [3, 4]

    # Edit
    edit = api_client.put(f"/calculations/{calc_id}", json={"inputs": [5, 6]}, headers=auth_headers)
    assert edit.status_code == 200
    assert edit.json()["result"] == 30
    assert _get_calc(db_session, calc_id).result == 30

    # Delete
    delete = api_client.delete(f"/calculations/{calc_id}", headers=auth_headers)
    assert delete.status_code == 204
    assert _get_calc(db_session, calc_id) is None
    assert api_client.get(f"/calculations/{calc_id}", headers=auth_headers).status_code == 404


@pytest.mark.parametrize(
    "payload",
    [
        {"type": "power", "inputs": [2, 3]},          # unsupported type
        {"type": "addition", "inputs": [1]},          # fewer than two inputs
        {"type": "addition", "inputs": "1,2"},        # inputs is not a list
        {"type": "addition", "inputs": [1, "abc"]},   # non-numeric input
        {"type": "division", "inputs": [10, 0]},      # division by zero
        {"type": "addition"},                         # missing inputs
        {},                                           # empty body
    ],
    ids=["bad-type", "one-input", "not-a-list", "non-numeric", "divide-by-zero", "missing-inputs", "empty"],
)
def test_endpoint_add_invalid_data_returns_422(api_client, auth_headers, payload):
    response = api_client.post("/calculations", json=payload, headers=auth_headers)
    assert response.status_code == 422


def test_endpoint_edit_invalid_inputs_returns_422(api_client, auth_headers):
    created = api_client.post(
        "/calculations", json={"type": "addition", "inputs": [1, 2]}, headers=auth_headers
    ).json()

    response = api_client.put(
        f"/calculations/{created['id']}", json={"inputs": [1]}, headers=auth_headers
    )

    assert response.status_code == 422


def test_endpoint_edit_division_by_zero_returns_400(api_client, db_session, auth_headers):
    created = api_client.post(
        "/calculations", json={"type": "division", "inputs": [100, 5]}, headers=auth_headers
    ).json()

    response = api_client.put(
        f"/calculations/{created['id']}", json={"inputs": [10, 0]}, headers=auth_headers
    )

    assert response.status_code == 400
    assert _get_calc(db_session, created["id"]).inputs == [100, 5]  # unchanged


def test_endpoint_unknown_calculation_returns_404(api_client, auth_headers):
    missing = uuid.uuid4()
    assert api_client.get(f"/calculations/{missing}", headers=auth_headers).status_code == 404
    assert api_client.put(f"/calculations/{missing}", json={"inputs": [1, 2]}, headers=auth_headers).status_code == 404
    assert api_client.delete(f"/calculations/{missing}", headers=auth_headers).status_code == 404


def test_endpoint_malformed_calculation_id_returns_400(api_client, auth_headers):
    assert api_client.get("/calculations/not-a-uuid", headers=auth_headers).status_code == 400


def test_endpoint_calculations_require_login(api_client):
    some_id = uuid.uuid4()
    assert api_client.get("/calculations").status_code == 401
    assert api_client.post("/calculations", json={"type": "addition", "inputs": [1, 2]}).status_code == 401
    assert api_client.get(f"/calculations/{some_id}").status_code == 401
    assert api_client.put(f"/calculations/{some_id}", json={"inputs": [1, 2]}).status_code == 401
    assert api_client.delete(f"/calculations/{some_id}").status_code == 401