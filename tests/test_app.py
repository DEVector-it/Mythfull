import base64
import sys
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app import API_KEY_HEADER, STUDY_BUDDY_API_KEY, app, PIL_AVAILABLE


@pytest.fixture()
def client():
    return app.test_client()


def _auth_headers():
    return {
        "Content-Type": "application/json",
        API_KEY_HEADER: STUDY_BUDDY_API_KEY,
    }


def test_home_page_renders(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Study Buddy AI" in response.data


def test_chat_endpoint_responds(client):
    response = client.post(
        "/api/chat",
        json={"plan": "myth-max", "message": "Hello Study Buddy!"},
        headers=_auth_headers(),
    )
    payload = response.get_json()
    assert response.status_code == 200
    assert payload["plan"]["slug"] == "myth-max"
    assert "response" in payload


def test_image_endpoint_returns_data_uri(client):
    response = client.post(
        "/api/image",
        json={"plan": "goat-myth", "prompt": "diagram"},
        headers=_auth_headers(),
    )
    payload = response.get_json()
    assert response.status_code == 200
    assert payload["plan"]["slug"] == "goat-myth"
    image_data = payload["image"]
    if PIL_AVAILABLE:
        assert image_data.startswith("data:image/png;base64,")
    else:
        assert image_data.startswith("data:image/svg+xml;base64,")
        decoded = base64.b64decode(image_data.split(",", 1)[1]).decode("utf-8")
        assert "diagram" in decoded
