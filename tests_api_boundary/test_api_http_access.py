"""HTTP authorization tests with a fake local Agent and no model/network calls.

These exercise FastAPI dependency resolution, real route handlers and
per-user metadata in an in-memory single-process test client.
"""
from __future__ import annotations

import sys
import types
import unittest
from types import SimpleNamespace
from uuid import UUID

from fastapi.testclient import TestClient


class FakeAgent:
    def __init__(self, **config):
        self.agent_name = config["agent_name"]
        self.system_prompt = config["system_prompt"]
        self.max_loops = config.get("max_loops", 1)
        self.autosave = config.get("autosave", False)
        self.saved_state_path = config.get("saved_state_path")
        self.llm = SimpleNamespace(
            model_name=config["model_name"], temperature=0.1
        )

    def run(self, prompt):
        return "FAKE_LOCAL_COMPLETION"


# Avoid importing the upstream Swarms runtime or contacting an LLM.
stub = types.ModuleType("swarms")
stub.Agent = FakeAgent
sys.modules["swarms"] = stub

from api import main as service  # noqa: E402


class TestAPIAuthorization(unittest.TestCase):
    def setUp(self):
        service.StoreManager._instance = service.AgentStore()
        self.api = service.SwarmsAPI()
        self.client = TestClient(self.api.app)
        self.alice = self.create_user("alice")
        self.bob = self.create_user("bobby")

    def tearDown(self):
        self.client.close()
        self.api.store.executor.shutdown(wait=False)

    def create_user(self, username):
        response = self.client.post("/v1/users", json={"username": username})
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        return {"id": UUID(payload["user_id"]), "key": payload["api_key"]}

    def headers(self, actor):
        return {"api-key": actor["key"]}

    def create_agent(self, actor, name="owned_agent"):
        response = self.client.post(
            "/v1/agent",
            headers=self.headers(actor),
            json={"agent_name": name, "system_prompt": "static local instruction"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["agent_id"]

    def test_creation_records_authoritative_owner_id(self):
        agent = self.create_agent(self.alice)
        metadata = self.api.store.agent_metadata[UUID(agent)]
        self.assertEqual(metadata["owner_id"], self.alice["id"])
        self.assertIn(UUID(agent), self.api.store.user_agents[self.alice["id"]])

    def test_foreign_user_is_denied_all_agent_id_operations(self):
        agent = self.create_agent(self.alice)
        headers = self.headers(self.bob)
        cases = [
            ("patch", f"/v1/agent/{agent}", {"json": {"tags": ["unwanted"]}}),
            ("get", f"/v1/agent/{agent}/metrics", {}),
            ("post", f"/v1/agent/{agent}/clone", {"params": {"new_name": "foreign"}}),
            ("delete", f"/v1/agent/{agent}", {}),
            ("post", "/v1/agent/completions", {"json": {"agent_id": agent, "prompt": "run"}}),
            ("get", f"/v1/agent/{agent}/status", {}),
        ]
        for method, path, options in cases:
            with self.subTest(method=method, path=path):
                response = getattr(self.client, method)(path, headers=headers, **options)
                self.assertEqual(response.status_code, 403, response.text)
        self.assertIn(UUID(agent), self.api.store.agents)

    def test_unauthenticated_routes_and_isolated_listing(self):
        agent = self.create_agent(self.alice)
        for url in ("/v1/agents", f"/v1/agent/{agent}/status"):
            response = self.client.get(url)
            self.assertIn(response.status_code, (401, 422))
        alice_list = self.client.get("/v1/agents", headers=self.headers(self.alice))
        bob_list = self.client.get("/v1/agents", headers=self.headers(self.bob))
        self.assertEqual(alice_list.status_code, 200)
        self.assertEqual(bob_list.status_code, 200)
        self.assertEqual(len(alice_list.json()), 1)
        self.assertEqual(bob_list.json(), [])

    def test_authorized_owner_can_clone_and_delete(self):
        agent = self.create_agent(self.alice)
        clone = self.client.post(
            f"/v1/agent/{agent}/clone", params={"new_name": "cloned_agent"},
            headers=self.headers(self.alice),
        )
        self.assertEqual(clone.status_code, 200, clone.text)
        clone_id = UUID(clone.json()["agent_id"])
        self.assertEqual(self.api.store.agent_metadata[clone_id]["owner_id"], self.alice["id"])

        deleted = self.client.delete(
            f"/v1/agent/{agent}", headers=self.headers(self.alice)
        )
        self.assertEqual(deleted.status_code, 200, deleted.text)
        self.assertNotIn(UUID(agent), self.api.store.user_agents[self.alice["id"]])
        self.assertIn(clone_id, self.api.store.user_agents[self.alice["id"]])

    def test_agent_name_traversal_is_refused(self):
        for name in ("../outside", "/tmp/escape", "..", "nested/agent", "x" * 65):
            with self.subTest(name=name):
                response = self.client.post(
                    "/v1/agent",
                    headers=self.headers(self.alice),
                    json={"agent_name": name, "system_prompt": "none"},
                )
                self.assertEqual(response.status_code, 422, response.text)

    def test_credentials_do_not_make_wildcard_cors(self):
        response = self.client.options(
            "/v1/agents",
            headers={
                "origin": "https://untrusted.example",
                "access-control-request-method": "GET",
            },
        )
        self.assertNotEqual(response.headers.get("access-control-allow-origin"), "*")


if __name__ == "__main__":
    unittest.main()
