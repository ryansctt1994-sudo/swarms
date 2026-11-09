"""Import-free tests for the Swarms API ownership policy and route wiring.

These checks intentionally do not instantiate an LLM, call a cloud API or
claim an end-to-end FastAPI deployment test. They execute the pure ownership
decision and inspect route wiring in the actual API module's syntax tree.
"""
from __future__ import annotations

import ast
import unittest
from pathlib import Path
from uuid import uuid4

from api.agent_authorization import may_access_agent

ROOT = Path(__file__).resolve().parents[1]
API_SOURCE = (ROOT / "api" / "main.py").read_text(encoding="utf-8")
TREE = ast.parse(API_SOURCE)


def find_method(name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    for node in ast.walk(TREE):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(f"missing method {name}")


def route_methods() -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    setup = find_method("_setup_routes")
    return {
        node.name: node
        for node in setup.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def has_auth_dependency(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(
        isinstance(arg, ast.arg) and arg.arg == "current_user"
        for arg in fn.args.args
    ) and "Depends(get_current_user)" in ast.unparse(fn)


class OwnershipDecisionTests(unittest.TestCase):
    def test_only_owner_and_explicit_admin_can_access(self):
        owner = uuid4()
        other = uuid4()
        self.assertTrue(may_access_agent(owner, owner))
        self.assertFalse(may_access_agent(owner, other))
        self.assertTrue(may_access_agent(owner, other, is_admin=True))

    def test_missing_or_malformed_identity_is_never_authorized(self):
        owner = uuid4()
        self.assertFalse(may_access_agent(None, owner, is_admin=True))
        self.assertFalse(may_access_agent("unknown", owner, is_admin=True))
        self.assertFalse(may_access_agent(owner, "unknown", is_admin=True))

    def test_every_sensitive_agent_route_requires_user_dependency(self):
        routes = route_methods()
        names = (
            "create_agent",
            "list_agents",
            "list_user_agents",
            "update_agent",
            "get_agent_metrics",
            "clone_agent",
            "delete_agent",
            "create_completion",
            "get_agent_status",
        )
        for name in names:
            with self.subTest(route=name):
                self.assertIn(name, routes)
                self.assertTrue(has_auth_dependency(routes[name]), name)

    def test_noncreating_agent_routes_require_owner_guard(self):
        routes = route_methods()
        guarded = (
            "update_agent",
            "get_agent_metrics",
            "clone_agent",
            "delete_agent",
            "create_completion",
            "get_agent_status",
        )
        for name in guarded:
            with self.subTest(route=name):
                body = ast.unparse(routes[name])
                self.assertIn("self._require_agent_access(", body)

    def test_list_routes_restrict_visible_agents_by_owner(self):
        routes = route_methods()
        all_agents = ast.unparse(routes["list_agents"])
        self.assertIn("current_user.is_admin", all_agents)
        self.assertIn("self.store.user_agents.get(current_user.id", all_agents)
        self.assertIn("item.agent_id in owned", all_agents)
        self.assertIn("self.store.user_agents.get(current_user.id", ast.unparse(routes["list_user_agents"]))

    def test_agent_ownership_is_persisted_and_clone_keeps_user(self):
        create = ast.unparse(find_method("create_agent"))
        clone = ast.unparse(find_method("clone_agent"))
        # Both route-level and store-level create_agent methods are checked:
        self.assertIn("self.store.create_agent(config, current_user.id)", ast.unparse(route_methods()["create_agent"]))
        self.assertIn("self.store.clone_agent(agent_id, new_name, current_user.id)", ast.unparse(route_methods()["clone_agent"]))
        self.assertIn("self.create_agent(config, user_id)", API_SOURCE)

    def test_agent_state_path_is_guarded_against_user_filename_traversal(self):
        source = API_SOURCE
        self.assertIn('re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", config.agent_name)', source)
        self.assertIn('config.agent_name in {".", ".."}', source)
        self.assertIn('status.HTTP_422_UNPROCESSABLE_ENTITY', source)

    def test_cors_is_not_wildcard_by_default_and_credentials_are_explicit(self):
        self.assertIn('os.getenv("SWARMS_CORS_ORIGINS", "")', API_SOURCE)
        self.assertIn('if "*" in allowed_origins:', API_SOURCE)
        self.assertIn('allow_credentials=True', API_SOURCE)

    def test_request_failures_are_not_rewritten_to_server_errors(self):
        source = ast.unparse(route_methods()["create_completion"])
        self.assertIn("except HTTPException:", source)
        self.assertIn("raise", source)


if __name__ == "__main__":
    unittest.main()
