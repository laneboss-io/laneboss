"""Application routing, without depending on HTTP transport behavior."""

from taskforge.errors import BadRequest, MethodNotAllowed, NotFound, Unauthorized
from tests.support import Fixture


class ApplicationTests(Fixture):
    def test_register_route_returns_ne_1(self):
        result = self.application.dispatch("POST", "/auth/register", {},
                                           {"username": "route_user", "password": self.password})
        self.assertEqual(result.status, 201)
        self.assertEqual(result.body["username"], "route_user")
        self.assertNotEqual(result.body["id"], self.user["id"])

    def test_login_route_returns_usabl_2(self):
        result = self.application.dispatch("POST", "/auth/login", {},
                                           {"username": self.username, "password": self.password})
        self.assertEqual(result.status, 200)
        authenticated = self.application.auth.authenticate(result.body["token"])
        self.assertEqual(authenticated["id"], self.user["id"])

    def test_create_route_sets_location(self):
        result = self.application.dispatch("POST", "/tasks", self.headers, {"title": "route task"})
        self.assertEqual(result.status, 201)
        self.assertEqual(result.headers["Location"], "/tasks/" + str(result.body["id"]))
        self.assertEqual(result.body["title"], "route task")

    def test_query_string_does_not_cha_3(self):
        own = self.task()
        result = self.application.dispatch("GET", "/tasks?status=open", self.headers)
        self.assertEqual(result.status, 200)
        self.assertEqual([row["id"] for row in result.body["items"]], [own["id"]])

    def test_get_route_returns_saved_task(self):
        task = self.task()
        result = self.application.dispatch("GET", "/tasks/" + str(task["id"]), self.headers)
        self.assertEqual(result.status, 200)
        self.assertEqual(result.body, task)

    def test_patch_route_persists_changes(self):
        task = self.task()
        result = self.application.dispatch("PATCH", "/tasks/" + str(task["id"]), self.headers,
                                           {"description": "changed by route"})
        self.assertEqual(result.status, 200)
        self.assertEqual(self.application.tasks.get(self.user["id"], task["id"])["description"],
                         "changed by route")

    def test_health_wrong_method_is_refused(self):
        with self.assertRaises(MethodNotAllowed):
            self.application.dispatch("POST", "/health", {}, {})

    def test_registration_wrong_method_4(self):
        with self.assertRaises(MethodNotAllowed):
            self.application.dispatch("GET", "/auth/register", {})

    def test_login_wrong_method_is_refused(self):
        with self.assertRaises(MethodNotAllowed):
            self.application.dispatch("GET", "/auth/login", {})

    def test_logout_wrong_method_is_refused(self):
        with self.assertRaises(MethodNotAllowed):
            self.application.dispatch("GET", "/auth/logout", self.headers)

    def test_task_wrong_method_is_refused(self):
        own = self.task()
        with self.assertRaises(MethodNotAllowed):
            self.application.dispatch("POST", "/tasks/" + str(own["id"]), self.headers, {})

    def test_zero_id_does_not_match_route(self):
        with self.assertRaises(NotFound):
            self.application.dispatch("GET", "/tasks/0", self.headers)

    def test_negative_id_does_not_matc_5(self):
        with self.assertRaises(NotFound):
            self.application.dispatch("GET", "/tasks/-3", self.headers)

    def test_noninteger_id_does_not_ma_6(self):
        with self.assertRaises(NotFound):
            self.application.dispatch("GET", "/tasks/letters", self.headers)

    def test_extra_path_segment_does_n_7(self):
        own = self.task()
        with self.assertRaises(NotFound):
            self.application.dispatch("GET", "/tasks/" + str(own["id"]) + "/extra", self.headers)

    def test_auth_scheme_is_case_insen_8(self):
        result = self.application.dispatch("GET", "/tasks", {"Authorization": "bearer " + self.token})
        self.assertEqual(result.status, 200)
        self.assertEqual(result.body["items"], [])

    def test_basic_auth_is_not_bearer_auth(self):
        with self.assertRaises(Unauthorized):
            self.application.dispatch("GET", "/tasks", {"Authorization": "Basic invalid"})

    def test_blank_bearer_token_is_refused(self):
        with self.assertRaises(Unauthorized):
            self.application.dispatch("GET", "/tasks", {"Authorization": "Bearer "})

    def test_scalar_body_is_refused(self):
        with self.assertRaises(BadRequest):
            self.application.dispatch("POST", "/tasks", self.headers, "scalar")

    def test_authorization_happens_bef_9(self):
        with self.assertRaises(Unauthorized):
            self.application.dispatch("POST", "/tasks", {}, {"title": "unauthorized task"})
        self.assertEqual(self.application.tasks.list(self.user["id"])["items"], [])
