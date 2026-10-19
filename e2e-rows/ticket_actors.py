"""Actual attested-human and separate role sessions for the service row pass.

This is a controller adapter, never a product implementation. Every result
comes from a real CLI child of the owner terminal or a dedicated role session.
"""

from pathlib import Path

from ticket_fixture import client_environment, fixture_for


class ServiceActors:
    def __init__(self, test, binary, environment, directory):
        self.test, self.binary = test, binary
        self.environment, self.directory = dict(environment), directory
        self.fixture = fixture_for(test)
        selected = client_environment(self.environment)
        name = selected.get("LANEBOSS_CONFIG", "")
        if not name:
            configurations = list((Path(selected["LANEBOSS_HOME"]) / "configs").glob("*/config.toml"))
            if len(configurations) == 1:
                name = configurations[0].parent.name
        if name:
            # Bind the valid setup policy before a row intentionally changes
            # caller-side inputs. Actor ownership is prepared at first use.
            self.fixture.bind(name, selected)
        self.roles = {}
        self.default_role = None
        self.background = []
        self.closed = False

    def request(self, arguments, **options):
        args = list(map(str, arguments))
        name = args[args.index("--config") + 1] if "--config" in args else self.environment.get("LANEBOSS_CONFIG", "")
        if not name:
            raise RuntimeError("the service actor request must name its configuration")
        environment = self.fixture.actor_environment(name, self.environment)
        selected = self.default_role if self.default_role is not None else options.get("role")
        if args and args[0] == "start" and "--role" in args:
            selected = args[args.index("--role") + 1]
            if options.get("role"):
                self.default_role = selected
        if selected is not None:
            key = (name, selected)
            if key not in self.roles:
                from reportsupport import TerminalController
                self.roles[key] = TerminalController(self.test, self.binary, environment,
                    self.directory, _service_role=True)
            actor = self.roles[key]
            result = actor.request(args, **options)
            self.last_arguments, self.last_binary = actor.last_arguments, actor.last_binary
            return result
        request = {"args": args, "cwd": str(self.directory),
                   "binary": str(self.fixture.actor_binary(options.pop("binary", self.binary))),
                   "environment": environment, **options}
        # Request environment is input to the actual child, not an actor label.
        request["environment"] = {**environment, **options.get("environment", {})}
        self.last_arguments, self.last_binary = request["args"], request["binary"]
        result = self.fixture.owner_request(name, request)
        if "pid" in result:
            self.background.append((name, result["pid"]))
        return result

    def select_role(self, role):
        self.default_role = role

    def close(self):
        if self.closed:
            return
        self.closed = True
        for name, pid in self.background:
            self.fixture.owner_request(name, {"stop": [pid]})
        self.background.clear()
