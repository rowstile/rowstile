"""Puts the rowstile command into the package (rowstile/_command) when building from the repository: authzlib,
every module of core/cli and Studio's page (cli/studio). A build from the sdist has it there already."""

import os
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

# each folder of core/ the command runs from, and the files of it that it runs: file by file, so that nothing else
# of the tree it is built from (an editor's backup, a note, bytecode) goes into the package
COMMAND = {"authzlib": (".py",), "cli": (".py",), "cli/studio": (".html", ".js", ".css")}


class CommandHook(BuildHookInterface):
    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        checkout = os.path.normpath(os.path.join(self.root, "..", "..", "core"))
        if not os.path.isdir(os.path.join(checkout, "authzlib")):
            return
        for folder, kinds in COMMAND.items():
            for name in sorted(os.listdir(os.path.join(checkout, folder))):
                if name.endswith(kinds):
                    source = os.path.join(checkout, folder, name)
                    build_data["force_include"][source] = f"rowstile/_command/{folder}/{name}"
