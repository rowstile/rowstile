"""Puts the rowstile command into the package (rowstile/_command) when building from the repository: the files
command-files.txt lists (authzlib, every module of core/cli and Studio's page), the ones the npm package carries
too. A build from the sdist has them there already."""

import os
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CommandHook(BuildHookInterface):
    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        checkout = os.path.normpath(os.path.join(self.root, "..", "..", "core"))
        if not os.path.isdir(os.path.join(checkout, "authzlib")):
            return
        with open(os.path.join(self.root, "command-files.txt"), encoding="utf-8") as fh:
            lines = [line.split("#")[0].split() for line in fh]
        # each folder, and the endings of its files the command runs: file by file, so that nothing else of the
        # tree it is built from (an editor's backup, a note, bytecode) goes into the package
        for folder, *endings in (line for line in lines if line):
            for name in sorted(os.listdir(os.path.join(checkout, folder))):
                source = os.path.join(checkout, folder, name)
                if os.path.isfile(source) and name.endswith(tuple(endings)):
                    build_data["force_include"][source] = f"rowstile/_command/{folder}/{name}"
