import os
import subprocess
from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):

    def initialize(self, version, build_data):
        # Only run hook on actual target builds, not when installing editable/dev
        if version == "editable":
            return

        src_dir = os.path.join(self.root, "src")
        version_file_path = os.path.join(src_dir, "mdns_sieve_gui", "_version.py")

        commit = "unknown"
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--short", "HEAD"],
                cwd=self.root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
                timeout=2.0,
            )
            git_val = result.stdout.strip()
            if git_val:
                commit = git_val
        except Exception:
            commit = os.environ.get("GIT_COMMIT", commit)

        with open(version_file_path, "w", encoding="utf-8") as f:
            f.write(
                '"""Version tracking module."""\n\n'
                f'# Generated dynamically during wheel build\n__commit__ = "{commit}"\n'
            )
