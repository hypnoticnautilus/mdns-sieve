import atexit
import os
import subprocess
import tempfile
from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):

    def initialize(self, version, build_data):
        # Only run hook on actual target builds, not when installing editable/dev
        if version == "editable":
            return

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

        # Create a temporary file to hold the generated _version.py
        fd, temp_path = tempfile.mkstemp(suffix=".py", prefix="version_")
        
        # Register deletion on process exit to keep system clean
        atexit.register(lambda: os.remove(temp_path) if os.path.exists(temp_path) else None)

        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(
                    '"""Version tracking module."""\n\n'
                    f'# Generated dynamically during wheel build\n__commit__ = "{commit}"\n'
                )
            
            # Use force_include to place the temp file at the correct wheel location
            build_data.setdefault("force_include", {})
            build_data["force_include"][temp_path] = "mdns_sieve_gui/_version.py"
        except Exception:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise
