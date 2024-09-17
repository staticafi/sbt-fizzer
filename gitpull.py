#!/usr/bin/env python3
import subprocess
subprocess.run(["git", "submodule", "update", "--init", "--recursive", "--remote", "--rebase"])
subprocess.run(["git", "submodule", "foreach", "--recursive", "git", "checkout", "main"])
subprocess.run(["git", "pull", "--all"])
