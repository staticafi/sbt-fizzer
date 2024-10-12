#!/usr/bin/env python3
import subprocess

subprocess.run(["git", "init"])
subprocess.run(["git", "-c", "protocol.file.allow=always", "submodule", "add", "https://github.com/staticafi/libutility.git", "./src/utility"])