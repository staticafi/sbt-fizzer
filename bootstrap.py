#!/usr/bin/env python3
import subprocess

subprocess.run(["git", "init"])
subprocess.run(["git", "-c", "protocol.file.allow=always", "submodule", "add", "https://github.com/staticafi/libutility.git", "./src/utility"])
subprocess.run(["git", "-c", "protocol.file.allow=always", "submodule", "add", "https://github.com/staticafi/libsala.git", "./src/sala"])
subprocess.run(["git", "-c", "protocol.file.allow=always", "submodule", "add", "https://github.com/staticafi/libllvmutl.git", "./src/llvmutl"])
subprocess.run(["git", "-c", "protocol.file.allow=always", "submodule", "add", "https://github.com/staticafi/binsalac.git", "./src/tools/salac"])
subprocess.run(["git", "-c", "protocol.file.allow=always", "submodule", "add", "https://github.com/staticafi/binsalat.git", "./src/tools/salat"])
subprocess.run(["git", "-c", "protocol.file.allow=always", "submodule", "add", "https://github.com/staticafi/datsalat.git", "./benchmarks/salatd"])
