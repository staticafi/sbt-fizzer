import os
import sys
import json
import shutil
import platform
import argparse


def quote(path : str) -> str:
    return '"' + path + '"'


def kill_clients():
    if platform.system() == "Windows":
        pass # TODO!
    else:
        os.system("pgrep sbt-client | xargs -r kill")


class Benchmark:
    def __init__(self, pathname : str, llvm_instumenter : str, client_builder : str, verbose : bool) -> None:
        self.llvm_instumenter = llvm_instumenter
        self.client_builder = client_builder
        self.verbose = verbose

        self.python_binary = sys.executable

        self.work_dir = os.path.dirname(pathname).replace("\\", "/")
        self.fname = os.path.basename(pathname)
        self.name = os.path.splitext(self.fname)[0]

        self.src_file = os.path.join(self.work_dir, self.fname)
        self.ll_file = os.path.join(self.work_dir, self.name + ".ll")
        self.instrumented_ll_file = os.path.join(self.work_dir, self.name + "_instrumented.ll")
        self.client_file = os.path.join(self.work_dir, self.name + "_client")
        self.final_file = os.path.join(self.work_dir, self.name + ".sbt-client")

        self.dir_stack = []

    def pushd(self, folder : str) -> None:
        self.dir_stack.append(os.getcwd())
        os.chdir(folder)

    def popd(self) -> str:
        assert len(self.dir_stack) > 0
        os.chdir(self.dir_stack[-1])
        del self.dir_stack[-1]

    def log(self, message : str) -> None:
        if self.verbose:
            print(">>> " + message)

    def _erase_file_if_exists(self, pathname : str) -> None:
        if os.path.exists(pathname):
            self.log("remove " + pathname)
            os.remove(pathname)

    def _erase_dir_if_exists(self, pathname : str) -> None:
        if os.path.exists(pathname):
            self.log("rmtree " + pathname)
            shutil.rmtree(pathname)

    def _execute(self, cmdline : str, output_dir : str) -> None:
        self.pushd(output_dir)
        self.log(cmdline)
        os.system(cmdline)
        self.popd()

    def _execute_and_check_output(self, cmdline : str, desired_output : str) -> None:
        self._execute(cmdline, os.path.dirname(desired_output))
        assert os.path.isfile(desired_output), "Output is missing: " + desired_output

    def build(self) -> None:
        self.log("===")
        self.log("=== Building: " + self.src_file)
        self.log("===")
        self._erase_file_if_exists(self.client_file)
        self._erase_file_if_exists(self.final_file)
        if not os.path.exists(self.ll_file):
            self._execute_and_check_output("clang -g -S -emit-llvm " + quote(self.src_file), self.ll_file)
        if not os.path.exists(self.instrumented_ll_file):
            self._execute_and_check_output(
                quote(self.python_binary) + " " + quote(self.llvm_instumenter) + " " +
                    "--output_dir " + quote(self.work_dir) + " " +
                    quote(self.ll_file),
                self.instrumented_ll_file,
                )
        self._execute_and_check_output(
            quote(self.python_binary) + " " + quote(self.client_builder) + " " +
                "--no_instrument " +
                "--output_dir " + quote(self.work_dir) + " " +
                quote(self.instrumented_ll_file),
            self.client_file
            )
        self.log("rename " + quote(self.client_file) + " " + quote(self.final_file))
        os.rename(self.client_file, self.final_file)
        assert os.path.isfile(self.final_file), "Output is missing: " + self.final_file

    def fuzz(self,
        server_pathname : str,
        max_executions: int,
        max_seconds : int,
        max_trace_size : int,
        max_stdin_bits : int,
        test_type : str,
        port : int,
        output_dir : str
        ) -> None:
        self.log("===")
        self.log("=== Fuzzing: " + self.src_file)
        self.log("===")
        self._erase_dir_if_exists(output_dir)
        self.log("makedirs " + output_dir)
        os.makedirs(output_dir)
        kill_clients()
        self._execute(
            quote(server_pathname) + " " +
                "--path_to_client " + quote(self.final_file) + " " +
                "--max_executions " + str(max_executions) + " " +
                "--max_seconds " + str(max_seconds) + " " +
                "--max_trace_size " + str(max_trace_size) + " " +
                "--max_stdin_bits " + str(max_stdin_bits) + " " +
                "--test_type " + test_type + " " +
                "--port " + str(port)  + " " +
                "--output_dir " + quote(output_dir),
            output_dir
            )

    def clear(self, benchmarks_root_dir : str, output_root_dir : str) -> None:
        self.log("===")
        self.log("=== Clearing: " + self.src_file)
        self.log("===")
        self._erase_file_if_exists(self.ll_file)
        self._erase_file_if_exists(self.instrumented_ll_file)
        self._erase_file_if_exists(self.client_file)
        self._erase_file_if_exists(self.final_file)
        self._erase_dir_if_exists(
            os.path.splitext(os.path.join(output_root_dir, os.path.relpath(self.src_file, benchmarks_root_dir)))[0]
            )


class Benman:
    def __init__(self) -> None:
        parser = argparse.ArgumentParser(description="Builds the client for the benchmark(s) or fuzz the benchmark(s).")
        parser.add_argument("--build", help="Build the passed benchmark(s). Possible values: "
                                            "all, fast, medium, slow, pending, fast/..., medium/..., slow/..., pending/...")
        parser.add_argument("--fuzz", help="Fuzz the passed benchmark(s). Possible values: "
                                           "all, fast, medium, slow, pending, fast/..., medium/..., slow/..., pending/...")
        parser.add_argument("--clear", help="Clears outputs of the passed benchmark(s). Possible values: "
                                            "all, fast, medium, slow, pending, fast/..., medium/..., slow/..., pending/...")
        parser.add_argument("--verbose", action='store_true', help="Enables the verbose mode.")
        self.args = parser.parse_args()

        self.python_binary = '"' + sys.executable + '"'
        self._script_dir = os.path.abspath(os.path.dirname(__file__))
        assert os.path.basename(os.path.dirname(self._script_dir)) == "dist", \
            "Run the installed version of script to the 'dist' directory. Build and install the project, if not present."
        self.benchmarks_dir = self._script_dir
        self.output_dir = os.path.normpath(os.path.join(self._script_dir, "..", "output", "benchmarks"))
        self.tools_dir = os.path.normpath(os.path.join(self._script_dir, "..", "tools"))
        assert os.path.isdir(self.tools_dir), "The tools install directory not found. Build and install the project first."
        self.lib_dir = os.path.normpath(os.path.join(self._script_dir, "..", "lib"))
        assert os.path.isdir(self.lib_dir), "The lib install directory not found. Build and install the project first."
        self.llvm_instrumenter = os.path.join(self.tools_dir, "sbt-fizzer_instrument")
        assert os.path.isfile(self.llvm_instrumenter), "The llvm instrumentation script not found. Build and install the project first."
        self.client_builder = os.path.join(self.tools_dir, "sbt-fizzer_build_client")
        assert os.path.isfile(self.client_builder), "The client build script not found. Build and install the project first."
        self.server_binary = self._find_binary_file(self.tools_dir, "server_")
        assert self.server_binary is not None, "The server binary not found. Build and install the project first."
        self.llvm_pass_binary = self._find_binary_file(self.lib_dir, "sbt-fizzer_pass_")
        assert self.llvm_pass_binary is not None, "The server binary not found. Build and install the project first."

    def _find_binary_file(self, folder : str, subname : str) -> str|None:
        second_change = None
        for fname in os.listdir(folder):
            if os.path.isfile(os.path.join(folder, fname)) and subname in fname:
                if "Release" in fname:
                    return os.path.join(folder, fname)
                elif second_change is None:
                    second_change = os.path.join(folder, fname)
        return second_change

    def collect_benchmarks(self, name : str) -> list[str]:
        def complete_and_check_benchmark_path(name : str) -> str:
            pathname = os.path.join(self.benchmarks_dir, name)
            assert os.path.isfile(pathname), "The benchmark path is invalid: " + pathname
            assert os.path.isfile(os.path.splitext(pathname)[0] + ".json"), "Missing '.json' file for benchmark: " + pathname
            return pathname

        def search_for_benchmarks(folder : str) -> list:
            benchmarks = []
            for name in os.listdir(os.path.join(self.benchmarks_dir, folder)):
                if os.path.splitext(name)[1].lower() in [".c", ".i"]:
                    try:
                        benchmarks.append(complete_and_check_benchmark_path(os.path.join(folder, name)))
                    except Exception:
                        pass
            return benchmarks

        kinds = ["fast", "medium", "slow", "pending"]
        benchmarks = []
        if name == "all":
            for kind in kinds:
                benchmarks += search_for_benchmarks(kind)
        elif name in kinds:
            benchmarks += search_for_benchmarks(name)
        else:
            benchmarks.append(complete_and_check_benchmark_path(name))
        return benchmarks

    def build(self, name : str) -> None:
        for pathname in self.collect_benchmarks(name):
            benchmark = Benchmark(pathname, self.llvm_instrumenter, self.client_builder, self.args.verbose)
            benchmark.build()

    def fuzz(self, name : str) -> None:
        for pathname in self.collect_benchmarks(name):
            with open(os.path.splitext(pathname)[0] + ".json", "rb") as fp:
                config = json.load(fp)
            assert all(x in config for x in ["args", "results"]) 
            assert all(x in config["args"] for x in [
                "max_executions",
                "max_seconds",
                "max_trace_size",
                "max_stdin_bits",
                "test_type",
                "port"
                ])
            assert all(x in config["results"] for x in ["num_covered", "num_uncovered"]) 
            benchmark = Benchmark(pathname, self.llvm_instrumenter, self.client_builder, self.args.verbose)
            benchmark.fuzz(
                self.server_binary,
                config["args"]["max_executions"],
                config["args"]["max_seconds"],
                config["args"]["max_trace_size"],
                config["args"]["max_stdin_bits"],
                config["args"]["test_type"],
                config["args"]["port"],
                os.path.splitext(os.path.join(self.output_dir, os.path.relpath(pathname, self.benchmarks_dir)))[0]
            )
        kill_clients()

    def clear(self, name : str) -> None:
        for pathname in self.collect_benchmarks(name):
            benchmark = Benchmark(pathname, self.llvm_instrumenter, self.client_builder, self.args.verbose)
            benchmark.clear(self.benchmarks_dir, self.output_dir)

    def run(self) -> None:
        if self.args.clear:
            assert self.args.clear != '.' or self.args.build is not None
            self.clear(self.args.clear if self.args.clear != '.' else self.args.build)
        if self.args.build:
            self.build(self.args.build)
        if self.args.fuzz:
            self.fuzz(self.args.fuzz)

if __name__ == '__main__':
    try:
        benman = Benman()
        benman.run()
    except Exception as e:
        print("ERROR: " + str(e))
