import os
import sys
import json
import shutil
import platform
import argparse


def ASSUMPTION(cond, msg="Unknown."):
    if not cond:
        raise Exception(msg)


def quote(path : str) -> str:
    return '"' + path + '"'


def kill_clients():
    if platform.system() == "Windows":
        pass # TODO!
    else:
        os.system("pgrep --full \".sbt-client\" | xargs -r kill")


class Benchmark:
    def __init__(self, pathname : str, llvm_instumenter : str, client_builder : str, server : str, verbose : bool) -> None:
        self.llvm_instumenter = llvm_instumenter
        self.client_builder = client_builder
        self.server = server
        self.verbose = verbose

        self.python_binary = sys.executable

        self.work_dir = os.path.dirname(pathname).replace("\\", "/")
        self.fname = os.path.basename(pathname)
        self.name = os.path.splitext(self.fname)[0]

        self.src_file = os.path.join(self.work_dir, self.fname)
        self.config_file = os.path.join(self.work_dir, self.name + ".json")
        self.ll_file = os.path.join(self.work_dir, self.name + ".ll")
        self.instrumented_ll_file = os.path.join(self.work_dir, self.name + "_instrumented.ll")
        self.client_file = os.path.join(self.work_dir, self.name + "_client")
        self.final_file = os.path.join(self.work_dir, self.name + ".sbt-client")

        self.dir_stack = []

    def pushd(self, folder : str) -> None:
        self.dir_stack.append(os.getcwd())
        os.chdir(folder)

    def popd(self) -> str:
        ASSUMPTION(len(self.dir_stack) > 0, "Cannot pop from the empty stack of directories.")
        os.chdir(self.dir_stack[-1])
        del self.dir_stack[-1]

    def log(self, message : str, brief_message: str = None) -> None:
        if self.verbose:
            print(">>> " + message)
        elif brief_message is not None:
            print(brief_message, end="")

    def _erase_file_if_exists(self, pathname : str) -> None:
        if os.path.exists(pathname):
            self.log("remove " + pathname)
            os.remove(pathname)

    def _erase_dir_if_exists(self, pathname : str) -> None:
        if os.path.exists(pathname):
            self.log("rmtree " + pathname)
            shutil.rmtree(pathname)

    def _compute_output_dir(self, benchmarks_root_dir : str, output_root_dir : str):
        return os.path.splitext(os.path.join(output_root_dir, os.path.relpath(self.src_file, benchmarks_root_dir)))[0]

    def _execute(self, cmdline : str, output_dir : str) -> None:
        self.pushd(output_dir)
        self.log(cmdline)
        os.system(cmdline)
        self.popd()

    def _execute_and_check_output(self, cmdline : str, desired_output : str, work_dir : str = None) -> None:
        self._execute(cmdline, os.path.dirname(desired_output) if work_dir is None else work_dir)
        ASSUMPTION(os.path.isfile(desired_output), "_execute_and_check_output(): the output is missing: " + desired_output)

    def _check_outcomes(self, config : dict, outcomes : dict):
        checked_properties_and_comparators = {
            "termination_type": "EQ",
            "termination_reason": "EQ",
            "num_executions": "LE",
            "num_covered_branchings": "GE",
            "covered_branchings": None,
            "num_generated_tests": "GE",
            "num_crashes": "GE",
            "num_boundary_violations": "LE"
        }

        def is_valid(obtained, expected, op : str) -> bool:
            if op == "EQ": return obtained == expected
            if op == "NE": return obtained != expected
            if op == "LT": return obtained < expected
            if op == "LE": return obtained <= expected
            if op == "GT": return obtained > expected
            if op == "GE": return obtained >= expected
            raise Exception("Invalid comparison operator '" + op + "'.")

        for property, expected_value in config["results"].items():
            ASSUMPTION(
                property in checked_properties_and_comparators,
                "Unsupported key '" + property + "' in the 'results' section of benchmark's config JSON file."
                )
            ASSUMPTION(
                property in outcomes,
                "The valid key '" + property + "' was not found in the 'outcomes' JSON file."
                )
            if type(expected_value) in [int, float, str]:
                if not is_valid(outcomes[property], expected_value, checked_properties_and_comparators[property]):
                    return False
            else:
                ASSUMPTION(property == "covered_branchings", "Only 'covered_branchings' can be a 'list' property to check.")
                ASSUMPTION(len(expected_value) % 2 == 0, "Expected covered branchings list must have even number of elements.")
                ASSUMPTION(len(outcomes[property]) % 2 == 0, "Obtained covered branchings list must have even number of elements.")
                def get_branchings(seq : list) -> set:
                    result = set()
                    if len(seq) > 0:
                        for i in range(0, len(seq)-1, 2):
                            result.add((seq[i], seq[i+1]))
                    return result
                expected_branchings = get_branchings(expected_value)
                obtained_branchings = get_branchings(outcomes[property])
                for x in expected_branchings:
                    if x not in obtained_branchings:
                        return False
        return True

    def build(self, benchmarks_root_dir : str, output_root_dir : str) -> None:
        self.log("===")
        self.log("=== Building: " + self.src_file, "building: " + os.path.relpath(self.src_file, os.path.dirname(self.work_dir)) + " ... ")
        self.log("===")
        self._erase_file_if_exists(self.client_file)
        self._erase_file_if_exists(self.final_file)

        output_dir = self._compute_output_dir(benchmarks_root_dir, output_root_dir)
        self.log("makedirs " + output_dir)
        os.makedirs(output_dir, exist_ok=True)

        if not os.path.exists(self.ll_file):
            # self._execute_and_check_output("clang -g -S -emit-llvm " + quote(self.src_file), self.ll_file)
            self._execute_and_check_output(
                quote(self.python_binary) + " " + quote(self.llvm_instumenter) + " " +
                    "--output_dir " + quote(self.work_dir) + " " +
                    quote(self.src_file) + " "
                    "--save_mapping " +
                    "--suppress_all_warnings",
                self.ll_file,
                output_dir
                )
        if not os.path.exists(self.instrumented_ll_file):
            self._execute_and_check_output(
                quote(self.python_binary) + " " + quote(self.llvm_instumenter) + " " +
                    "--output_dir " + quote(self.work_dir) + " " +
                    quote(self.ll_file) + " "
                    "--save_mapping",
                self.instrumented_ll_file,
                output_dir
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
        ASSUMPTION(os.path.isfile(self.final_file), "build(): the output is missing: " + self.final_file)
        self.log("Done", "Done\n")

    def fuzz(self, benchmarks_root_dir : str, output_root_dir : str) -> bool:
        self.log("===")
        self.log("=== Fuzzing: " + self.src_file, "fuzzing: " + os.path.relpath(self.src_file, os.path.dirname(self.work_dir)) + " ... ")
        self.log("===")
        if self.work_dir.endswith("pending"):
            self.log("The outcomes are as IGNORED => the test has PASSED.", "ignored\n")
            return True
        with open(self.config_file, "rb") as fp:
            config = json.load(fp)
        ASSUMPTION(all(x in config for x in ["args", "results"]), "Cannot find 'args' or 'results' in the benchmark's JSON file.")
        ASSUMPTION(all(x in config["args"] for x in [
            "max_executions",
            "max_seconds",
            "max_trace_length",
            "max_stdin_bytes",
            "max_exec_milliseconds",
            "max_exec_megabytes",
            "stdin_model",
            "stdout_model",
            "optimizer_max_seconds",
            "optimizer_max_trace_length",
            "optimizer_max_stdin_bytes"
            ]), "Benchmark's JSON file does not contain all required options for running the tool.")

        output_dir = self._compute_output_dir(benchmarks_root_dir, output_root_dir)

        self.log("makedirs " + output_dir)
        os.makedirs(output_dir, exist_ok=True)
        kill_clients()
        self._execute(
            quote(self.server) + " " +
                "--path_to_client " + quote(self.final_file) + " " +
                "--max_executions " + str(config["args"]["max_executions"]) + " " +
                "--max_seconds " + str(config["args"]["max_seconds"]) + " " +
                "--max_trace_length " + str(config["args"]["max_trace_length"]) + " " +
                "--max_stdin_bytes " + str(config["args"]["max_stdin_bytes"]) + " " +
                "--max_exec_milliseconds " + str(config["args"]["max_exec_milliseconds"]) + " " +
                "--max_exec_megabytes " + str(config["args"]["max_exec_megabytes"]) + " " +
                "--stdin_model " + config["args"]["stdin_model"] + " " +
                "--stdout_model " + config["args"]["stdout_model"] + " " +
                "--optimizer_max_seconds " + str(config["args"]["optimizer_max_seconds"]) + " " +
                "--optimizer_max_trace_length " + str(config["args"]["optimizer_max_trace_length"]) + " " +
                "--optimizer_max_stdin_bytes " + str(config["args"]["optimizer_max_stdin_bytes"]) + " " +
                "--test_type " + "native" + " " +
                ("--silent_mode " if self.verbose is False else "") +
                "--port " + str(45654)  + " " +
                "--output_dir " + quote(output_dir),
            output_dir
            )

        try:
            outcomes_pathname = os.path.join(output_dir, self.name + "_outcomes.json")
            with open(outcomes_pathname, "rb") as fp:
                outcomes = json.load(fp)
            if self._check_outcomes(config, outcomes) is True:
                self.log("The outcomes are as expected => the test has PASSED.", "ok\n")
                return True
        except Exception as e:
            self.log("FAILURE due to an EXCEPTION: " + str(e), "EXCEPTION[" + str(e) + "]\n")
            return False
        self.log("The outcomes are NOT as expected => the test has FAILED.", "FAILED\n")
        return False

    def clear(self, benchmarks_root_dir : str, output_root_dir : str) -> None:
        self.log("===")
        self.log("=== Clearing: " + self.src_file, "clearing: " + os.path.relpath(self.src_file, os.path.dirname(self.work_dir)) + " ... ")
        self.log("===")
        self._erase_file_if_exists(self.ll_file)
        self._erase_file_if_exists(self.instrumented_ll_file)
        self._erase_file_if_exists(self.client_file)
        self._erase_file_if_exists(self.final_file)
        self._erase_dir_if_exists(self._compute_output_dir(benchmarks_root_dir, output_root_dir))
        self.log("Done", "Done\n")


class Benman:
    def __init__(self) -> None:
        parser = argparse.ArgumentParser(description="Builds the client for the benchmark(s) or fuzz the benchmark(s).")
        parser.add_argument("--clear", action='store_true', help="Clears the build files and outputs of the input benchmark(s).")
        parser.add_argument("--build", action='store_true', help="Builds the input benchmark(s).")
        parser.add_argument("--fuzz", action='store_true', help="Applies fuzzing on the input benchmark(s).")
        parser.add_argument("--input", help="Benchmark(s) to be processed. Possible values: "
                                           "all, fast, medium, slow, pending, fast/..., medium/..., slow/..., pending/...")
        parser.add_argument("--verbose", action='store_true', help="Enables the verbose mode.")
        self.args = parser.parse_args()

        self.python_binary = '"' + sys.executable + '"'
        self._benchmarks_dir = os.getcwd()
        self.benchmarks_dir = self._benchmarks_dir
        self.output_dir = os.path.normpath(os.path.join(self._benchmarks_dir, "..", "output", "benchmarks"))
        self.tools_dir = os.path.normpath(os.path.join(self._benchmarks_dir, "..", "tools"))
        ASSUMPTION(os.path.isdir(self.tools_dir), "The tools install directory not found. Build and install the project first.")
        self.lib_dir = os.path.normpath(os.path.join(self._benchmarks_dir, "..", "lib"))
        ASSUMPTION(os.path.isdir(self.lib_dir), "The lib install directory not found. Build and install the project first.")
        self.llvm_instrumenter = os.path.join(self.tools_dir, "sbt-fizzer_instrument")
        ASSUMPTION(os.path.isfile(self.llvm_instrumenter), "The llvm instrumentation script not found. Build and install the project first.")
        self.client_builder = os.path.join(self.tools_dir, "sbt-fizzer_build_client")
        ASSUMPTION(os.path.isfile(self.client_builder), "The client build script not found. Build and install the project first.")
        self.server_binary = self._find_binary_file(self.tools_dir, "server_")
        ASSUMPTION(self.server_binary is not None, "The server binary not found. Build and install the project first.")
        self.llvm_pass_binary = self._find_binary_file(self.lib_dir, "sbt-fizzer_pass_")
        ASSUMPTION(self.llvm_pass_binary is not None, "The server binary not found. Build and install the project first.")

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
            ASSUMPTION(os.path.isfile(pathname), "The benchmark path is invalid: " + pathname)
            ASSUMPTION(os.path.isfile(os.path.splitext(pathname)[0] + ".json"), "Missing '.json' file for benchmark: " + pathname)
            return pathname

        def search_for_benchmarks(folder : str) -> list:
            benchmarks = []
            pathname = os.path.join(self.benchmarks_dir, folder)
            if os.path.isdir(pathname):
                for name in os.listdir(pathname):
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
        return sorted(benchmarks)

    def build(self, name : str) -> bool:
        for pathname in self.collect_benchmarks(name):
            benchmark = Benchmark(pathname, self.llvm_instrumenter, self.client_builder, self.server_binary, self.args.verbose)
            benchmark.build(self.benchmarks_dir, self.output_dir)
        return True

    def fuzz(self, name : str) -> bool:
        num_failures = 0
        benchmark_paths = self.collect_benchmarks(name)
        for pathname in benchmark_paths:
            benchmark = Benchmark(pathname, self.llvm_instrumenter, self.client_builder, self.server_binary, self.args.verbose)
            if not benchmark.fuzz(self.benchmarks_dir, self.output_dir):
                num_failures += 1
        kill_clients()
        if num_failures > 0:
            print("FAILURE[" + str(num_failures) + "/" + str(len(benchmark_paths)) + "]")
            return False
        else:
            print("SUCCESS")
            return True

    def clear(self, name : str) -> None:
        for pathname in self.collect_benchmarks(name):
            benchmark = Benchmark(pathname, self.llvm_instrumenter, self.client_builder, self.server_binary, self.args.verbose)
            benchmark.clear(self.benchmarks_dir, self.output_dir)
        return True

    def run(self) -> bool:
        if self.args.clear:
            if self.clear(self.args.input) is False:
                return False
        if self.args.build:
            if self.build(self.args.input) is False:
                return False
        if self.args.fuzz:
            if self.fuzz(self.args.input) is False:
                return False
        return True

if __name__ == '__main__':
    exit_code = 0
    try:
        benman = Benman()
        if benman.run() is False:
            exit_code = 1
    except Exception as e:
        exit_code = 1
        print("ERROR: " + str(e))
    exit(exit_code)
