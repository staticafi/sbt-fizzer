#!/usr/bin/env python3
import subprocess
import argparse
import sys
import shlex
import time
from pathlib import Path

def errprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def add_base_args(parser):
    parser.add_argument('target_file', 
                        help='Path to target file.',
                        type=Path)
    parser.add_argument('--output_dir', 
                        type=Path,
                        default=Path(), 
                        help="Output directory.")

def add_instr_args(parser):
    instr_group = parser.add_mutually_exclusive_group()
    instr_group.add_argument('--no_instrument',
                             action="store_true", 
                             help=(
                                "Skip instrumentation. Use if the .ll or .bc "
                                "file is already instrumented."
                             ))
    instr_group.add_argument('--instrument', 
                             default="-O0",
                             metavar="FLAGS", 
                             help=(
                                "Additional flags for clang/opt to use while "
                                "instrumenting the program. Use as "
                                "--instrument=\"FLAGS\". Default: %(default)s."
                             ))


class FizzerUtils:
    script_dir = Path(__file__).resolve().parent
    client_libraries = " ".join(map( # type: ignore
        lambda rel_path, script_dir=script_dir: str(script_dir / rel_path), 
        @CLIENT_LIBRARIES_FILES_LIST@ # type: ignore
    ))
    
    client_cmake_build_flags = (
                                "-flto "
                                "@CLIENT_NEEDED_COMPILATION_FLAGS@"
                                )
    pass_path = script_dir / "@FIZZER_PASS_FILE@"
    server_path = script_dir / "@SERVER_FILE@"

    def __init__(self, file_path, output_dir):
        self.file_path = file_path
        file_name = file_path.stem
        if file_name.endswith("_instrumented"):
            self.file_name = file_name[:-len("_instrumented")]
        else:
            self.file_name = file_name
        self.file_suffix = self.file_path.suffix
        self.output_dir = output_dir.absolute()


    def instrument(self, additional_flags="", timeout=None):
        instrumented_file_name = self.file_name + "_instrumented.ll"
        self.instrumented_file = self.output_dir / instrumented_file_name
    
        if self.file_suffix == ".ll" or self.file_suffix == ".bc":
            instrumentation = (
                "opt @OPT_USE_LEGACY_PM@ -load {0} -legacy-sbt-fizzer-pass " 
                "{1} -S -o {2}"
            ).format(self.pass_path, self.file_path, self.instrumented_file)
        else:
            instrumentation = (
                "clang {0} -flto @CLANG_USE_LEGACY_PM@ " 
                "-Xclang -load -Xclang {1} "
                "-Xclang -disable-O0-optnone -fno-discard-value-names {2} "
                "-S -o {3}"
            ).format(
                additional_flags, self.pass_path, 
                self.file_path, self.instrumented_file
                )

        instrumentation_output = subprocess.run(
            shlex.split(instrumentation), timeout=timeout
        )
        if instrumentation_output.returncode:
            errprint("Instrumentation of file failed")
            sys.exit(1)

    def compile_program_ll(self):
        self.program_ll = self.output_dir / (self.file_name + ".ll")
        subprocess.run(["clang", "-o", self.program_ll, "-S", "-emit-llvm", self.file_path])
        subprocess.run(["opt", "-lowerswitch", "-S", "-o", self.program_ll, self.program_ll])

    def build_client(self, additional_flags="", timeout=None):
        client_file_name = self.file_name + "_client"
        self.client_file = self.output_dir / client_file_name

        client_compilation = "clang++ {0} {1} {2} {3} -o {4}".format(
            self.client_cmake_build_flags, additional_flags, 
            self.instrumented_file, self.client_libraries, self.client_file
        )

        compilation_output = subprocess.run(
            shlex.split(client_compilation), timeout=timeout
        )
        if compilation_output.returncode:
            errprint("Compilation of client failed")
            sys.exit(1)

        
    def run_fuzzing(self, server_options=""):
        server_invocation = (
            "{0} {1} --path_to_client {2} --path_to_program_ll {3} --output_dir {4}"
            ).format(
                self.server_path, server_options, 
                self.client_file, self.program_ll, self.output_dir
        )

        invocation_output = subprocess.run(shlex.split(server_invocation))
        if invocation_output.returncode:
            errprint("Running fuzzing failed")
            sys.exit(1)


def adjust_timeout_by_elapsed(args, start):
    delta = time.time() - start
    if args.max_seconds:
        args.max_seconds -= int(delta)
    return delta


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Tool for instrumenting the program, building the client "
                    "and running fuzzing in one command.",
        epilog="Any additional arguments are passed to the server.")

    add_base_args(parser)
    add_instr_args(parser)
    
    parser.add_argument('--clang', 
                        default="-O3",
                        metavar="FLAGS", 
                        help=(
                            'Additional clang++ flags to use ' 
                            'while compiling the client. ' 
                            'Use as --clang="FLAGS". Default: %(default)s.'
                        ))

    parser.add_argument('--max_seconds',
                        metavar='SECONDS',
                        type=int,
                        help=(
                            'Maximum allocated time for fuzzing.'
                        ))
    

    args, server_args = parser.parse_known_args()
    pass_to_server_args_str = " ".join(server_args)
    
    utils = FizzerUtils(args.target_file, args.output_dir)
    starting_time = time.time()
    if args.no_instrument:
        utils.instrumented_file = utils.file_path
    else:
        print("Instrumenting target...", flush=True)
        try:
            utils.instrument(args.instrument, timeout=args.max_seconds)
            utils.compile_program_ll()
        except subprocess.TimeoutExpired as e:
            errprint(f"Instrumentation timed out after {e.timeout:.3f} seconds")
            sys.exit(1)
        print(
            (f"Instrumentation done "
            f"({adjust_timeout_by_elapsed(args, starting_time):.3f} seconds)"),
            flush=True
        )

    print("Building client...", flush=True)
    try:
        utils.build_client(args.clang, timeout=args.max_seconds)
    except subprocess.TimeoutExpired as e:
        errprint(f"Building timed out after {e.timeout:.3f} seconds")
        sys.exit(1)
    print(
        (f"Building done "
        f"({adjust_timeout_by_elapsed(args, starting_time):.3f} seconds)"), 
        flush=True
    )

    if args.max_seconds:
        pass_to_server_args_str += f" --max_seconds {args.max_seconds}"

    utils.run_fuzzing(pass_to_server_args_str)
