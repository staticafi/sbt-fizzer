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
    parser.add_argument('file', 
                        help='Path to the file you want to fuzz.',
                        type=Path)
    parser.add_argument('--output_dir', 
                        type=Path,
                        default=Path(), 
                        help="Output directory.")
    parser.add_argument('--save_mapping',
                        action="store_true", 
                        help=(
                        "When specified, then there is also saved "
                        "mapping of instrumented instruction to the "
                        "original C code."
                        ))
    parser.add_argument('--suppress_all_warnings',
                        action="store_true", 
                        help=(
                        "When specified, then Clang compiler won't "
                        "generate any warning for the compiled C code."
                        ))

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
    fuzz_target_libraries = " ".join(map( # type: ignore
        lambda rel_path, script_dir=script_dir: str(script_dir / rel_path), 
        @FUZZ_TARGET_LIBRARIES_FILES_LIST@ # type: ignore
    ))
    
    fuzz_target_cmake_build_flags = (
                                "-flto "
                                "@FUZZ_TARGET_NEEDED_COMPILATION_FLAGS@"
                                )
    instrumenter_path = script_dir / "@FIZZER_INSTRUMENTER_FILE@"
    server_path = script_dir / "@SERVER_FILE@"
    client_path = script_dir / "@CLIENT_FILE@"

    def __init__(self, file_path, output_dir):
        self.file_path = file_path
        file_name = file_path.stem
        if file_name.endswith("_instrumented"):
            self.file_name = file_name[:-len("_instrumented")]
        else:
            self.file_name = file_name
        self.file_suffix = self.file_path.suffix
        self.output_dir = output_dir.absolute()


    def instrument(self, additional_flags="", timeout=None, save_mapping=False, suppress_all_warnings=False):
        if self.file_suffix.lower() == ".c" or self.file_suffix.lower() == ".i":
            self.file_suffix = ".ll"
            out_path = Path(str(self.file_path)[:-2] + self.file_suffix)
            warning_suppression = "-Wno-everything " if suppress_all_warnings is True else ""
            compile_output = subprocess.run(
                shlex.split("clang -g -S -emit-llvm " + warning_suppression + str(self.file_path) + " -o " + str(out_path)), timeout=timeout
            )
            if compile_output.returncode:
                errprint("Compilation of the C file has failed")
                sys.exit(1)
            self.file_path = out_path
    
        instrumented_file_name = self.file_name + "_instrumented.ll"
        self.instrumented_file = self.output_dir / instrumented_file_name
    
        assert self.file_suffix == ".ll" or self.file_suffix == ".bc", "A LLVM file is required for the instrumentation."

        instrumentation = (str(self.instrumenter_path) +
            " --input " + str(self.file_path) +
            " --output " + str(self.instrumented_file) +
            (" --save_mapping" if save_mapping else "")
            )

        instrumentation_output = subprocess.run(
            shlex.split(instrumentation), timeout=timeout
        )
        if instrumentation_output.returncode:
            errprint("Instrumentation of file failed")
            sys.exit(1)
        

    def build_fuzz_target(self, additional_flags="", timeout=None):
        fuzz_target_file_name = self.file_name + "_sbt-fizzer_target"
        self.fuzz_target_file = self.output_dir / fuzz_target_file_name

        fuzz_target_compilation = "clang++ {0} {1} {2} {3} -o {4}".format(
            self.fuzz_target_cmake_build_flags, additional_flags, 
            self.instrumented_file, self.fuzz_target_libraries, self.fuzz_target_file
        )

        compilation_output = subprocess.run(
            shlex.split(fuzz_target_compilation), timeout=timeout
        )
        if compilation_output.returncode:
            errprint("Compilation of fuzz_target failed")
            sys.exit(1)

        
    def run_fuzzing(self, server_options=""):
        server_invocation = (
            "{0} {1} --path_to_target {2} --output_dir {3}"
            ).format(
                self.server_path, server_options,
                self.fuzz_target_file, self.output_dir
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
        description="Tool for instrumenting the program, building the fuzz target "
                    "and running fuzzing in one command.",
        epilog="Any additional arguments are passed to the server.")

    add_base_args(parser)
    add_instr_args(parser)
    
    parser.add_argument('--clang', 
                        default="-O3",
                        metavar="FLAGS", 
                        help=(
                            'Additional clang++ flags to use ' 
                            'while compiling the fuzz target. ' 
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
    
    utils = FizzerUtils(args.file, args.output_dir)
    starting_time = time.time()
    if args.no_instrument:
        utils.instrumented_file = utils.file_path
    else:
        print("Instrumenting target...", flush=True)
        try:
            utils.instrument(args.instrument, timeout=args.max_seconds, save_mapping=args.save_mapping)
        except subprocess.TimeoutExpired as e:
            errprint(f"Instrumentation timed out after {e.timeout:.3f} seconds")
            sys.exit(1)
        print(
            (f"Instrumentation done "
            f"({adjust_timeout_by_elapsed(args, starting_time):.3f} seconds)"),
            flush=True
        )

    print("Building fuzz target...", flush=True)
    try:
        utils.build_fuzz_target(args.clang, timeout=args.max_seconds)
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