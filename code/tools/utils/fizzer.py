#!/usr/bin/env python3
import subprocess
import argparse
import sys
from pathlib import Path

def errprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def add_base_args(parser):
    parser.add_argument('target_file', 
                        help='Path to target .c, .ll or .bc file.',
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
    client_libraries = "@CLIENT_LIBRARIES_FILES@"
    client_cmake_build_flags = (
                                "-flto "
                                "@CLIENT_NEEDED_COMPILATION_FLAGS@"
                                )
    pass_path_str = "@FIZZER_PASS_FILE@"
    server_path_str = "@SERVER_FILE@"

    def __init__(self, file_path, output_dir):
        self.file_path = file_path
        file_name = file_path.stem
        if file_name.endswith("_instrumented"):
            self.file_name = file_name[:-len("_instrumented")]
        else:
            self.file_name = file_name
        self.file_suffix = self.file_path.suffix
        self.output_dir = output_dir.absolute()


    def instrument(self, additional_flags=""):
        instrumented_file_name = self.file_name + "_instrumented.ll"
        self.instrumented_file = self.output_dir / instrumented_file_name
    
        if self.file_suffix == ".c":
            instrumentation = (
                "clang {0} -flto -flegacy-pass-manager " 
                "-Xclang -load -Xclang {1} "
                "-Xclang -disable-O0-optnone -fno-discard-value-names {2} "
                "-S -o {3}"
            ).format(
                additional_flags, self.pass_path_str, 
                self.file_path, self.instrumented_file
                )
        elif self.file_suffix == ".ll" or self.file_suffix == ".bc":
            instrumentation = (
                "opt -enable-new-pm=0 -load {0} -legacy-fizzer-pass " 
                "{1} -S -o {2}"
            ).format(self.pass_path_str, self.file_path, self.instrumented_file)
        else:
            errprint("Unknown file extension, expected .c, .ll or .bc")
            sys.exit(1)

        instrumentation_output = subprocess.run(instrumentation, shell=True)
        if instrumentation_output.returncode:
            errprint("Instrumentation of file failed")
            sys.exit(1)
        

    def build_client(self, additional_flags=""):
        client_file_name = self.file_name + "_client"
        self.client_file = self.output_dir / client_file_name

        client_compilation = "clang++ {0} {1} {2} {3} -o {4}".format(
            self.client_cmake_build_flags, additional_flags, 
            self.instrumented_file, self.client_libraries, self.client_file
        )

        compilation_output = subprocess.run(client_compilation, shell=True)
        if compilation_output.returncode:
            errprint("Compilation of client failed")
            sys.exit(1)

        
    def run_fuzzing(self, server_options=""):
        server_invocation = (
            "{0} {1} --path_to_client {2} --output_dir {3}"
            ).format(
                self.server_path_str, server_options, 
                self.client_file, self.output_dir
        )

        invocation_output = subprocess.run(server_invocation, shell=True)
        if invocation_output.returncode:
            errprint("Running fuzzing failed")
            sys.exit(1)


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
    

    args, server_args = parser.parse_known_args()
    pass_to_server_args_str = " ".join(server_args)
    
    utils = FizzerUtils(args.target_file, args.output_dir)
    if args.no_instrument:
        utils.instrumented_file = utils.file_path
    else:
        utils.instrument(args.instrument)
    utils.build_client(args.clang)
    utils.run_fuzzing(pass_to_server_args_str)