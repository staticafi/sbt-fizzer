#!/usr/bin/env python3
import subprocess
import sys
import os


def _execute(command_and_args, timeout_ = None):
    cmd = [x for x in command_and_args if len(x) > 0]
    # print("*** CALLING ***\n" + " ".join(cmd) + "\n************\n")
    return subprocess.run(cmd, timeout=timeout_)


def  benchmark_file_name(input_file):
    return os.path.basename(input_file)


def  benchmark_name(input_file):
    return os.path.splitext(benchmark_file_name(input_file))[0]


def  benchmark_ll_name(input_file):
    return benchmark_name(input_file) + ".ll"


def  benchmark_instrumented_ll_name(input_file):
    return benchmark_name(input_file) + "_instrumented.ll"


def  benchmark_target_name(input_file):
    return benchmark_name(input_file) + "_sbt-fizzer_target"


def build(self_dir, input_file, output_dir, options, use_m32):
    ll_file = os.path.join(output_dir, benchmark_ll_name(input_file))
    if _execute(
            [ "clang" ] +
                (["-m32"] if use_m32 is True else []) +
                [ "-O0", "-g", "-S", "-emit-llvm", "-Wno-everything", "-fbracket-depth=1024", input_file, "-o", ll_file],
            None).returncode:
        raise Exception("Compilation has failed: " + input_file)

    instrumented_ll_file = os.path.join(output_dir, benchmark_instrumented_ll_name(input_file))
    if _execute(
            [ os.path.join(self_dir, "tools", "@FIZZER_INSTRUMENTER_FILE@") ] +
                options +
                ["--input", ll_file, "--output", instrumented_ll_file],
            None).returncode:
        raise Exception("Instrumentation has failed: " + ll_file)


    fuzz_target_libraries = list(map( # type: ignore
        lambda lib_name: os.path.join(self_dir, "lib32" if use_m32 is True else "lib", lib_name).replace("\\", "/"), 
        @FUZZ_TARGET_LIBRARIES_FILES_LIST@ # type: ignore
        ))
    target_file = os.path.join(output_dir, benchmark_target_name(input_file))
    if _execute(
            [ "clang++" ] +
                (["-m32"] if use_m32 is True else []) +
                [ "-O3", instrumented_ll_file ] +
                "@FUZZ_TARGET_NEEDED_COMPILATION_FLAGS@".split() +
                fuzz_target_libraries +
                [ "-o", target_file ],
            None).returncode:
        raise Exception("Compilation has failed: " + input_file)


def fuzz(self_dir, input_file, output_dir, options):
    target = os.path.join(output_dir, benchmark_target_name(input_file))
    if not os.path.isfile(target):
        target = os.path.join(os.path.dirname(input_file), benchmark_target_name(input_file))
        if not os.path.isfile(target):
            raise Exception("Cannot find the fuzzing target file: " + target)

    if _execute(
            [ os.path.join(self_dir, "tools", "@SERVER_FILE@"),
                "--path_to_target", target,
                "--output_dir", output_dir] +
                options,
            None).returncode:
        raise Exception("Fuzzing has failed.")


def help(self_dir):
    print("sbt-fizzer usage")
    print("================")
    print("help                 Prints this help message.")
    print("input_file <PATH>    A source C file to build and analyze.")
    print("output_dir <PATH>    A directory under which all results will be saved.")
    print("                     If not specified, then the current directory is used.")
    print("skip_building        Skip building of the source C file.")
    print("skip_fuzzing         Skip fuzzing of the built source C file.")
    print("use_network          When specified, the fuzzer will use network communication")
    print("                     instead of shared memory. This option is introduced so that")
    print("                     you do not have to use options 'path_to_target' and")
    print("                     'path_to_client' listed below.")
    print("m32                  When specified, the source C file will be compiled for")
    print("                     32-bit machine (cpu). Otherwise, 64-bit machine is assumed.")
    print("\nNext follows a listing of options of tools called from this script. When they are")
    print("passed to the script they will automatically be propagated to the corresponding tool.")

    print("\nThe options of the LLVM 'instrumenter' tool:")
    _execute([ os.path.join(self_dir, "tools", "@FIZZER_INSTRUMENTER_FILE@"), "--help"], None)
    print("\nThe options of the 'fuzzer' tool (a.k.a. the server):")
    _execute([ os.path.join(self_dir, "tools", "@SERVER_FILE@"), "--help"], None)

    print("\n!!! WARNING !!!!")
    print("An analyzed program is currently *NOT* executed in an isolated environment. It is thus")
    print("*NOT* advised to use it on a C program accessing disk or any other external resource")
    print("(unless you provided the isolation, e.g. by running the analysis in a Docker container).")


def version(self_dir):
    _execute([ os.path.join(self_dir, "tools", "@SERVER_FILE@"), "--version"], None)


def main():
    self_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
    old_cwd = os.path.abspath(os.getcwd())
    input_file = None
    output_dir = old_cwd
    skip_building = False
    skip_fuzzing = False
    use_m32 = False
    options = []
    options_instument = []
    i = 1
    while (i < len(sys.argv)):
        arg = sys.argv[i]
        if arg == "--help":
            help(self_dir)
            return
        if arg == "--version":
            version(self_dir)
            return
        if arg == "--input_file" and i+1 < len(sys.argv) and os.path.isfile(sys.argv[i+1]):
            input_file = os.path.normpath(os.path.abspath(sys.argv[i+1]))
            i += 1
        elif arg == "--output_dir" and i+1 < len(sys.argv) and not os.path.isfile(sys.argv[i+1]):
            output_dir = os.path.normpath(os.path.abspath(sys.argv[i+1]))
            os.makedirs(output_dir, exist_ok=True)
            i += 1
        elif arg == "--use_network":
            options.append("--path_to_client")
            options.append(os.path.join(self_dir, "tools", "@CLIENT_FILE@"))
        elif arg == "--skip_building":
            skip_building = True
        elif arg == "--skip_fuzzing":
            skip_fuzzing = True
        elif arg in [ "--save_mapping", "--br_too" ]:
            options_instument.append(arg)
        elif arg == "--m32":
            use_m32 = True
        else:
            options.append(arg)
        i += 1

    if input_file is None:
        raise Exception("Cannot find the input file.")

    old_cwd = os.getcwd()
    os.chdir(output_dir)
    try:
        if skip_building is False:
            build(self_dir, input_file, output_dir, options_instument, use_m32)
        if skip_fuzzing is False:
            fuzz(self_dir, input_file, output_dir, options)
    except Exception as e:
        os.chdir(old_cwd)
        raise e


if __name__ == "__main__":
    exit_code = 0
    try:
        main()
    except Exception as e:
        exit_code = 1
        print("ERROR: " + str(e))
    exit(exit_code)
