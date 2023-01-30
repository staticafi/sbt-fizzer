#!/usr/bin/env python3
import argparse
import os
import sys
import shutil

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=(
            "Utility for building a client executable for a passed .c file. "
            "The resulting client is then in '../temp' folder."
        ))
    parser.add_argument('-c', '--c_file', help='pathname of a C source to be transformed to the client executable.')
    parser.add_argument('-e', "--erase", action='store_true', help='erase all temporary files in the directory of this script.')
    parser.add_argument('-v', "--verbose", action='store_true', help='enables the verbose mode.')
    args = parser.parse_args()

    script_dir = os.path.abspath(os.path.dirname(__file__))
    temp_dir = os.path.join(script_dir, "../temp")
    tools_dir = os.path.join(script_dir, "../dist/tools")

    if args.erase:
        for fname in os.listdir(temp_dir):
            ext = os.path.splitext(fname)[1].lower()
            if os.path.isdir(os.path.join(temp_dir, fname)) and fname == "test-suite":
                shutil.rmtree(os.path.join(temp_dir, fname))
            if ext == ".html" or ext == ".et" or (args.c_file is not None and (fname.endswith("_instrumented.ll") or fname.endswith("client"))):
                if args.verbose:
                    print("> rm " + os.path.join(temp_dir, fname))
                os.remove(os.path.join(temp_dir, fname))

    if args.c_file is not None:

        python_binary = '"' + sys.executable + '"'

        c_file = os.path.abspath(args.c_file).replace("\\", "/")
        ll_file = os.path.join(temp_dir, os.path.splitext(os.path.basename(c_file))[0] + ".ll").replace("\\", "/")
        instrumented_ll_file = (os.path.splitext(ll_file)[0] + "_instrumented.ll").replace("\\", "/")
        client_file = (os.path.splitext(ll_file)[0] + "_client").replace("\\", "/")
        final_file = os.path.join(temp_dir, "client").replace("\\", "/")

        if args.verbose:
            print("> python_binary: " + python_binary)
            print("> c_file: " + c_file)
            print("> ll_file: " + ll_file)
            print("> instrumented_ll_file: " + instrumented_ll_file)
            print("> client_file: " + client_file)
            print("> final_file: " + final_file)

        if not os.path.isfile(c_file):
            print("ERROR: Cannot access: " + c_file)
            exit(1)

        os.chdir(temp_dir)

        if not os.path.exists(ll_file):
            if args.verbose:
                print("> clang -S -emit-llvm " + c_file)
            os.system("clang -S -emit-llvm " + c_file)
            if not os.path.isfile(ll_file):
                print("ERROR: Cannot access: " + ll_file)
                exit(1)

            
        if not os.path.exists(instrumented_ll_file):
            if args.verbose:
                print("> " + python_binary + " " + tools_dir + "/sbt-fizzer_instrument --output_dir ./ " + ll_file)
            os.system(python_binary + " " + tools_dir + "/sbt-fizzer_instrument --output_dir ./ " + ll_file)
            if not os.path.isfile(instrumented_ll_file):
                print("ERROR: Cannot access: " + instrumented_ll_file)
                exit(1)

        if os.path.exists(client_file):
            if args.verbose:
                print("> rm " + client_file)
            os.remove(client_file)

        if args.verbose:
            print("> " + python_binary + " " + tools_dir + "/sbt-fizzer_build_client --no_instrument --output_dir ./ " + instrumented_ll_file)
        os.system(python_binary + " " + tools_dir + "/sbt-fizzer_build_client --no_instrument --output_dir ./ " + instrumented_ll_file)
        if not os.path.isfile(client_file):
            print("ERROR: Cannot access: " + client_file)
            exit(1)

        if os.path.isfile(final_file):
            os.remove(final_file)
        if args.verbose:
            print("> mv " + client_file + " " + final_file)
        os.rename(client_file, final_file)
