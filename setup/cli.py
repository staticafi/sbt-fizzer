#!/usr/bin/env python3
import argparse
import os
import sys

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
            if ext == ".html" or ext == ".et" or (args.c_file is not None and (fname.endswith("_instrumented.ll") or fname == "client")):
                if args.verbose:
                    print("> rm " + os.path.join(temp_dir, fname))
                os.remove(os.path.join(temp_dir, fname))

    if args.c_file:
        c_file = os.path.abspath(args.c_file)
        if not os.path.isfile(c_file):
            print("ERROR: Cannot access: " + c_file)
            exit(1)

        os.chdir(temp_dir)

        if args.verbose:
            print("> clang -S -emit-llvm " + c_file)
        os.system("clang -S -emit-llvm " + c_file)

        python_binary = '"' + sys.executable + '"'
            
        ll_file = os.path.join(temp_dir, os.path.splitext(os.path.basename(c_file))[0] + ".ll")
        if not os.path.isfile(ll_file):
            print("ERROR: Cannot access: " + ll_file)
            exit(1)
        if args.verbose:
            print("> " + python_binary + " " + tools_dir + "/sbt-fizzer_instrument --output_dir ./ " + ll_file)
        os.system(python_binary + " " + tools_dir + "/sbt-fizzer_instrument --output_dir ./ " + ll_file)

        instrumented_ll_file = os.path.splitext(ll_file)[0] + "_instrumented.ll"
        if not os.path.isfile(instrumented_ll_file):
            print("ERROR: Cannot access: " + instrumented_ll_file)
            exit(1)
        if args.verbose:
            print("> " + python_binary + " " + tools_dir + "/sbt-fizzer_build_client --output_dir ./ " + instrumented_ll_file)
        os.system(python_binary + " " + tools_dir + "/sbt-fizzer_build_client --output_dir ./ " + instrumented_ll_file)

        client_file = os.path.splitext(ll_file)[0] + "_client"
        if not os.path.isfile(instrumented_ll_file):
            print("ERROR: Cannot access: " + client_file)
            exit(1)

        final_file = os.path.join(temp_dir, "client")
        if os.path.isfile(final_file):
            os.remove(final_file)
        if args.verbose:
            print("> mv " + client_file + " " + final_file)
        os.rename(client_file, final_file)
