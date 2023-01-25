#!/usr/bin/env python3
import argparse
import os

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=(
            "Utility for building a client executable for a passed .c file. "
            "The resulting client is then in '../temp' folder."
        ))
    parser.add_argument('-c', '--c_file', help='pathname of a C source to be transformed to the client executable.')
    parser.add_argument('-e', "--erase", action='store_true', help='erase all temporary files in the directory of this script.')
    args = parser.parse_args()

    script_dir = os.path.abspath(os.path.dirname(__file__))
    temp_dir = os.path.join(script_dir, "../temp")
    tools_dir = os.path.join(script_dir, "../dist/tools")

    if args.erase:
        for fname in os.listdir(temp_dir):
            ext = os.path.splitext(fname)[1].lower()
            if ext == ".html" or ext == ".et" or (args.c_file is not None and (ext == ".ll" or fname == "client")):
                os.remove(os.path.join(temp_dir, fname))

    if args.c_file:
        c_file = os.path.abspath(args.c_file)
        if not os.path.isfile(c_file):
            print("ERROR: Cannot access: " + c_file)
            exit(1)

        os.chdir(temp_dir)

        os.system("clang -S -emit-llvm " + c_file)

        ll_file = os.path.join(temp_dir, os.path.splitext(os.path.basename(c_file))[0] + ".ll")
        if not os.path.isfile(ll_file):
            print("ERROR: Cannot access: " + ll_file)
            exit(1)
        os.system("python3 " + tools_dir + "/sbt-fizzer_instrument --output_dir ./ " + ll_file)

        instrumented_ll_file = os.path.splitext(ll_file)[0] + "_instrumented.ll"
        if not os.path.isfile(instrumented_ll_file):
            print("ERROR: Cannot access: " + instrumented_ll_file)
            exit(1)
        os.system("python3 " + tools_dir + "/sbt-fizzer_build_client --output_dir ./ " + instrumented_ll_file)

        client_file = os.path.splitext(ll_file)[0] + "_client"
        if not os.path.isfile(instrumented_ll_file):
            print("ERROR: Cannot access: " + client_file)
            exit(1)

        final_file = os.path.join(temp_dir, "client")
        if os.path.isfile(final_file):
            os.remove(final_file)
        os.rename(client_file, final_file)
