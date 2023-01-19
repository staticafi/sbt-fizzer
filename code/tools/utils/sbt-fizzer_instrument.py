#!/usr/bin/env python3
import argparse


if __name__ == '__main__':
    from importlib.util import spec_from_loader, module_from_spec
    from importlib.machinery import SourceFileLoader 

    spec = spec_from_loader(
        "@FIZZER_TARGET_NAME@", 
        SourceFileLoader(
            "@FIZZER_TARGET_NAME@", 
            "@CMAKE_INSTALL_PREFIX@/tools/@FIZZER_TARGET_NAME@"))
    fizzer = module_from_spec(spec)
    spec.loader.exec_module(fizzer)

    parser = argparse.ArgumentParser(
        description="Tool for instrumenting the program.",
        epilog=(
            "Any additional arguments are " 
            "passed to clang/opt as flags to use."
        ))
    fizzer.add_base_args(parser)

    args, instr_args = parser.parse_known_args()
    pass_to_instr_args_str = " ".join(instr_args)

    utils = fizzer.FizzerUtils(args.target_file, args.output_dir)
    utils.instrument(pass_to_instr_args_str)