#!/usr/bin/env python3
import argparse
from pathlib import Path


if __name__ == '__main__':
    from importlib.util import spec_from_loader, module_from_spec
    from importlib.machinery import SourceFileLoader 

    spec = spec_from_loader(
        "@FIZZER_TARGET_NAME@", 
        SourceFileLoader(
            "@FIZZER_TARGET_NAME@", 
            str(Path(__file__).resolve().parent / "@FIZZER_TARGET_NAME@")
            )
        )
    fizzer = module_from_spec(spec)
    spec.loader.exec_module(fizzer)

    parser = argparse.ArgumentParser(
        description=(
            "Tool for instrumenting the program and " 
            "building the client in one command."
        ),
        epilog=(
            "Any additional arguments are passed to clang/opt "  
            "as flags to use while compiling the client."
        ))
    fizzer.add_base_args(parser)
    fizzer.add_instr_args(parser)

    args, clang_args = parser.parse_known_args()
    pass_to_clang_args_str = " ".join(clang_args)

    utils = fizzer.FizzerUtils(args.target_file, args.output_dir)
    if args.no_instrument:
        utils.instrumented_file = utils.file_path
    else:
        utils.instrument(args.instrument, save_mapping=args.save_mapping)
    utils.build_client(pass_to_clang_args_str)