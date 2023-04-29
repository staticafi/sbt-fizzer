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
        description="Tool for instrumenting the program.",
        epilog=(
            "Any additional arguments are " 
            "passed to clang as flags to use."
        ))
    fizzer.add_base_args(parser)

    args, instr_args = parser.parse_known_args()
    pass_to_instr_args_str = " ".join(instr_args)

    utils = fizzer.FizzerUtils(args.file, args.output_dir)
    utils.instrument(
        pass_to_instr_args_str,
        save_mapping=args.save_mapping,
        suppress_all_warnings=args.suppress_all_warnings
        )
