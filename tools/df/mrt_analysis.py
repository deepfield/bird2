import argparse
from .mrtanalysis.analysis import Analysis


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v", "--verbose", action="store_true", default=False, help="verbose output"
    )
    parser.add_argument("--version", action="version", version="%{prog} 0.0.1")
    parser.add_argument(
        "--progress", action="store_true", default=False, help="show progress"
    )
    parser.add_argument(
        "--errors",
        action="store_true",
        default=False,
        help="show detailed error messages",
    )
    parser.add_argument(
        "--bgp", action="store_true", default=True, help="show stats on bgp attributes"
    )
    parser.add_argument(
        "--seen",
        action="store_true",
        default=False,
        help="show stats on seen attributes",
    )
    parser.add_argument(
        "--hexdump",
        action="store_true",
        default=False,
        help="hexdump the header and rib entry blocks",
    )
    parser.add_argument(
        "--blockdump",
        action="store_true",
        default=False,
        help="detail analysis of the payload blocks",
    )
    parser.add_argument(
        "files", type=str, nargs="+", default=[], help="mrt files to parse"
    )
    args = parser.parse_args()
    return args


def main():
    args = parse_args()

    for f in args.files:
        the_analysis = Analysis()
        the_analysis.show_progress = args.progress
        the_analysis.block_analysis(f, args)
        the_analysis.report(args)
        if args.hexdump:
            the_analysis.hexdump(args)
        if args.blockdump:
            the_analysis.blockdump()


if __name__ == "__main__":
    main()
