#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reject floating-point types and runtime libm use in the portable core."""
import argparse
import pathlib
import re
import sys
import tempfile


COMMENTS_AND_LITERALS = re.compile(
    r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
)
FLOAT_TOKEN = re.compile(r'\b(?:float|double)\b')
MATH_INCLUDE = re.compile(r'^\s*#\s*include\s*[<"]math\.h[>"]', re.MULTILINE)
LIBM_CALL = re.compile(r'\b(?:sin|cos|exp|pow|sqrt|floor|round|lround)\s*\(')


def strip_comments_and_literals(source):
    return COMMENTS_AND_LITERALS.sub(
        lambda match: ''.join('\n' if char == '\n' else ' ' for char in match.group()), source
    )


def scan_file(path, display_name):
    source = path.read_text(encoding='utf-8')
    clean = strip_comments_and_literals(source)
    findings = []
    for pattern in (FLOAT_TOKEN, MATH_INCLUDE, LIBM_CALL):
        for match in pattern.finditer(clean):
            line = clean.count('\n', 0, match.start()) + 1
            findings.append((line, display_name))
    return findings


def scan_sources(root):
    findings = []
    for suffix in ('.c', '.h'):
        for path in sorted((root / 'src').glob('*' + suffix)):
            findings.extend(scan_file(path, path.relative_to(root).as_posix()))
    return sorted(findings)


def negative_control():
    with tempfile.TemporaryDirectory(prefix='genewhip-audio-no-float-') as temporary:
        path = pathlib.Path(temporary) / 'negative.c'
        path.write_text('static double x;\n', encoding='utf-8')
        findings = scan_file(path, 'negative.c')
        if not any(name == 'negative.c' and line == 1 for line, name in findings):
            print('FAIL: negative control was not detected', file=sys.stderr)
            return 1
        print('float in core: negative.c:1')
        print('audio_no_float_negative_control: PASS')
        return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('root', nargs='?', type=pathlib.Path, default=pathlib.Path.cwd())
    parser.add_argument('--negative-control', action='store_true')
    args = parser.parse_args()
    if args.negative_control:
        return negative_control()
    findings = scan_sources(args.root.resolve())
    for line, name in findings:
        print(f'float in core: {name}:{line}', file=sys.stderr)
    if findings:
        return 1
    print('audio_no_float: PASS')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
