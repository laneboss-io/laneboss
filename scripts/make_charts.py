"""Draws docs/assets/judge_answers.svg from docs/assets/data/judge_answers.csv.

The chart shows every answer one judge gave in a trial of five hand-written test subjects, each asked nine times, to
the question "is this tool result a refusal?": one dot for each answer, on a scale of 0 to 1, in a row for each kind
of subject. It uses the standard library only and has no clock and no randomness: the same CSV always gives the same
bytes.

    python3 scripts/make_charts.py            writes docs/assets/judge_answers.svg
    python3 scripts/make_charts.py --check    writes nothing; exits 1 when the SVG on disk is not what the CSV gives

The CSV holds two columns, kind and probability, and nothing else. What was measured is stated in README.md under the
chart and in the constants below, and the script stops when the CSV no longer agrees with them: the answers of every
kind must be the subjects of that kind times the number of times each was asked.
"""

import argparse
import csv
import math
from pathlib import Path
import sys
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "docs" / "assets" / "data" / "judge_answers.csv"
OUT = ROOT / "docs" / "assets" / "judge_answers.svg"

# What was measured (the CSV carries only the pairs): five hand-written subjects, each asked nine times, to one judge.
JUDGE = "Jev (model jev-1.13.0)"
DAY = "9 October 2026"
TIMES_EACH = 9
SUBJECTS = {"refusal": ("hook", "harness"), "not a refusal": ("os", "test"), "subject withheld": ("secret",)}
KINDS = tuple(SUBJECTS)
LABEL = {"refusal": "Refusal subjects", "not a refusal": "Subjects that are not refusals",
         "subject withheld": "Subject withheld"}
SLOT = {"refusal": "s1", "not a refusal": "s2", "subject withheld": "s3"}
INK, INK2, RULE = "#0b0b0b", "#52514e", "#dcdbd6"
FILL = {"s1": "#2a78d6", "s2": "#eb6834", "s3": "#1baf7a"}

WIDTH = 560
MARGIN = 28
PLOT_X0, PLOT_X1 = MARGIN, WIDTH - MARGIN
RADIUS = 3
PITCH = 7                         # the distance between the centres of two dots with the same probability
HEAD = 118                        # the title and the lines under it
LABEL_HEIGHT = 52                 # a row's name and its counts, above its dots
PAD = 12

STYLE = """\
svg { --surface: #fcfcfb; --ink: #0b0b0b; --ink2: #52514e; --rule: #dcdbd6;
      --s1: #2a78d6; --s2: #eb6834; --s3: #1baf7a;
      font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
@media (prefers-color-scheme: dark) {
  svg { --surface: #1a1a19; --ink: #f0efec; --ink2: #c3c2b7; --rule: #3b3b38;
        --s1: #3987e5; --s2: #d95926; --s3: #199e70; }
}
.bg { fill: var(--surface); }
.title { font-size: 18px; font-weight: 600; fill: var(--ink); }
.sub { font-size: 13px; fill: var(--ink2); }
.row { font-size: 15px; font-weight: 600; fill: var(--ink); }
.note { font-size: 13px; fill: var(--ink2); }
.small { font-size: 12px; fill: var(--ink2); }
.tick { font-size: 12px; fill: var(--ink2); text-anchor: middle; }
.rule { stroke: var(--rule); stroke-width: 1; }
.dot { stroke: var(--surface); stroke-width: 2; paint-order: stroke; }
.s1 { fill: var(--s1); }
.s2 { fill: var(--s2); }
.s3 { fill: var(--s3); }
"""

SUBTITLE = [
    "One judge, {} on {}.".format(JUDGE, DAY),
    "Five hand-written test subjects, each asked nine times:",
    "is this tool result a refusal? One dot is one answer,",
    "its probability of YES from 0 to 1.",
]
FOOTNOTE = [
    "The subjects were written by hand for the trial, not taken from real",
    "sessions. Nine identical requests each show how stable an answer is,",
    "not how accurate the judge is in general.",
]


def read_answers():
    with open(DATA, encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        header = next(reader)
        if header != ["kind", "probability"]:
            raise SystemExit("{}: the header is not kind,probability".format(DATA))
        answers = {kind: [] for kind in KINDS}
        for number, row in enumerate(reader, 2):
            if len(row) != 2 or row[0] not in answers:
                raise SystemExit("{}:{}: not a kind and a probability".format(DATA, number))
            probability = float(row[1])
            if not 0.0 <= probability <= 1.0:
                raise SystemExit("{}:{}: a probability outside 0 to 1".format(DATA, number))
            answers[row[0]].append(probability)
    for kind in KINDS:
        expected = len(SUBJECTS[kind]) * TIMES_EACH
        if len(answers[kind]) != expected:
            raise SystemExit("{}: {} answers of kind {!r}, but the note in this script says {} subject(s) asked {} "
                             "times: {}".format(DATA, len(answers[kind]), kind, len(SUBJECTS[kind]), TIMES_EACH,
                                                expected))
    return answers


def x_of(probability):
    return PLOT_X0 + probability * (PLOT_X1 - PLOT_X0)


def stack(values):
    """(x, height) of every dot of one row: each at the x of its own probability, and dots with the same probability
    one above the other; the height is that of the dot's centre above the lowest centre."""
    seen = {}
    placed = []
    for value in sorted(values):
        level = seen.get(value, 0)
        seen[value] = level + 1
        placed.append((x_of(value), level * PITCH))
    return placed


def text(x, y, css, content, fill, anchor=None):
    extra = ' text-anchor="{}"'.format(anchor) if anchor else ""
    return '<text x="{:.1f}" y="{:.1f}" class="{}" fill="{}"{}>{}</text>'.format(x, y, css, fill, extra, escape(content))


def build(answers):
    total = sum(len(values) for values in answers.values())
    tallest = max(h for kind in KINDS for _, h in stack(answers[kind]))
    row_height = LABEL_HEIGHT + int(math.ceil(tallest)) + 2 * RADIUS + PAD
    plot_top = HEAD
    plot_bottom = plot_top + row_height * len(KINDS)
    height = plot_bottom + 56 + 18 * len(FOOTNOTE) + 12
    low, high = min(answers["refusal"]), max(answers["refusal"])
    heading = "The two refusal subjects scored {:g} to {:g}".format(low, high)
    names = {kind: ", ".join(SUBJECTS[kind]) for kind in KINDS}
    ranges = {kind: "{:g} to {:g}".format(min(answers[kind]), max(answers[kind])) for kind in KINDS}

    parts = []
    parts.append('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {} {}" width="{}" height="{}" role="img" '
                 'aria-labelledby="title desc">'.format(WIDTH, height, WIDTH, height))
    parts.append('<title id="title">{}: five hand-written test subjects, each asked nine times of one judge</title>'.format(
        escape(heading)))
    summary = "; ".join("{} ({}): {} answers from {}".format(
        LABEL[kind], names[kind], len(answers[kind]), ranges[kind]) for kind in KINDS)
    parts.append('<desc id="desc">One dot is one answer on a scale of 0 to 1: the probability of YES to the question '
                 'whether a tool result is a refusal. {}. {} answers in all, from {} on {}; the subjects were written '
                 'by hand for the trial, and nine identical requests each show how stable an answer is, not how '
                 'accurate the judge is in general.</desc>'.format(escape(summary), total, escape(JUDGE), DAY))
    parts.append("<style>\n{}</style>".format(STYLE))
    parts.append('<rect class="bg" x="0" y="0" width="{}" height="{}" fill="#fcfcfb"/>'.format(WIDTH, height))
    parts.append(text(MARGIN, 36, "title", heading, INK))
    for number, line in enumerate(SUBTITLE):
        parts.append(text(MARGIN, 62 + 17 * number, "sub", line, INK2))

    # Recessive grid: a vertical line at every tenth, a horizontal line above each row and under the last.
    for step in range(11):
        value = step / 10
        parts.append('<line class="rule" x1="{:.1f}" y1="{}" x2="{:.1f}" y2="{}" stroke="{}"/>'.format(
            x_of(value), plot_top, x_of(value), plot_bottom, RULE))
        parts.append(text(x_of(value), plot_bottom + 18, "tick", "{:g}".format(value), INK2))
    for index in range(len(KINDS) + 1):
        y = plot_top + row_height * index
        parts.append('<line class="rule" x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}"/>'.format(
            PLOT_X0, y, PLOT_X1, y, RULE))
    parts.append(text((PLOT_X0 + PLOT_X1) / 2, plot_bottom + 40, "note",
                      "Probability of YES (a refusal), as the judge returned it", INK2, "middle"))

    for index, kind in enumerate(KINDS):
        band_top = plot_top + row_height * index
        baseline = band_top + row_height - PAD          # the bottom of the lowest dots
        parts.append("<g>")
        parts.append("<title>{} ({}): {} answers, from {}</title>".format(
            escape(LABEL[kind]), escape(names[kind]), len(answers[kind]), ranges[kind]))
        parts.append(text(PLOT_X0 + 2, band_top + 24, "row", "{}: {}".format(LABEL[kind], names[kind]), INK))
        parts.append(text(PLOT_X0 + 2, band_top + 43, "note", "{} answers, {}".format(len(answers[kind]), ranges[kind]),
                          INK2))
        for x, rise in stack(answers[kind]):
            parts.append('<circle class="dot {}" cx="{:.1f}" cy="{:.1f}" r="{}" fill="{}" stroke="#fcfcfb" '
                         'stroke-width="2"/>'.format(SLOT[kind], x, baseline - RADIUS - rise, RADIUS, FILL[SLOT[kind]]))
        parts.append("</g>")

    for number, line in enumerate(FOOTNOTE):
        parts.append(text(MARGIN, plot_bottom + 66 + 18 * number, "small", line, INK2))
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def main(arguments=None):
    parser = argparse.ArgumentParser(
        description="Draw docs/assets/judge_answers.svg from docs/assets/data/judge_answers.csv.")
    parser.add_argument("--check", action="store_true",
                        help="write nothing; exit 1 when the SVG on disk is not what the CSV gives")
    options = parser.parse_args(arguments)
    svg = build(read_answers())
    if options.check:
        current = OUT.read_bytes() if OUT.exists() else b""
        if current == svg.encode("utf-8"):
            print("{} is what {} gives".format(OUT.relative_to(ROOT), DATA.relative_to(ROOT)))
            return 0
        print("{} is not what {} gives".format(OUT.relative_to(ROOT), DATA.relative_to(ROOT)))
        return 1
    with open(OUT, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(svg)
    print("wrote {} ({} bytes)".format(OUT.relative_to(ROOT), len(svg.encode("utf-8"))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
