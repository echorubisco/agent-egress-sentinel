#!/usr/bin/env bash
# render.sh -- validate and render the explainer diagrams in this directory.
#
#   ./docs/render.sh                 # validate + render all at 1600px wide
#   ./docs/render.sh check           # validate only, render nothing (CI-safe)
#   ./docs/render.sh 2400            # render at a different width
#   ./docs/render.sh one.svg two.svg # only these files
#
# The .svg files ARE the source: hand-authored, one BRIEF comment at the top
# stating intent, and a stable id on every region so a later edit can target
# one block instead of redrawing. PNGs are throwaway output and live in out/,
# which is gitignored -- GitHub renders the SVG directly, so nothing here needs
# to be committed as raster.
#
# WHAT VALIDATION DOES NOT CATCH: SVG carries no text metrics, so a label that
# overflows its box, collides with a line, or gets clipped by the canvas edge is
# invisible to xmllint and to reading the source. The first version of these
# three passed xmllint with seven such defects in it. Always open the rendered
# PNG and look at it.

set -u
cd "$(dirname "$0")"

WIDTH=1600
OUT=out
MODE=render
FILES=()

for arg in "$@"; do
  case "$arg" in
    check)   MODE=check ;;
    *.svg)   FILES+=("$arg") ;;
    ''|*[!0-9]*) printf 'unknown argument: %s (see header for usage)\n' "$arg" >&2; exit 2 ;;
    *)       WIDTH="$arg" ;;
  esac
done
[ ${#FILES[@]} -eq 0 ] && FILES=(*.svg)

ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; }
info() { printf '  ....  %s\n' "$1"; }

# ------------------------------------------------------------- converter ---
# rsvg-convert is the one that has actually been used here. The others are
# fallbacks so a fresh clone is not stuck; none of them are interchangeable on
# font rendering, so if a diagram looks off, check which one ran.
CONV=""
for c in rsvg-convert magick inkscape; do
  command -v "$c" >/dev/null 2>&1 && { CONV="$c"; break; }
done

render_one() {  # $1 = svg, $2 = png
  case "$CONV" in
    rsvg-convert) rsvg-convert -w "$WIDTH" "$1" -o "$2" ;;
    magick)       magick -background none -density 200 "$1" -resize "${WIDTH}x" "$2" ;;
    inkscape)     inkscape "$1" --export-type=png --export-width="$WIDTH" --export-filename="$2" ;;
  esac
}

# ------------------------------------------------------------------ run ---
fails=0
have_xmllint=$(command -v xmllint >/dev/null 2>&1 && echo yes || echo no)
[ "$have_xmllint" = no ] && info "xmllint not found -- skipping XML validation"

if [ "$MODE" = render ]; then
  [ -z "$CONV" ] && {
    bad "no SVG converter found. brew install librsvg  (or imagemagick / inkscape)"
    exit 1
  }
  info "converter: $CONV   width: ${WIDTH}px   output: $OUT/"
  mkdir -p "$OUT"
fi

for svg in "${FILES[@]}"; do
  [ -f "$svg" ] || { bad "$svg (no such file)"; fails=$((fails+1)); continue; }

  if [ "$have_xmllint" = yes ] && ! xmllint --noout "$svg" 2>/dev/null; then
    bad "$svg (malformed XML)"; fails=$((fails+1)); continue
  fi

  # Convention check, not a syntax check: intent belongs in the file so the next
  # edit does not have to guess it.
  grep -q 'BRIEF' "$svg" || info "$svg has no BRIEF comment -- add one before editing further"

  if [ "$MODE" = check ]; then
    ok "$svg ($(grep -cE '<g id="|<rect id="|<circle id="' "$svg") addressable regions)"
    continue
  fi

  png="$OUT/${svg%.svg}.png"
  if render_one "$svg" "$png" && [ -s "$png" ]; then
    ok "$svg -> $png ($(wc -c < "$png" | tr -d ' ') bytes)"
  else
    bad "$svg (render failed)"; fails=$((fails+1))
  fi
done

echo
if [ "$fails" -ne 0 ]; then
  bad "$fails file(s) failed"
  exit 1
fi
if [ "$MODE" = render ]; then
  info "now LOOK at the PNGs in $OUT/ -- xmllint cannot see text overflow or overlap"
fi
