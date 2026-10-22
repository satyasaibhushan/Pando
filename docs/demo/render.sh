#!/usr/bin/env bash
# Render docs/demo/demo.cast into poster.png, demo.webm and demo.mp4.
# Needs agg (cargo install --git https://github.com/asciinema/agg) and an
# ffmpeg with libvpx-vp9 and libx264. AGG and FFMPEG override the binaries.
set -euo pipefail
cd "$(dirname "$0")"
AGG="${AGG:-agg}"
FFMPEG="${FFMPEG:-ffmpeg}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
style=(--font-family "JetBrains Mono,DejaVu Sans Mono,Liberation Mono" --font-size 28
  --theme github-dark --idle-time-limit 1.5 --last-frame-duration 3)

# Everything before the poster marker, held on its last frame.
python3 - "$work/poster.cast" <<'PY'
import json, sys
lines = open("demo.cast").read().splitlines()
out = [lines[0]]
for line in lines[1:]:
    event = json.loads(line)
    if event[1] == "m" and event[2] == "poster":
        break
    out.append(line)
open(sys.argv[1], "w").write("\n".join(out) + "\n")
PY

"$AGG" "${style[@]}" "$work/poster.cast" "$work/poster.gif"
# -update keeps overwriting one image, so the last frame wins.
"$FFMPEG" -v error -y -i "$work/poster.gif" -update 1 poster.png
"$AGG" "${style[@]}" demo.cast "$work/demo.gif"
scale=(-vf "fps=30,scale=trunc(iw/2)*2:trunc(ih/2)*2")
"$FFMPEG" -v error -y -i "$work/demo.gif" "${scale[@]}" -c:v libvpx-vp9 -crf 34 -b:v 0 -row-mt 1 -an demo.webm
"$FFMPEG" -v error -y -i "$work/demo.gif" "${scale[@]}" -c:v libx264 -crf 22 -pix_fmt yuv420p -movflags +faststart -an demo.mp4
