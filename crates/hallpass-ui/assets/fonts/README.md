# Fonts

`InterUI.ttf` is [Inter](https://github.com/rsms/inter) 4.1 by The Inter
Project Authors, under the SIL Open Font License 1.1 (`OFL.txt`). It is the
window's proportional face; egui's bundled fonts stay behind it as fallbacks
for anything outside the subset.

It is cut down from the release's `InterVariable.ttf` (860 KB) to what the
window uses (160 KB): the optical-size axis pinned to text size, the weight
axis narrowed to 300-700, and the glyphs to Latin, Latin-1, Latin Extended
and common punctuation. To rebuild it, with `fonttools` installed:

```sh
fonttools varLib.instancer InterVariable.ttf opsz=14 wght=300:700 -o pinned.ttf
pyftsubset pinned.ttf \
  --unicodes="U+0020-007E,U+00A0-024F,U+02C6-02DD,U+2000-206F,U+20AC,U+2122,U+2190-2199,U+2212,U+2215,U+2260,U+2264,U+2265,U+FFFD" \
  --layout-features='kern,liga,calt,tnum,case,ccmp,locl,mark,mkmk' \
  --output-file=InterUI.ttf
```
