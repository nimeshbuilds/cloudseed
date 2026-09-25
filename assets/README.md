# cloudseed brand assets

The mark combines a cloud, a sprout cutout, and a seed. Flat cobalt blue, white space, and a navy wordmark match the documentation site. The artwork uses native SVG shapes, with no external images or fonts to download.

| File | Use | Size |
|---|---|---|
| `icon.svg` / `icon.png` | App icon, avatar, favicon source | 512×512 SVG / 1024×1024 PNG |
| `logo.svg` / `logo.png` | Wordmark for light backgrounds; transparent | 720×160 SVG / 1440×320 PNG |
| `logo-dark.svg` / `logo-dark.png` | Wordmark for dark backgrounds; transparent | 720×160 SVG / 1440×320 PNG |
| `banner.svg` / `banner.png` | README banner | 1280×640 |
| `social-preview.svg` / `social-preview.png` | GitHub/social preview | 1200×630 |

`docs/assets/icon.svg` uses the same mark. Its PNG exports are `favicon.png` (48×48) and `apple-touch-icon.png` (180×180). `docs/assets/og-image.svg` and `.png` match the social preview at 1200×630. Application screenshots and the demo GIF are separate content, not generated brand artwork.

Colors: cobalt `#2563eb`, ink `#0f172a`, muted text `#526077`, pale blue `#f5f8ff`, and white `#ffffff`. The wordmark uses the system stack Inter / Helvetica Neue / Helvetica / Arial, so text shape can vary slightly by installed fonts. Commit rendered PNGs with SVG changes to keep published previews consistent.

## Regenerate

The source is `scripts/build-brand-assets.py`; edit its shared mark and palette rather than editing generated copies separately. SVG generation requires only Python 3.9+:

```bash
python3 scripts/build-brand-assets.py
```

To export PNGs, use the optional Node.js `sharp` renderer. It is a maintainer dependency and is not needed to build the docs or run cloudseed. The checked-in PNGs were rendered with sharp 0.35.4. Install it in a disposable build directory, then pass its package path:

```bash
npm install --prefix build/brand-renderer --no-save sharp@0.35.4
python3 scripts/build-brand-assets.py --png \
  --sharp-module "$PWD/build/brand-renderer/node_modules/sharp"
```

An existing installation can also be supplied with `--sharp-module /absolute/path/to/sharp` and a custom Node executable with `--node /absolute/path/to/node`. The script regenerates all seven SVGs and eight PNGs together, without touching screenshots.
