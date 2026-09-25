# cloudseed brand assets

| File | Use |
|---|---|
| `icon.svg` | app / favicon / avatar (512×512, rounded tile). A cloud with a keyhole (secure), a sprout growing from a seed (bootstrapped from scratch). |
| `logo.svg` | horizontal wordmark on light backgrounds (720×160) |
| `logo-dark.svg` | horizontal wordmark on dark backgrounds |
| `banner.svg` | social / README banner (1280×640) |
| `*.png` | rasterized copies when a converter was available at build time |

Colors: navy `#0f172a` → indigo `#1e3a8a` (background), leaf `#16a34a` → `#4ade80`, seed amber `#f59e0b`, cloud white → `#dbeafe`.

Re-rasterize (any of): `rsvg-convert -w 1024 icon.svg > icon.png` · `inkscape icon.svg -w 1024 -o icon.png` ·
macOS: `qlmanage -t -s 1024 -o . icon.svg && mv icon.svg.png icon.png`.
