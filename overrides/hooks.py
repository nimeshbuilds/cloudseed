"""MkDocs hooks for the cloudseed site (standard library only).

- Reads cloudseed's version from the package (cloudseed/__init__.py) so the landing page and the JSON-LD metadata
  never drift from the code, and exposes it to the templates as `config.extra.cloudseed_version`.
- Guards the SEO metadata: MkDocs silently ignores front matter that is not valid YAML (for example an unquoted
  `description: a: b`) and renders it as page text. That is reported as a warning, so `mkdocs build --strict` fails.
- Diagrams: every ```mermaid fence is wrapped in <div class="cs-diagram"> (a frame that hides the source while
  mermaid loads, see extra.css) and gets a tighter flowchart layout, so wide diagrams stay readable in the content
  column. Material draws them in the browser; nothing about the diagram source changes.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

log = logging.getLogger("mkdocs.hooks.cloudseed")

_FRONT_MATTER = re.compile(r"\A---[ \t]*\n.*?^(?:---|\.\.\.)[ \t]*$", re.S | re.M)


_MERMAID_INIT = '%%{init: {"flowchart": {"nodeSpacing": 30, "rankSpacing": 38, "padding": 12}}}%%\n'


def _diagram_fence(original):
    def fence(source, language, class_name, options, md, **kwargs):
        html = original(_MERMAID_INIT + source, language, class_name, options, md, **kwargs)
        return '<div class="cs-diagram">' + html + "</div>"
    return fence


def on_config(config, **kwargs):
    init = Path(config.config_file_path).resolve().parent / "cloudseed" / "__init__.py"
    version = ""
    if init.is_file():
        m = re.search(r"""^__version__\s*=\s*["']([^"']+)["']""", init.read_text(encoding="utf-8"), re.M)
        version = m.group(1) if m else ""
    config.extra["cloudseed_version"] = version
    for fence in (config.mdx_configs.get("pymdownx.superfences") or {}).get("custom_fences", []):
        if fence.get("name") == "mermaid" and not getattr(fence["format"], "_cs_wrapped", False):
            fence["format"] = _diagram_fence(fence["format"])
            fence["format"]._cs_wrapped = True
    return config


def on_page_markdown(markdown, page, config, files, **kwargs):
    if not page.meta and _FRONT_MATTER.match(markdown):
        log.warning("%s: its front matter is not valid YAML, so MkDocs shows it as text and the page loses its title "
                    "and description (quote values that contain ': ')", page.file.src_uri)
    return markdown
