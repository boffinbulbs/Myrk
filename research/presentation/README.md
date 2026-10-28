# Research figure presentation

This directory supplies transparent SVG display variants of seven canonical research charts. Light and dark variants preserve the plot geometry, observations, data labels, units and axes. Detailed footer notes accompany the research text and manifest, with a concise scope label on each display. The remaining changes affect paint, typography and accessibility descriptions. No measurements or monetary projections are recalculated.

The original SVGs, generation scripts, raw data and historical manifests remain in their research directories:

| Source | Evidence class |
|---|---|
| [Monetary research](../emission/README.md) | Analytical projections under the retained 120 second accounting reference |
| [Primitive research](../crypto/README.md) | Historical measurements of the recorded primitive source and hardware |
| [Conservation proof research](../proofs/README.md) | Historical measurements of the isolated unbound conservation relation |

None of these figures measures a complete private payment, Aegis consensus, wallet performance or a deployed chain. Their original scope and source provenance remain applicable.

## Deterministic display transformation

[render_figures.py](render_figures.py) uses the Python standard library. It reads the seven canonical SVGs, applies a fixed injective color palette, changes the full canvas paint to transparent and supplies font fallbacks. It moves only the explicitly selected footer notes, records their original text and replaces them with a short scope label. A structural fingerprint checks every remaining geometric attribute and rendered data label before serialization and after parsing the generated SVG.

The [manifest](manifest.json) records each original source hash, each display variant hash, unchanged plot fingerprints, the complete moved notes, the exact generator and text contrast against the reference light and dark canvases. The contrast check is a presentation property rather than a transaction privacy or cryptographic security test. Monetary settings remain development references with production parameters still open.

```text
python research/presentation/render_figures.py
python research/presentation/render_figures.py --check
```

The check compares exact expected bytes without rewriting output. Original chart files are never modified by this renderer. No font files, dependencies or external resources are bundled into the display SVGs.

## Theme selection

Repository pages use a picture element with separate light and dark SVG sources and descriptive alternative text. The canvas remains transparent in both variants. Text, axes and data series use the selected palette so the surrounding page can remain visible without sacrificing contrast. The markup follows the [documented GitHub image theme support](https://github.blog/changelog/2022-08-15-specify-theme-context-for-images-in-markdown-ga/).

SVGs retain a fixed viewBox and scale with the page. Their geometry is reproducible, while final font rasterization depends on the reader's platform. The light source remains a fallback for renderers without theme selection.
