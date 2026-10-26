// Optional PNG previews. Canonical data and figures are CSV and SVG.
// Reproducible rendering uses sharp 0.35.5 with density 144.
const fs = require("node:fs/promises");
const path = require("node:path");
const sharp = require("sharp");

(async () => {
  if (sharp.versions.sharp !== "0.35.5") {
    throw new Error("Reproducible PNG previews require sharp 0.35.5.");
  }
  const check = process.argv.includes("--check");
  if (process.argv.slice(2).some((value) => value !== "--check")) {
    throw new Error("Usage: node render_previews.cjs [--check]");
  }
  const directory = path.join(__dirname, "charts");
  for (const name of ["primitive_latency", "envelope_latency"]) {
    const svg = await fs.readFile(path.join(directory, `${name}.svg`));
    const png = await sharp(svg, { density: 144 }).png().toBuffer();
    const destination = path.join(directory, `${name}.png`);
    if (check) {
      const existing = await fs.readFile(destination);
      if (!existing.equals(png)) {
        throw new Error(`PNG preview differs: ${name}.png`);
      }
    } else {
      await fs.writeFile(destination, png);
    }
  }
  console.log(check ? "Crypto PNG previews match." : "Rendered crypto PNG previews.");
})().catch((error) => { console.error(error.message); process.exitCode = 1; });
