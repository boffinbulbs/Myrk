// Optional PNG previews of the canonical SVG plots. Validated with sharp 0.35.5.
const fs = require("node:fs/promises");
const path = require("node:path");
const sharp = require("sharp");

(async () => {
  const directory = path.join(__dirname, "charts");
  for (const name of ["reward_schedule", "issued_supply", "annual_issuance", "gross_issuance_rate"]) {
    const source = await fs.readFile(path.join(directory, `${name}.svg`));
    await sharp(source, { density: 144 }).png().toFile(path.join(directory, `${name}.png`));
  }
  console.log(`Rendered four PNG chart previews with sharp ${sharp.versions.sharp}.`);
})().catch((error) => { console.error(error); process.exitCode = 1; });
