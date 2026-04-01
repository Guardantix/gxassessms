/**
 * Basic unbranded .docx renderer for GxAssessMS.
 *
 * Usage: node render.js --payload <path> --output <path> --constants <path>
 *
 * Reads a ReportPayload JSON file, generates a clean .docx document,
 * and writes it to the output path. No branding or custom styling.
 */

const fs = require("fs");
const path = require("path");
const {
  Document,
  Packer,
  Paragraph,
  TextRun,
  HeadingLevel,
} = require("docx");

const { buildExecutiveSummary } = require("./sections/executive-summary");
const { buildFindings } = require("./sections/findings");
const { buildMethodology } = require("./sections/methodology");

function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i += 2) {
    const key = argv[i].replace(/^--/, "");
    const value = argv[i + 1];
    if (!value) {
      process.stderr.write(`Missing value for argument: ${argv[i]}\n`);
      process.exit(1);
    }
    args[key] = value;
  }
  return args;
}

function validateArgs(args) {
  const required = ["payload", "output", "constants"];
  for (const key of required) {
    if (!args[key]) {
      process.stderr.write(`Missing required argument: --${key}\n`);
      process.exit(1);
    }
  }
}

function loadJson(filePath, label) {
  try {
    const content = fs.readFileSync(filePath, "utf-8");
    return JSON.parse(content);
  } catch (err) {
    process.stderr.write(
      `Failed to load ${label} from ${filePath}: ${err.message}\n`
    );
    process.exit(1);
  }
}

async function render(payload, constants, outputPath) {
  const sections = [];

  // Title page
  sections.push({
    properties: {},
    children: [
      new Paragraph({
        children: [
          new TextRun({
            text: "Microsoft Ecosystem Assessment",
            bold: true,
            size: 48,
          }),
        ],
        spacing: { after: 400 },
      }),
      new Paragraph({
        children: [
          new TextRun({
            text: payload.tenant_name || "Unknown Tenant",
            size: 32,
          }),
        ],
        spacing: { after: 200 },
      }),
      new Paragraph({
        children: [
          new TextRun({
            text: `Assessment Date: ${payload.assessment_date || "N/A"}`,
            size: 24,
          }),
        ],
        spacing: { after: 200 },
      }),
      new Paragraph({
        children: [
          new TextRun({
            text: `Tools: ${(payload.tool_sources || []).join(", ") || "None"}`,
            size: 24,
          }),
        ],
        spacing: { after: 200 },
      }),
    ],
  });

  // Executive Summary
  sections.push({
    properties: {},
    children: buildExecutiveSummary(payload, constants),
  });

  // Findings
  sections.push({
    properties: {},
    children: buildFindings(payload, constants),
  });

  // Methodology
  sections.push({
    properties: {},
    children: buildMethodology(payload, constants),
  });

  const doc = new Document({ sections });
  const buffer = await Packer.toBuffer(doc);

  const outputDir = path.dirname(outputPath);
  if (outputDir && !fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  fs.writeFileSync(outputPath, buffer);
}

async function main() {
  const args = parseArgs(process.argv);
  validateArgs(args);

  const payload = loadJson(args.payload, "payload");
  const constants = loadJson(args.constants, "constants");

  await render(payload, constants, args.output);
}

main().catch((err) => {
  process.stderr.write(`Render failed: ${err.message}\n`);
  process.exit(1);
});
