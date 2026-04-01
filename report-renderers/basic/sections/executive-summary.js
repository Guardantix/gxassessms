/**
 * Executive summary section builder.
 * Renders the executive summary narrative and key statistics.
 */

const { Paragraph, TextRun, HeadingLevel } = require("docx");

function countBySeverity(findings, severity) {
  return findings.filter((f) => f.severity === severity).length;
}

function buildExecutiveSummary(payload, constants) {
  const children = [];

  children.push(
    new Paragraph({
      text: "Executive Summary",
      heading: HeadingLevel.HEADING_1,
      spacing: { after: 200 },
    })
  );

  // Narrative text (if provided by QA layer)
  const narrative = (payload.narratives || {}).executive_summary;
  if (narrative) {
    children.push(
      new Paragraph({
        children: [new TextRun({ text: narrative })],
        spacing: { after: 200 },
      })
    );
  }

  // Key statistics
  const findings = payload.findings || [];
  const severityOrder = (constants && constants.severity_order) || {};
  const severities = Object.keys(severityOrder).sort(
    (a, b) => severityOrder[b] - severityOrder[a]
  );

  children.push(
    new Paragraph({
      text: "Assessment Overview",
      heading: HeadingLevel.HEADING_2,
      spacing: { before: 200, after: 100 },
    })
  );

  children.push(
    new Paragraph({
      children: [
        new TextRun({ text: `Total Findings: ${findings.length}`, bold: true }),
      ],
      spacing: { after: 100 },
    })
  );

  for (const severity of severities) {
    const count = countBySeverity(findings, severity);
    if (count > 0) {
      children.push(
        new Paragraph({
          children: [
            new TextRun({ text: `${severity}: `, bold: true }),
            new TextRun({ text: `${count}` }),
          ],
          spacing: { after: 50 },
        })
      );
    }
  }

  // Coverage summary
  const coverage = payload.coverage || [];
  const assessed = coverage.filter((c) => c.status === "assessed").length;
  const notAssessed = coverage.filter((c) => c.status === "not_assessed").length;

  if (coverage.length > 0) {
    children.push(
      new Paragraph({
        children: [
          new TextRun({
            text: `Controls Assessed: ${assessed} | Not Assessed: ${notAssessed}`,
          }),
        ],
        spacing: { before: 100, after: 200 },
      })
    );
  }

  return children;
}

module.exports = { buildExecutiveSummary };
