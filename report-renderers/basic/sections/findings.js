/**
 * Findings section builder.
 * Renders findings grouped by category, sorted by severity within each group.
 */

const { Paragraph, TextRun, HeadingLevel } = require("docx");

function groupByCategory(findings, constants) {
  const groups = {};
  const categoryNames = (constants && constants.category_display_names) || {};

  for (const finding of findings) {
    const categoryKey = finding.category || "UNKNOWN";
    const displayName = categoryNames[categoryKey] || categoryKey;

    if (!groups[displayName]) {
      groups[displayName] = [];
    }
    groups[displayName].push(finding);
  }

  return groups;
}

function sortBySeverity(findings, constants) {
  const severityOrder = (constants && constants.severity_order) || {};
  return [...findings].sort((a, b) => {
    const orderA = severityOrder[a.severity] || 0;
    const orderB = severityOrder[b.severity] || 0;
    return orderB - orderA;
  });
}

function buildFindingParagraphs(finding) {
  const paragraphs = [];

  paragraphs.push(
    new Paragraph({
      children: [
        new TextRun({ text: `[${finding.severity}] `, bold: true }),
        new TextRun({ text: finding.title || "Untitled Finding", bold: true }),
      ],
      heading: HeadingLevel.HEADING_3,
      spacing: { before: 150, after: 100 },
    })
  );

  if (finding.description) {
    paragraphs.push(
      new Paragraph({
        children: [new TextRun({ text: finding.description })],
        spacing: { after: 100 },
      })
    );
  }

  if (finding.root_cause) {
    paragraphs.push(
      new Paragraph({
        children: [
          new TextRun({ text: "Root Cause: ", bold: true }),
          new TextRun({ text: finding.root_cause }),
        ],
        spacing: { after: 50 },
      })
    );
  }

  if (finding.remediation) {
    paragraphs.push(
      new Paragraph({
        children: [
          new TextRun({ text: "Remediation: ", bold: true }),
          new TextRun({ text: finding.remediation }),
        ],
        spacing: { after: 50 },
      })
    );
  }

  const sources = Array.isArray(finding.sources) ? finding.sources : [];
  if (sources.length > 0) {
    const sourceText = sources
      .map((s) => `${s.tool} (${s.check_id})`)
      .join(", ");
    paragraphs.push(
      new Paragraph({
        children: [
          new TextRun({ text: "Sources: ", bold: true }),
          new TextRun({ text: sourceText, italics: true }),
        ],
        spacing: { after: 100 },
      })
    );
  }

  return paragraphs;
}

function buildFindings(payload, constants) {
  const children = [];

  children.push(
    new Paragraph({
      text: "Findings",
      heading: HeadingLevel.HEADING_1,
      spacing: { after: 200 },
    })
  );

  const findings = payload.findings || [];

  if (findings.length === 0) {
    children.push(
      new Paragraph({
        children: [
          new TextRun({
            text: "No findings were identified during this assessment.",
          }),
        ],
        spacing: { after: 200 },
      })
    );
    return children;
  }

  const grouped = groupByCategory(findings, constants);
  const categoryNames = Object.keys(grouped).sort();

  for (const categoryName of categoryNames) {
    children.push(
      new Paragraph({
        text: categoryName,
        heading: HeadingLevel.HEADING_2,
        spacing: { before: 200, after: 100 },
      })
    );

    const sorted = sortBySeverity(grouped[categoryName], constants);
    for (const finding of sorted) {
      children.push(...buildFindingParagraphs(finding));
    }
  }

  return children;
}

module.exports = { buildFindings };
