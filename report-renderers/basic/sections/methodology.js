/**
 * Methodology section builder.
 * Describes the assessment methodology: tools used, coverage, limitations.
 */

const { Paragraph, TextRun, HeadingLevel } = require("docx");

function buildMethodology(payload, constants) {
  const children = [];

  children.push(
    new Paragraph({
      text: "Methodology",
      heading: HeadingLevel.HEADING_1,
      spacing: { after: 200 },
    })
  );

  // Assessment approach
  children.push(
    new Paragraph({
      text: "Assessment Approach",
      heading: HeadingLevel.HEADING_2,
      spacing: { after: 100 },
    })
  );

  children.push(
    new Paragraph({
      children: [
        new TextRun({
          text:
            "This assessment was performed using automated security and compliance scanning tools " +
            "against the Microsoft 365 and Azure tenant. Findings were consolidated, " +
            "deduplicated across tools, and reviewed for accuracy.",
        }),
      ],
      spacing: { after: 200 },
    })
  );

  // Tools used
  const toolSources = payload.tool_sources || [];
  if (toolSources.length > 0) {
    children.push(
      new Paragraph({
        text: "Tools Used",
        heading: HeadingLevel.HEADING_2,
        spacing: { after: 100 },
      })
    );

    for (const tool of toolSources) {
      children.push(
        new Paragraph({
          children: [new TextRun({ text: `- ${tool}` })],
          spacing: { after: 50 },
        })
      );
    }
  }

  // Coverage summary
  const coverage = payload.coverage || [];
  if (coverage.length > 0) {
    const assessed = coverage.filter((c) => c.status === "ASSESSED").length;
    const total = coverage.length;

    children.push(
      new Paragraph({
        text: "Coverage",
        heading: HeadingLevel.HEADING_2,
        spacing: { before: 200, after: 100 },
      })
    );

    children.push(
      new Paragraph({
        children: [
          new TextRun({
            text:
              `${assessed} of ${total} controls were assessed. ` +
              "Controls not assessed may require manual review or were outside " +
              "the scope of the automated tools used.",
          }),
        ],
        spacing: { after: 200 },
      })
    );
  }

  // Limitations
  children.push(
    new Paragraph({
      text: "Limitations",
      heading: HeadingLevel.HEADING_2,
      spacing: { before: 200, after: 100 },
    })
  );

  children.push(
    new Paragraph({
      children: [
        new TextRun({
          text:
            "This assessment reflects the configuration state at the time of scanning. " +
            "Results may change as the tenant configuration evolves. " +
            "Automated tools may not identify all security issues; " +
            "manual review is recommended for critical controls.",
        }),
      ],
      spacing: { after: 200 },
    })
  );

  return children;
}

module.exports = { buildMethodology };
