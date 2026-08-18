import { useEffect, useState } from "react";
import { Compliance as ComplianceData, ComplianceControl, api } from "./api";

/**
 * Control coverage (WP-F4).
 *
 * This panel is read by people making decisions on behalf of other people — an auditor, a board, a
 * prospect's security team — so the way it can mislead is not cosmetic. There are three statuses
 * and the third is the point:
 *
 *  - **failing** — a finding maps to the control;
 *  - **passing** — an engine that can assess it ran and reported nothing;
 *  - **not assessed** — nothing that could assess it ran.
 *
 * `not assessed` is given the same visual weight as the other two and is never folded into a pass
 * rate, because a 100% pass over 20% coverage is precisely the number that misleads an auditor. The
 * coverage percentage is printed next to every count for the same reason, and a failed request is
 * never rendered as a clean result.
 */

const STATUS_LABEL: Record<string, string> = {
  failing: "failing",
  passing: "passing",
  not_assessed: "not assessed",
};

const FRAMEWORK_LABEL: Record<string, string> = {
  soc2: "SOC 2",
  iso27001: "ISO/IEC 27001",
  "pci-dss": "PCI DSS v4.0",
};

export function CompliancePanel() {
  const [data, setData] = useState<ComplianceData | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let live = true;
    api
      .compliance()
      .then((result) => live && setData(result))
      .catch((err: Error) => live && setError(err.message || "the request failed"));
    return () => {
      live = false;
    };
  }, []);

  if (error) {
    return (
      <section className="compliance">
        <h3>Control coverage</h3>
        <p className="err" role="alert">
          Control coverage could not be loaded: {error}. No control status is shown, because an
          unknown status is not a passing one.
        </p>
      </section>
    );
  }
  if (!data) return <p>Loading control coverage…</p>;

  return (
    <section className="compliance">
      <h3>Control coverage</h3>
      <p className="disclaimer">{data.disclaimer}</p>
      {data.frameworks.map((framework) => (
        <div key={framework.framework} className="framework">
          <h4>
            {FRAMEWORK_LABEL[framework.framework] ?? framework.framework}{" "}
            <span className="coverage">{framework.coverage}% of controls assessed</span>
          </h4>
          <p className="counts">
            <Count label="failing" value={framework.counts.failing ?? 0} />
            <Count label="passing" value={framework.counts.passing ?? 0} />
            {/* Never merged into "passing": the whole value of this panel is the distinction. */}
            <Count label="not assessed" value={framework.counts.not_assessed ?? 0} />
          </p>
          <p className="engines">
            Assessed by:{" "}
            {framework.engines_assessed.length > 0
              ? framework.engines_assessed.join(", ")
              : "no engine has run against this scope yet"}
          </p>
          <table>
            <thead>
              <tr>
                <th>Control</th>
                <th>Title</th>
                <th>Status</th>
                <th>Basis</th>
              </tr>
            </thead>
            <tbody>
              {framework.controls.map((control) => (
                <ControlRow key={control.id} control={control} />
              ))}
            </tbody>
          </table>
        </div>
      ))}
    </section>
  );
}

function Count({ label, value }: { label: string; value: number }) {
  return (
    <span className={`count ${label.replace(" ", "-")}`}>
      {value} {label}
    </span>
  );
}

function ControlRow({ control }: { control: ComplianceControl }) {
  return (
    <tr>
      <td>
        <code>{control.id}</code>
      </td>
      <td title={control.description}>{control.title}</td>
      <td>
        <span className={`status ${control.status}`}>
          {STATUS_LABEL[control.status] ?? control.status}
        </span>
      </td>
      <td>
        {control.rationale}
        {control.findings.length > 0 && (
          <ul className="control-findings">
            {control.findings.slice(0, 5).map((finding) => (
              <li key={finding.id}>
                <span className={`sev ${finding.severity}`}>{finding.severity}</span> {finding.title}
              </li>
            ))}
          </ul>
        )}
      </td>
    </tr>
  );
}
