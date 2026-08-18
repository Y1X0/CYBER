import { useEffect, useState } from "react";
import { AttackChain, AttackChains, ChainStep, api } from "./api";

/**
 * The attack-graph view (WP-F3).
 *
 * A list of findings tells a customer what is wrong. This tells them what an attacker does with it,
 * in order, and it is the one screen where a mistake in presentation is a security problem rather
 * than a usability one — so three properties are load-bearing and each has a test:
 *
 *  - **A failed request never renders as an empty graph.** "No attack paths found" and "we could
 *    not reach the server" look identical if the error is swallowed, and only one of them means
 *    the customer is fine.
 *  - **An empty result is qualified.** Findings the analysis could not reason about are shown next
 *    to the "no chains" message, because a clean graph built on half the evidence is not a clean
 *    graph.
 *  - **Every step names its finding.** The chain is an ordering of observations; a reader who
 *    doubts a hop has to be able to go and read the finding it rests on.
 */

const SEVERITY_COLOR: Record<string, string> = {
  critical: "#b00020",
  high: "#d9534f",
  medium: "#f0ad4e",
  low: "#5bc0de",
  info: "#777",
};

const CAPABILITY_LABEL: Record<string, string> = {
  network_access: "reach the service",
  code_execution: "run code",
  credential_access: "hold a credential",
  data_access: "read data",
  privilege_escalation: "gain privileges",
  lateral_movement: "move to another host",
};

export function AttackGraph() {
  const [data, setData] = useState<AttackChains | null>(null);
  const [error, setError] = useState<string>("");
  const [selected, setSelected] = useState<AttackChain | null>(null);

  useEffect(() => {
    let live = true;
    api
      .attackChains()
      .then((result) => live && setData(result))
      .catch((err: Error) => live && setError(err.message || "the request failed"));
    return () => {
      live = false;
    };
  }, []);

  // Deliberately checked before the empty state: an error must never be shown as "nothing found".
  if (error) {
    return (
      <section className="attack-graph">
        <h3>Attack paths</h3>
        <p className="err" role="alert">
          Attack paths could not be loaded: {error}. This is not a statement that there are none.
        </p>
      </section>
    );
  }
  if (!data) return <p>Loading attack paths…</p>;

  return (
    <section className="attack-graph">
      <h3>Attack paths</h3>
      {data.chains.length === 0 ? (
        <EmptyState unchainable={data.unchainable_findings} />
      ) : (
        <>
          {data.truncated && (
            <p className="note">
              Showing the highest-scoring chains only — more exist than were returned.
            </p>
          )}
          <ol className="chain-list">
            {data.chains.map((chain, index) => (
              <li key={`${chain.entry}-${index}`}>
                <ChainCard chain={chain} onSelect={() => setSelected(chain)} />
              </li>
            ))}
          </ol>
        </>
      )}
      {selected && <ChainDetail chain={selected} onClose={() => setSelected(null)} />}
      {data.unchainable_findings > 0 && data.chains.length > 0 && (
        <p className="note">
          {data.unchainable_findings} finding(s) could not be placed in a chain — their class grants
          no capability the analysis models. They are still findings.
        </p>
      )}
    </section>
  );
}

function EmptyState({ unchainable }: { unchainable: number }) {
  return (
    <div className="empty">
      <p>No attack chain was found: no sequence of findings leads from the internet to another.</p>
      {unchainable > 0 && (
        <p className="note">
          {unchainable} finding(s) could not be reasoned about, so this is not a clean bill of
          health — review them individually.
        </p>
      )}
    </div>
  );
}

function ChainCard({ chain, onSelect }: { chain: AttackChain; onSelect: () => void }) {
  return (
    <button className="chain-card" onClick={onSelect} aria-label={`Attack chain from ${chain.entry}`}>
      <header>
        <span className="score" title="Deterministic score: likelihood × impact, minus a penalty per hop">
          {chain.score}
        </span>
        <span className="entry">{chain.entry}</span>
        <span className="meta">
          {chain.length} steps · {chain.likelihood}% likelihood · impact {chain.impact}
        </span>
      </header>
      <ol className="hops">
        {chain.steps.map((step, index) => (
          <li key={step.finding_id}>
            {index > 0 && <span className="arrow">→</span>}
            <Hop step={step} />
          </li>
        ))}
      </ol>
      <p className="capabilities">
        Ends with the attacker able to:{" "}
        {chain.capabilities.map((c) => CAPABILITY_LABEL[c] ?? c).join(", ")}
      </p>
    </button>
  );
}

function Hop({ step }: { step: ChainStep }) {
  return (
    <span className="hop" style={{ borderColor: SEVERITY_COLOR[step.severity] ?? "#777" }}>
      <strong>{step.title}</strong>
      <small>
        {step.cwe_id ?? step.severity} · {step.reliability}% reliable
      </small>
    </span>
  );
}

function ChainDetail({ chain, onClose }: { chain: AttackChain; onClose: () => void }) {
  return (
    <aside className="chain-detail" role="dialog" aria-label="Attack chain detail">
      <button className="close" onClick={onClose} aria-label="Close">
        ×
      </button>
      <h4>How this chain works</h4>
      <p>{chain.narrative}</p>
      <ol>
        {chain.steps.map((step) => (
          <li key={step.finding_id}>
            <strong>{step.title}</strong>
            <div>{step.rationale}</div>
            <div className="grants">
              Grants: {step.grants.map((g) => CAPABILITY_LABEL[g] ?? g).join(", ")}
            </div>
            {/* The finding id is shown rather than hidden: a chain is an ordering of observations,
                and a reader who doubts a hop must be able to open the finding it rests on. */}
            <a href={`#finding-${step.finding_id}`} className="finding-ref">
              finding {step.finding_id}
            </a>
          </li>
        ))}
      </ol>
    </aside>
  );
}
