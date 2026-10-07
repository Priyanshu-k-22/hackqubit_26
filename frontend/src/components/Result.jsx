import { useState } from "react";
import { Link } from "react-router-dom";

import {
  RiskBadge,
  Bar,
  Demo,
} from "./ui";

import {
  level,
  freqLabel,
} from "../utils/risk";

const demoNodes = r => [
  ["Brand", r.brand, 50, 20],
  ["Campaign", r.campaign, 50, 75],
  ["Domain", r.domain, 20, 135],
  ["IP", "Not checked", 50, 135],
  ["Certificate", "Not checked", 80, 135],
  ["VPA", r.upi, 50, 190],
];

const urlHeadline = r => {
  if (r.status === "INVALID URL") {
    return "⚠️ INVALID — Invalid URL";
  }

  if (r.riskLevel === "CRITICAL") {
    return "🔴 CRITICAL — Strong threat indicators";
  }

  if (r.riskLevel === "HIGH") {
    return "🔴 HIGH — Suspicious URL";
  }

  if (r.riskLevel === "MEDIUM") {
    return "🟠 MEDIUM — Verify before proceeding";
  }

  if (r.status === "AUTHORIZED") {
    return "🟢 LOW — Authorized domain";
  }

  return "🟢 LOW — No strong indicators detected";
};

export default function Result({
  r,
  printMode,
}) {
  const [sel, setSel] =
    useState(null);

  const l = level(r.score);

  const low =
    l === "LOW";

  const isUrlResult =
    r.kind === "url" &&
    Boolean(r.status);

  const isQrResult =
    r.kind === "qr" &&
    Boolean(r.status);

  const F = ({ k, v }) => (
    <div>
      <dt className="text-xs text-slate-500">
        {k}
      </dt>

      <dd className="break-all font-mono text-sm">
        {String(v)}
      </dd>
    </div>
  );

  const headline =
    isUrlResult
      ? urlHeadline(r)
      : isQrResult
        ? r.status === "AUTHORIZED"
          ? "🟢 LOW — Authorized Payment QR"
          : r.status ===
              "NON-PAYMENT QR"
            ? "🟠 MEDIUM — Non-payment QR"
            : "🔴 HIGH — Unknown / Unauthorized QR"
        : `${l} RISK`;

  return (
    <div className="space-y-4">

      {/* MAIN RESULT */}

      <div
        className={`panel p-5 ${
          low
            ? "border-emerald-500/50"
            : "border-red-500/40"
        }`}
      >
        <div className="flex flex-wrap items-center justify-between gap-3">

          <div>
            <div className="text-sm font-semibold">
              {headline}
            </div>

            <div className="text-4xl font-bold">
              {r.score}

              <span className="text-lg text-slate-500">
                {" "} / 100
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2">

            <RiskBadge
              score={r.score}
            />

            {r.demo && <Demo />}

            {!printMode && (
              <Link
                to={`/report/${r.id}`}
                className="btn-p"
              >
                Generate full report
              </Link>
            )}
          </div>
        </div>

        {r.backendUnavailable && (
          <p className="mt-2 text-sm text-amber-600">
            Intelligence backend unavailable.
            Demo fallback was used.
          </p>
        )}

        <p className="mt-2 text-xs text-slate-500">
          {isUrlResult
            ? "This URL assessment uses local structural and brand-impersonation intelligence. It does not open the destination or follow redirects."
            : isQrResult
              ? "Unknown QR codes are treated cautiously. This does not prove that the payee is fraudulent."
              : r.demo
                ? "Scores are synthetic demo values and are not scientifically validated."
                : "This is a heuristic assessment, not a fraud verdict."}

          {" "}Low risk does not guarantee safety.
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2">

        {/* RISK BREAKDOWN */}

        <section className="panel p-4">
          <h3 className="mb-3 font-medium">
            Risk breakdown
          </h3>

          <div className="space-y-3">
            {Object.entries(
              r.breakdown || {}
            ).map(([k, v]) => (
              <Bar
                key={k}
                label={k}
                v={v}
              />
            ))}
          </div>
        </section>

        {/* EVIDENCE */}

        <section className="panel p-4">
          <h3 className="mb-3 font-medium">
            {low
              ? "Why is this considered low risk?"
              : "Why did we flag this?"}
          </h3>

          <ul className="space-y-1 text-sm">
            {(r.evidence || []).map(
              evidence => (
                <li key={evidence}>
                  ✓ {evidence}
                </li>
              )
            )}
          </ul>
        </section>

        {/* TARGET */}

        <section className="panel p-4 md:col-span-2">
          <h3 className="mb-3 font-medium">
            Target details
          </h3>

          <dl className="grid grid-cols-2 gap-3">

            <F
              k="Input type"
              v={
                r.kind?.toUpperCase() ||
                "UNKNOWN"
              }
            />

            <F
              k="Entered URL"
              v={
                r.input ||
                "Unavailable"
              }
            />

            <F
              k="Extracted domain"
              v={
                r.domain ||
                "Unavailable"
              }
            />

            {isUrlResult && (
              <>
                <F
                  k="Authorization status"
                  v={r.status}
                />

                <F
                  k="Reason"
                  v={r.reason}
                />

                <F
                  k="Matched trusted domain"
                  v={
                    r.matchedDomain ||
                    "None"
                  }
                />
              </>
            )}

            <F
              k="Protocol"
              v={
                r.protocol ||
                "Unknown"
              }
            />

            <F
              k="UPI ID"
              v={r.upi || "-"}
            />

            <F
              k="Payee name"
              v={r.payee || "-"}
            />

            <F
              k="Redirects"
              v={
                r.redirects ??
                "Not checked"
              }
            />

            <F
              k="Brand"
              v={
                r.brand ||
                "Unknown"
              }
            />

          </dl>
        </section>

        {/* URL INTELLIGENCE */}

        {r.urlDetails && (
          <section className="panel p-4 md:col-span-2">

            <h3 className="mb-3 font-medium">
              URL intelligence
            </h3>

            <dl className="grid grid-cols-2 gap-3 md:grid-cols-3">

              <F
                k="Hostname"
                v={
                  r.urlDetails.hostname
                }
              />

              <F
                k="Path"
                v={
                  r.urlDetails.path ||
                  "/"
                }
              />

              <F
                k="Query parameters"
                v={
                  r.urlDetails
                    .queryParameterCount
                }
              />

              <F
                k="Sensitive parameter names"
                v={
                  r.urlDetails
                    .sensitiveQueryParameterCount
                }
              />

              <F
                k="HTTPS"
                v={
                  r.urlDetails
                    .usesHttps
                    ? "Yes"
                    : "No"
                }
              />

              <F
                k="IP address"
                v={
                  r.urlDetails.ipVersion
                    ? `IPv${r.urlDetails.ipVersion}`
                    : "No"
                }
              />

              <F
                k="Nested hostname labels"
                v={
                  r.urlDetails
                    .subdomainCount
                }
              />

              <F
                k="Punycode label"
                v={
                  r.urlDetails.hasPunycode
                    ? "Detected"
                    : "Not detected"
                }
              />

              <F
                k="Non-standard port"
                v={
                  r.urlDetails
                    .hasNonStandardPort
                    ? "Detected"
                    : "Not detected"
                }
              />

              <F
                k="Suspicious keywords"
                v={
                  r.urlDetails
                    .suspiciousKeywords
                    ?.join(", ") ||
                  "None"
                }
              />

              <F
                k="Suspicious path"
                v={
                  r.urlDetails
                    .suspiciousPath
                    ? "Detected"
                    : "Not detected"
                }
              />

            </dl>

            <p className="mt-3 text-xs text-slate-500">
              Query values are redacted.
              The backend does not open the submitted URL.
            </p>

          </section>
        )}

        {/* THREAT FREQUENCY */}

        <section className="panel p-4 md:col-span-2">

          <h3 className="mb-3 font-medium">
            Threat frequency
          </h3>

          <dl className="grid grid-cols-2 gap-3">

            <F
              k="Observations"
              v={r.reports ?? 0}
            />

            <F
              k="Unique reporters"
              v={r.users ?? 0}
            />

            <F
              k="First detected"
              v={r.first || "-"}
            />

            <F
              k="Last detected"
              v={r.last || "-"}
            />

            <F
              k="Campaign"
              v={r.campaign || "-"}
            />

            <F
              k="Status"
              v={r.status || "-"}
            />

          </dl>

          <p className="mt-3 rounded bg-slate-100 p-2 text-sm dark:bg-ink-800">
            {freqLabel(
              r.reports || 0
            )}

            . Repeated observations
            are a signal, not proof of fraud.
          </p>

        </section>

      </div>

      {/* DEMO GRAPH ONLY */}

      {!low && r.demo && (
        <section className="panel p-4">

          <h3 className="mb-2 font-medium">
            Infrastructure graph
            <span className="text-xs text-slate-500">
              {" "}(demo)
            </span>
          </h3>

          <div className="grid gap-3 md:grid-cols-2">

            <svg
              viewBox="0 0 100 210"
              className="h-64 w-full"
              role="img"
              aria-label="Infrastructure graph"
            >
              {[
                [0, 1],
                [1, 2],
                [1, 3],
                [1, 4],
                [3, 5],
              ].map(([a, b]) => {
                const A =
                  demoNodes(r)[a];

                const B =
                  demoNodes(r)[b];

                return (
                  <line
                    key={`${a}-${b}`}
                    x1={A[2]}
                    y1={A[3]}
                    x2={B[2]}
                    y2={B[3]}
                    stroke="#64748b"
                    strokeWidth=".6"
                  />
                );
              })}

              {demoNodes(r).map(n => (
                <g
                  key={n[0]}
                  tabIndex={0}
                  role="button"
                  aria-label={n[0]}
                  className="cursor-pointer"
                  onClick={() =>
                    setSel(n)
                  }
                  onKeyDown={e =>
                    e.key === "Enter" &&
                    setSel(n)
                  }
                >
                  <circle
                    cx={n[2]}
                    cy={n[3]}
                    r="9"
                    fill={
                      sel === n
                        ? "#0891b2"
                        : "#1e2942"
                    }
                    stroke="#22d3ee"
                    strokeWidth=".8"
                  />

                  <text
                    x={n[2]}
                    y={n[3] + 2}
                    fontSize="4"
                    textAnchor="middle"
                    fill="#fff"
                  >
                    {n[0]}
                  </text>
                </g>
              ))}
            </svg>

            <div className="rounded border border-dashed p-3 text-sm dark:border-ink-700">
              {sel ? (
                <dl className="space-y-1">
                  <div>
                    <b>Type:</b>{" "}
                    {sel[0]}
                  </div>

                  <div className="break-all">
                    <b>Value:</b>{" "}
                    {sel[1]}
                  </div>
                </dl>
              ) : (
                "Select a node to inspect it."
              )}
            </div>

          </div>
        </section>
      )}

    </div>
  );
}