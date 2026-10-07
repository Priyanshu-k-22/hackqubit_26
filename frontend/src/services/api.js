import {
  threats as mockThreats,
  campaigns as mockCampaigns,
} from "../data/mock";

import {
  analyzeQrPayload,
} from "../../../shared/qrAnalyzer.mjs";

const configuredBase =
  import.meta.env.VITE_API_BASE_URL;

const trimmedBase =
  configuredBase?.replace(/\/+$/, "");

const BASE = trimmedBase
  ? (
      trimmedBase.endsWith("/api")
        ? trimmedBase
        : `${trimmedBase}/api`
    )
  : "/api";

const DEMO =
  import.meta.env.VITE_DEMO_MODE === "true";

const sleep = ms =>
  new Promise(resolve => setTimeout(resolve, ms));

const hash = s =>
  [...s].reduce(
    (a, c) =>
      (a * 31 + c.charCodeAt(0)) >>> 0,
    7
  );

const known = [
  "official",
  "sbi.co.in",
  "google.com",
  "paytm.com",
];

const safeInput = (kind, input) => {
  if (kind !== "url") {
    return input;
  }

  try {
    const url = new URL(
      input.includes("://")
        ? input
        : `https://${input}`
    );

    const query = [
      ...url.searchParams.keys(),
    ]
      .map(
        key =>
          `${encodeURIComponent(key)}=[redacted]`
      )
      .join("&");

    return `${url.origin}${url.pathname}${
      query ? `?${query}` : ""
    }`;
  } catch {
    return input;
  }
};

function mockAnalyze(kind, input) {
  const h = hash(input);

  const m = mockThreats.find(
    t =>
      input.includes(
        t.target.split("?")[0]
      ) ||
      t.target.includes(input)
  );

  let domain = "-";
  let upi = "-";
  let payee = "-";

  try {
    const u = new URL(
      input.startsWith("upi://")
        ? input.replace(
            "upi://",
            "https://x/"
          )
        : input.includes("://")
          ? input
          : `https://${input}`
    );

    if (input.startsWith("upi://")) {
      upi =
        u.searchParams.get("pa") ||
        "-";

      payee =
        u.searchParams.get("pn") ||
        "-";
    } else {
      domain = u.hostname;
    }
  } catch {}

  if (kind === "upi") {
    upi = input;
  }

  const low = known.some(k =>
    input.includes(k)
  );

  const score = m
    ? m.risk
    : low
      ? 4
      : 55 + (h % 43);

  const reports = m
    ? m.reports
    : low
      ? 0
      : h % 20;

  const ev = low
    ? [
        "No known threat indicators",
        "No matching campaign found",
        "Domain matches local demo registry",
      ]
    : [
        "Suspicious URL pattern",
        "Possible brand impersonation",
        "Threat intelligence requires further verification",
      ];

  const b = n =>
    Math.min(
      99,
      Math.max(
        1,
        score + ((h >> n) % 11) - 5
      )
    );

  return {
    id:
      "SCN-" +
      h.toString(16).toUpperCase(),

    kind,

    input: safeInput(
      kind,
      input
    ),

    score,

    riskLevel:
      score >= 85
        ? "CRITICAL"
        : score >= 65
          ? "HIGH"
          : score >= 40
            ? "MEDIUM"
            : "LOW",

    domain,

    upi,

    payee,

    redirects: 0,

    protocol:
      input.startsWith("http://")
        ? "HTTP"
        : "HTTPS",

    brand:
      m?.brand ||
      (low
        ? "Official brand"
        : "Unknown"),

    reports,

    campaign:
      m?.campaign ||
      "CAM-DEMO",

    status:
      m?.status ||
      (low
        ? "LOW RISK"
        : "Under Review"),

    first:
      m?.first ||
      new Date()
        .toISOString()
        .slice(0, 10),

    last:
      m?.last ||
      new Date()
        .toISOString()
        .slice(0, 10),

    users:
      Math.ceil(reports * 0.7),

    evidence: ev,

    demo: true,

    ts:
      new Date().toISOString(),

    breakdown: {
      "Domain risk": b(1),
      Behavior: b(2),
      Infrastructure: b(3),
      "Threat intelligence": b(4),
    },
  };
}

async function call(
  path,
  body,
  fallback
) {
  if (DEMO) {
    await sleep(300);

    return fallback();
  }

  let response;

  try {
    response = await fetch(
      BASE + path,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",
        },

        body: JSON.stringify(body),
      }
    );
  } catch {
    const value =
      fallback();

    value.backendUnavailable =
      true;

    return value;
  }

  const data =
    await response
      .json()
      .catch(() => ({
        message:
          "Invalid server response",
      }));

  if (!response.ok) {
    throw new Error(
      data.message ||
      `Request failed (${response.status})`
    );
  }

  return data;
}

async function get(path) {
  const response =
    await fetch(BASE + path);

  const data =
    await response
      .json()
      .catch(() => ({
        message:
          "Invalid server response",
      }));

  if (!response.ok) {
    throw new Error(
      data.message ||
      `Request failed (${response.status})`
    );
  }

  return data;
}

export const save = result => {
  const all =
    JSON.parse(
      localStorage.getItem(
        "ups_results"
      ) || "{}"
    );

  all[result.id] = result;

  localStorage.setItem(
    "ups_results",
    JSON.stringify(all)
  );

  return result;
};

export const scannerApi = {
  analyzeUrl: url =>
    call(
      "/scan/url",
      { url },
      () =>
        mockAnalyze(
          "url",
          url
        )
    ).then(save),

  analyzeUpi: upi =>
    call(
      "/scan/upi",
      { upi },
      () =>
        mockAnalyze(
          "upi",
          upi
        )
    ).then(save),

  analyzeQr: payload =>
    call(
      "/scan/qr",
      { payload },
      () =>
        analyzeQrPayload(
          payload
        )
    ).then(save),

  analyzeImage: file =>
    call(
      "/scan/image",
      { name: file.name },
      () =>
        mockAnalyze(
          "image",
          file.name
        )
    ).then(save),
};

export const threatApi = {
  list: async () => {
    if (DEMO) {
      return mockThreats;
    }

    const data =
      await get("/threats");

    return data.threats || [];
  },

  getResult: async id => {
    const local =
      JSON.parse(
        localStorage.getItem(
          "ups_results"
        ) || "{}"
      )[id];

    if (local) {
      return local;
    }

    if (DEMO) {
      return (
        mockThreats.find(
          t => t.id === id
        ) || null
      );
    }

    const data =
      await get(
        `/threats/id/${encodeURIComponent(id)}`
      );

    const threat =
      data.threat;

    if (!threat) {
      return null;
    }

    const result = {
      ...(threat.analysis || {}),

      id: threat.id,

      reports:
        threat.reports,

      users:
        threat.users,

      first:
        threat.first,

      last:
        threat.last,

      campaign:
        threat.campaign,

      status:
        threat.status,

      brand:
        threat.brand,

      score:
        threat.risk,

      riskLevel:
        threat.riskLevel,

      reason:
        threat.reason,

      demo: false,

      ts:
        threat.analysis?.ts ||
        new Date().toISOString(),
    };

    return save(result);
  },
};

export const campaignApi = {
  list: async () =>
    DEMO
      ? mockCampaigns
      : [],
};

export const reportApi = {
  get: id =>
    JSON.parse(
      localStorage.getItem(
        "ups_results"
      ) || "{}"
    )[id],

  list: () =>
    Object.values(
      JSON.parse(
        localStorage.getItem(
          "ups_results"
        ) || "{}"
      )
    ),
};

export const feedbackApi = {
  submit: body =>
    call(
      "/feedback",
      body,
      () => ({
        ok: true,
        demo: true,
      })
    ),
};

export const isDemo = DEMO;