const threats = new Map();

const getToday = () => {
  return new Date().toISOString().split("T")[0];
};

const createCampaignId = () => {
  return `CAM-${Math.floor(100 + Math.random() * 900)}`;
};

const recordThreat = (input, data = {}) => {
  const key = input.trim().toLowerCase();
  const today = getToday();

  if (threats.has(key)) {
    const existing = threats.get(key);

    existing.reports += 1;
    existing.users += 1;
    existing.last = today;

    if (data.status) {
      existing.status = data.status;
    }

    threats.set(key, existing);

    return existing;
  }

  const threat = {
    reports: 1,
    users: 1,
    first: today,
    last: today,
    campaign: data.campaign || createCampaignId(),
    status: data.status || "Analyzed",
  };

  threats.set(key, threat);

  return threat;
};

const getThreat = (input) => {
  const key = input.trim().toLowerCase();
  return threats.get(key) || null;
};

const getAllThreats = () => {
  return Array.from(threats.entries()).map(([input, data]) => ({
    input,
    ...data,
  }));
};

module.exports = {
  recordThreat,
  getThreat,
  getAllThreats,
};