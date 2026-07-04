const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const DATA_FILE = path.join(__dirname, "bans.json");
const ADMIN_KEY = process.env.ADMIN_KEY;

if (!ADMIN_KEY) {
  console.error("ADMIN_KEY environment variable is not set. Refusing to start.");
  process.exit(1);
}

function loadBans() {
  if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, JSON.stringify({ version: 1, bans: {} }, null, 2));
  }
  return JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
}

function saveBans(data) {
  data.version = (data.version || 0) + 1;
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
  return data;
}

function computeEtag(data) {
  return crypto.createHash("sha1").update(JSON.stringify(data)).digest("hex");
}

function requireAdmin(req, res, next) {
  const key = req.header("x-admin-key");
  if (!key || key !== ADMIN_KEY) {
    return res.status(401).json({ error: "unauthorized" });
  }
  next();
}

function isValidUserId(userId) {
  return Number.isInteger(userId) && userId > 0;
}

app.get("/banlist", (req, res) => {
  const data = loadBans();
  const payload = { version: data.version, userIds: Object.keys(data.bans).map(Number) };
  const etag = computeEtag(payload);

  if (req.header("if-none-match") === etag) {
    return res.status(304).end();
  }

  res.set("ETag", etag);
  res.json(payload);
});

app.post("/admin/ban", requireAdmin, (req, res) => {
  const { userId, reason } = req.body || {};
  if (!isValidUserId(userId)) return res.status(400).json({ error: "userId must be a positive integer" });

  const data = loadBans();
  data.bans[userId] = { reason: reason || "Cheating", bannedAt: new Date().toISOString() };
  saveBans(data);

  res.json({ ok: true, userId, reason: data.bans[userId].reason });
});

app.post("/admin/unban", requireAdmin, (req, res) => {
  const { userId } = req.body || {};
  if (!isValidUserId(userId)) return res.status(400).json({ error: "userId must be a positive integer" });

  const data = loadBans();
  delete data.bans[userId];
  saveBans(data);

  res.json({ ok: true, userId });
});

app.get("/admin/list", requireAdmin, (req, res) => {
  res.json(loadBans());
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Ban list API running on port ${PORT}`);
});
