const express = require("express");
const crypto = require("crypto");
const { Redis } = require("@upstash/redis");

const app = express();
app.use(express.json());

const ADMIN_KEY = process.env.ADMIN_KEY;
if (!ADMIN_KEY) {
  console.error("ADMIN_KEY environment variable is not set. Refusing to start.");
  process.exit(1);
}

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

const BANS_KEY = "bans"; // hash: userId -> JSON string {reason, bannedAt}
const VERSION_KEY = "bans_version";

async function getAllBans() {
  const bans = await redis.hgetall(BANS_KEY);
  return bans || {};
}

async function getVersion() {
  const v = await redis.get(VERSION_KEY);
  return v ? Number(v) : 1;
}

async function bumpVersion() {
  return redis.incr(VERSION_KEY);
}

function computeEtag(payload) {
  return crypto.createHash("sha1").update(JSON.stringify(payload)).digest("hex");
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

app.get("/banlist", async (req, res) => {
  try {
    const [bans, version] = await Promise.all([getAllBans(), getVersion()]);
    const payload = { version, userIds: Object.keys(bans).map(Number) };
    const etag = computeEtag(payload);

    if (req.header("if-none-match") === etag) {
      return res.status(304).end();
    }

    res.set("ETag", etag);
    res.json(payload);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "internal error" });
  }
});

app.post("/admin/ban", requireAdmin, async (req, res) => {
  try {
    const { userId, reason } = req.body || {};
    if (!isValidUserId(userId)) return res.status(400).json({ error: "userId must be a positive integer" });

    const entry = { reason: reason || "Cheating", bannedAt: new Date().toISOString() };
    await redis.hset(BANS_KEY, { [userId]: JSON.stringify(entry) });
    await bumpVersion();

    res.json({ ok: true, userId, reason: entry.reason });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "internal error" });
  }
});

app.post("/admin/unban", requireAdmin, async (req, res) => {
  try {
    const { userId } = req.body || {};
    if (!isValidUserId(userId)) return res.status(400).json({ error: "userId must be a positive integer" });

    await redis.hdel(BANS_KEY, String(userId));
    await bumpVersion();

    res.json({ ok: true, userId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "internal error" });
  }
});

app.get("/admin/list", requireAdmin, async (req, res) => {
  try {
    const [bans, version] = await Promise.all([getAllBans(), getVersion()]);
    const parsed = {};
    for (const [userId, raw] of Object.entries(bans)) {
      parsed[userId] = JSON.parse(raw);
    }
    res.json({ version, bans: parsed });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "internal error" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Ban list API running on port ${PORT}`);
});
