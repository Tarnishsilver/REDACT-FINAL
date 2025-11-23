// index.js — Unified Event Logging Version with Enhanced UI
//-----------------------------------------------------

import dotenv from "dotenv";
dotenv.config({ override: true });
import multer from "multer";
import ExifParser from "exif-parser";

import express from "express";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import axios from "axios";
import sqlite3 from "sqlite3";
import { promisify } from "util";
import { MongoClient } from "mongodb";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import { v4 as uuidv4 } from "uuid";
import cors from "cors";

// --------------------------------------------------
// INIT APP
// --------------------------------------------------
const app = express();
app.set("case sensitive routing", true);
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "script-src": ["'self'", "'unsafe-inline'"], // TEMP solution
      },
    },
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(
  cors({
    origin: "http://3.236.124.19//", // Vite default
    credentials: true,
  })
);

// Serve frontend + logs
app.use(express.static(path.join(process.cwd(), "public")));
const LOG_DIR = path.join(process.cwd(), "logs");
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR);
app.use("/logs", express.static(LOG_DIR));

// --------------------------------------------------
// --------------------------------------------------
const PORT = process.env.PORT || 3001;
const MONGO_URI =
  process.env.MONGO_URI ||
  "mongodb+srv://atharvamehta2024_db_user:NoT62jJW4AcJRV9P@cluster0.uycbv7o.mongodb.net/chameleon_forensics?retryWrites=true&w=majority&appName=Cluster0";

const FORENSICS_DB = "chameleon_forensics";
const EVENTS_COL = "events";
const STATES_COL = "attacker_states";
const META_COL = "meta";

const DB_PATH = path.join(process.cwd(), "honeypot.db");
const TARGET_PASSWORD = process.env.TARGET_PASSWORD || "c@iy25";
const ML_API = process.env.ML_API || "http://127.0.0.1:8000/predict";
const XSS_API = process.env.XSS_API || "http://127.0.0.1:8001/predict";

const MERKLE_BATCH = 50;

// --------------------------------------------------
// CONNECT MONGO
// --------------------------------------------------
console.log("Connecting to MongoDB…");
const mongoClient = new MongoClient(MONGO_URI, {
  serverSelectionTimeoutMS: 5000,
});
await mongoClient.connect();

console.log("Mongo connected.");

const db = mongoClient.db(FORENSICS_DB);
const eventsCol = db.collection(EVENTS_COL);
const statesCol = db.collection(STATES_COL);
const metaCol = db.collection(META_COL);
const uploadFilesCol = db.collection("upload_files");

await metaCol.updateOne(
  { _id: "counters" },
  { $setOnInsert: { eventCounter: 0 } },
  { upsert: true }
);

// --------------------------------------------------
// SQLITE INIT
// --------------------------------------------------
if (!fs.existsSync(DB_PATH)) {
  console.error("SQLite DB missing:", DB_PATH);
  process.exit(1);
}

const sqlite = new sqlite3.Database(DB_PATH);
const sqliteAll = promisify(sqlite.all.bind(sqlite));

// --------------------------------------------------

// --------------------------------------------------
// MULTER STORAGE
// --------------------------------------------------
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const dir = path.join(process.cwd(), "uploads");
    if (!fs.existsSync(dir)) fs.mkdirSync(dir);
    cb(null, dir);
  },
  filename: function (req, file, cb) {
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, unique + path.extname(file.originalname));
  },
});

const upload = multer({ storage });

// --------------------------------------------------
// ROUTES
// --------------------------------------------------
app.get("/", (req, res) =>
  res.sendFile(path.join(process.cwd(), "public", "index.html"))
);

// POST /admin (UNIFIED EVENT)
app.post("/admin", async (req, res) => {
  const ip = getIP(req);
  const state = await getState(ip);
  const scanner = detectScanner(req);

  const username = req.body.username || "";
  const password = req.body.password || "";
  const payload = `${username} ${password}`;

  const eventDoc = {
    event_id: uuidv4(),
    ts: new Date(),
    ip,
    scanner,
    ipIntel: {},
    deviceFp: {},
    payloadFp: {},
    behavioral: {},
    loginAttempt: {},
    deception: {},
  };

  const ipIntel = await getIPIntel(ip);
  eventDoc.ipIntel = ipIntel;

  // Log and track Tor/VPN usage in attacker state
  try {
    if (ipIntel && ipIntel.isTor) {
      eventDoc.deception.torDetected = true;
      await statesCol.updateOne({ ip }, { $inc: { tor_count: 1 } });
    }
    if (ipIntel && ipIntel.isVPN) {
      eventDoc.deception.vpnDetected = true;
      await statesCol.updateOne({ ip }, { $inc: { vpn_count: 1 } });
    }
  } catch (e) {
    console.warn(
      "Failed to increment tor/vpn counters:",
      e && e.message ? e.message : e
    );
  }

  const deviceFp = {
    userAgent: req.get("User-Agent") || "",
    acceptLang: req.get("Accept-Language") || "",
    screen: req.body.screen || null,
    timezone: req.body.timezone || null,
  };
  eventDoc.deviceFp = deviceFp;

  const pfp = payloadFingerprint(payload);
  eventDoc.payloadFp = pfp;

  // Run XSS and SQL heuristics early and record results on the event
  const xssResult = await detectXSS(payload);
  eventDoc.loginAttempt.xssLabel = xssResult.xssLabel;
  eventDoc.loginAttempt.xssScore = xssResult.xssScore;

  if (xssResult.xssLabel === "xss_payload") {
    // mark deception and notify
    eventDoc.deception.xssDetected = true;
    await logUnified(eventDoc);
    await triggerWebhook(eventDoc.event_id);

    // increment per-IP xss counter and decide whether to hint or escalate
    await statesCol.updateOne({ ip }, { $inc: { xss_count: 1 } });
    const updatedState = await getState(ip);
    const safePayload = escapeHtml(payload);

    // First time: show a subtle hint pointing to the frontend search for offers
    if ((updatedState.xss_count || 0) <= 1) {
      const frontendSearch = `http://3.236.124.19//search?q=${encodeURIComponent(
        payload
      )}`;
      return res.send(`
        <html>
        <body style="background:#07101a;color:#cbd5e1;padding:40px;font-family:Arial">
          <h3>Looking for Offers?</h3>
          <p>Our internal offers index may have special banking offers and discounts.</p>
          <p>Try searching the offers index: <a href="${frontendSearch}">${frontendSearch}</a></p>
          <p>Suggested query: <em>"credit card offers"</em></p>
        </body>
        </html>
      `);
    }

    // Subsequent detections: escalate to the search module deception
    const frontendSearch = `http://3.236.124.19//search?q=${encodeURIComponent(
      payload
    )}`;

    // Simple, minimal UI: short message and link to the frontend search
    return res.send(`
      <html>
        <body style="background:#07101a;color:#cbd5e1;padding:36px;font-family:Arial, sans-serif;">
          <h3 style="margin-bottom:8px">Search Error</h3>
          <p style="margin-bottom:12px">An unexpected pattern was detected. Try the frontend search:</p>
          <a href="${frontendSearch}" style="color:#7dd3fc;text-decoration:none;padding:8px 12px;background:#04293a;border-radius:6px;display:inline-block">Open Search</a>
        </body>
      </html>
    `);
  }

  const sqlResult = detectSQL(payload);
  eventDoc.deception.sqlLabel = sqlResult.sqlLabel;
  if (sqlResult.evidence) eventDoc.deception.sqlEvidence = sqlResult.evidence;

  if (sqlResult.sqlLabel === "sqli") {
    eventDoc.deception.hint = "sqli_detected";
    await logUnified(eventDoc);
    await triggerWebhook(eventDoc.event_id);
    return res.send(sqliHintHTML);
  }

  const now = Date.now();
  let delta = null;
  if (state.lastRequest) delta = now - new Date(state.lastRequest).getTime();

  const updatedDeltas = [...(state.requestTimes || [])];
  if (delta !== null) updatedDeltas.push(delta);

  await statesCol.updateOne(
    { ip },
    {
      $set: {
        lastRequest: new Date(now),
        requestTimes: updatedDeltas.slice(-200),
        requestCount: (state.requestCount || 0) + 1,
      },
    }
  );

  eventDoc.behavioral = {
    delta,
    requestCount: state.requestCount + 1,
    failed_logins: state.failed_logins,
  };

  if (state.failed_logins >= 7) {
    eventDoc.loginAttempt.status = "banned";
    eventDoc.deception.banned = true;
    await logUnified(eventDoc);
    await triggerWebhook(eventDoc.event_id);

    return res.status(403).send(bannedHTML);
  }

  if (username === "admin" && password === TARGET_PASSWORD) {
    eventDoc.loginAttempt = {
      username,
      passwordPreview: password.slice(0, 100),
      mlLabel: "override",
      mlConf: 1,
      status: "correct",
    };

    const session = {
      username,
      otp_status: "Not Verified",
      created: new Date().toISOString(),
    };

    res.cookie(
      "session",
      Buffer.from(JSON.stringify(session)).toString("base64"),
      {
        httpOnly: false,
        maxAge: 1800000,
      }
    );

    await logUnified(eventDoc);
    await triggerWebhook(eventDoc.event_id);

    return res.send(otpFormHTML);
  }

  let ml;
  try {
    ml = (await axios.post(ML_API, { query: payload }, { timeout: 4000 })).data;
  } catch {
    ml = { label: "normal", confidence: 0.4 };
  }

  if (username.toLowerCase() === "admin") {
    ml.label = "normal";
    ml.confidence = 1.0;
  }

  eventDoc.loginAttempt = {
    username,
    passwordPreview: password.slice(0, 100),
    mlLabel: ml.label,
    mlConf: ml.confidence,
    status: "failed",
  };

  if (ml.label === "injected") {
    eventDoc.deception.hint = "users_table";
    await logUnified(eventDoc);
    await triggerWebhook(eventDoc.event_id);

    return res.send(sqliHintHTML);
  }

  if (payload.toLowerCase().includes("select * from 'users'")) {
    let rows = [];
    try {
      rows = await sqliteAll(`SELECT * FROM 'users'`);
    } catch (e) {
      rows = [{ error: e.message }];
    }

    eventDoc.deception.tableLeak = true;
    eventDoc.deception.leakedRows = rows;

    await logUnified(eventDoc);
    await triggerWebhook(eventDoc.event_id);

    return res.send(
      tableLeakHTML.replace("{{LEAKED_DATA}}", JSON.stringify(rows, null, 2))
    );
  }

  const newFails = (state.failed_logins || 0) + 1;
  await statesCol.updateOne(
    { ip },
    { $set: { failed_logins: newFails, lastSeen: new Date() } }
  );

  if (newFails > 3 && newFails < 7) {
    eventDoc.deception.tarpitDelay = 5000;
    await new Promise((r) => setTimeout(r, 5000));
  }

  await logUnified(eventDoc);
  await triggerWebhook(eventDoc.event_id);

  return res.status(401).send(loginFailedHTML);
});

// OTP VERIFY
app.post("/otp-verify", async (req, res) => {
  const ip = getIP(req);
  const cookie = req.cookies.session || "";
  let parsed = {};
  try {
    parsed = JSON.parse(Buffer.from(cookie, "base64").toString());
  } catch {}

  const eventDoc = {
    event_id: uuidv4(),
    ts: new Date(),
    ip,
    otpCode: req.body.code,
    parsedCookie: parsed,
  };

  await logUnified(eventDoc);
  await triggerWebhook(eventDoc.event_id);

  if (/^\d{4,8}$/.test(req.body.code)) {
    return res.send(uploadFormHTML);
  }

  return res.send(invalidOtpHTML);
});

// UPLOAD ID handled below with full metadata + DB insert (see later `/upload-id` handler)

// HEALTH
app.get("/health", (req, res) => res.json({ ok: true }));
// HELPERS
// --------------------------------------------------
function sha256(s) {
  return crypto.createHash("sha256").update(s).digest("hex");
}

function computeMerkleRoot(hashes) {
  if (hashes.length === 0) return null;
  let layer = hashes.slice();
  while (layer.length > 1) {
    const next = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = layer[i + 1] || layer[i];
      next.push(sha256(left + right));
    }
    layer = next;
  }
  return layer[0];
}

function detectScanner(req) {
  const ua = (req.get("User-Agent") || "").toLowerCase();
  if (ua.includes("gobuster")) return "Gobuster";
  if (ua.includes("dirsearch")) return "Dirsearch";
  if (ua.includes("sqlmap")) return "SQLmap";
  if (ua.includes("ffuf")) return "FFUF";
  if (ua.includes("burp")) return "Burp Suite";
  if (ua.includes("python-requests")) return "Python Script";
  if (ua.includes("curl/")) return "Curl";
  return null;
}

function getIP(req) {
  const xf = req.headers["x-forwarded-for"];
  if (xf && typeof xf === "string") return xf.split(",")[0].trim();
  return req.socket.remoteAddress.replace(/^::ffff:/, "");
}

async function getIPIntel(ip) {
  try {
    const r = await axios.get(`https://ipapi.co/${ip}/json/`, {
      timeout: 3000,
    });
    const d = r.data || {};
    const org = d.org || "";
    const isVPN = /vpn|proxy|hosting|cloud|aws|amazon|google/i.test(
      org.toLowerCase()
    );

    // Add Tor detection if we have the exit list loaded
    const isTor = typeof isTorExit === "function" ? isTorExit(ip) : false;

    return {
      ip,
      asn: d.asn || null,
      org,
      country: d.country_name || null,
      city: d.city || null,
      region: d.region || null,
      isVPN,
      isTor,
    };
  } catch {
    const isTor = typeof isTorExit === "function" ? isTorExit(ip) : false;
    return { ip, error: "geo_lookup_failed", isTor };
  }
}

// ----------------------------
// Tor exit node list helpers
// ----------------------------
const torExitSet = new Set();

async function loadTorExitList() {
  try {
    const url = "https://check.torproject.org/exit-addresses";
    const resp = await axios.get(url, { timeout: 5000 });
    const txt = resp.data || "";
    const lines = txt.split(/\r?\n/);
    const newSet = new Set();
    for (const line of lines) {
      if (line.startsWith("ExitAddress ")) {
        const parts = line.split(" ");
        if (parts[1]) newSet.add(parts[1].trim());
      }
    }
    // replace contents atomically
    torExitSet.clear();
    for (const ip of newSet) torExitSet.add(ip);
    console.log(`Loaded ${torExitSet.size} Tor exit nodes.`);
  } catch (e) {
    console.warn(
      "Failed to load Tor exit list:",
      e && e.message ? e.message : e
    );
  }
}

function isTorExit(ip) {
  if (!ip) return false;
  return torExitSet.has(ip);
}

// Load immediately and refresh periodically
await loadTorExitList();
setInterval(() => loadTorExitList().catch(() => {}), 60 * 60 * 1000);

function entropy(s) {
  if (!s) return 0;
  const freq = {};
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let e = 0;
  const len = s.length;
  for (const c in freq) {
    const p = freq[c] / len;
    e -= p * Math.log2(p);
  }
  return e;
}

// Safe HTML escape helper for templates
function escapeHtml(s) {
  if (s === null || s === undefined) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Simple payload fingerprinting used for event metadata
function payloadFingerprint(s) {
  const src = s || "";
  return {
    hash: sha256(src),
    entropy: entropy(src),
    len: src.length,
  };
}

// Call external XSS detection service and return a normalized result
async function detectXSS(payload) {
  try {
    const resp = await axios.post(
      XSS_API,
      { html: payload },
      { timeout: 3000 }
    );
    return {
      xssLabel: resp.data.label || "normal_html",
      xssScore: resp.data.score || 0,
    };
  } catch (err) {
    return { xssLabel: "normal_html", xssScore: 0 };
  }
}

// Lightweight heuristic SQL-injection detector (returns a label + evidence)
function detectSQL(payload) {
  const p = payload || "";
  const rules = [
    { name: "select_from", re: /\bselect\b[\s\S]*\bfrom\b/i },
    { name: "union_select", re: /\bunion\b[\s\S]*\bselect\b/i },
    { name: "or_true", re: /(\bor\b\s*1\s*=\s*1\b)|('\s*or\s*'1'\s*=\s*'1')/i },
    { name: "comment", re: /--|;#/ },
    { name: "drop_table", re: /\bdrop\b\s+\btable\b/i },
    { name: "insert_into", re: /\binsert\b\s+\binto\b/i },
  ];

  for (const r of rules) {
    if (r.re.test(p)) return { sqlLabel: "sqli", evidence: r.name };
  }
  return { sqlLabel: "normal", evidence: null };
}

async function logUnified(eventDoc) {
  const serialized = JSON.stringify(eventDoc);
  const hash = sha256(serialized);

  eventDoc.hash = hash;

  await eventsCol.insertOne(eventDoc);

  const meta = await metaCol.findOneAndUpdate(
    { _id: "counters" },
    { $inc: { eventCounter: 1 } },
    { returnDocument: "after" }
  );

  const counter = meta.value.eventCounter;

  if (counter % MERKLE_BATCH === 0) {
    const batch = await eventsCol
      .find()
      .sort({ ts: -1 })
      .limit(MERKLE_BATCH)
      .toArray();
    const roots = batch.map((e) => e.hash).reverse();
    const root = computeMerkleRoot(roots);

    await metaCol.updateOne(
      { _id: "counters" },
      { $set: { lastMerkleRoot: root, lastMerkleAt: new Date() } }
    );

    await db.collection("merkle_roots").insertOne({ root, ts: new Date() });
  }
}

// Send event ID to external webhook (n8n)
async function triggerWebhook(eventId) {
  try {
    await axios.post("https://mlomi.app.n8n.cloud/webhook-test/new-event", {
      eventId,
    });
  } catch (e) {
    console.warn("Webhook POST failed:", e && e.message ? e.message : e);
  }
}

// --------------------------------------------------
// STATE HELPERS
// --------------------------------------------------
async function getState(ip) {
  let s = await statesCol.findOne({ ip });
  if (!s) {
    s = {
      ip,
      failed_logins: 0,
      sqli_count: 0,
      xss_count: 0,
      tor_count: 0,
      vpn_count: 0,
      requestCount: 0,
      lastRequest: null,
      requestTimes: [],
    };
    await statesCol.insertOne(s);
  }
  return s;
}

// --------------------------------------------------
// ENHANCED UI HTML TEMPLATES
// --------------------------------------------------

const otpFormHTML = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Two-Factor Authentication</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      padding: 40px;
      max-width: 420px;
      width: 100%;
      animation: slideUp 0.4s ease-out;
    }
    @keyframes slideUp {
      from { opacity: 0; transform: translateY(30px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .icon {
      width: 64px;
      height: 64px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 24px;
      font-size: 32px;
    }
    h3 {
      text-align: center;
      color: #1a202c;
      font-size: 24px;
      margin-bottom: 8px;
      font-weight: 600;
    }
    .subtitle {
      text-align: center;
      color: #718096;
      margin-bottom: 32px;
      font-size: 14px;
    }
    .form-group {
      margin-bottom: 24px;
    }
    label {
      display: block;
      color: #4a5568;
      font-size: 14px;
      font-weight: 500;
      margin-bottom: 8px;
    }
    input {
      width: 100%;
      padding: 12px 16px;
      border: 2px solid #e2e8f0;
      border-radius: 8px;
      font-size: 16px;
      transition: all 0.3s;
      font-family: monospace;
      letter-spacing: 4px;
      text-align: center;
    }
    input:focus {
      outline: none;
      border-color: #667eea;
      box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
    }
    button {
      width: 100%;
      padding: 14px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    button:hover {
      transform: translateY(-2px);
      box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
    }
    button:active {
      transform: translateY(0);
    }
    .info {
      margin-top: 20px;
      padding: 12px;
      background: #edf2f7;
      border-radius: 8px;
      font-size: 13px;
      color: #4a5568;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="icon">🔐</div>
    <h3>Two-Factor Authentication</h3>
    <p class="subtitle">Enter the verification code sent to your device</p>
    
    <form method="POST" action="/otp-verify">
      <div class="form-group">
        <label for="code">Verification Code</label>
        <input 
          type="text" 
          id="code"
          name="code" 
          placeholder="000000"
          maxlength="8"
          autocomplete="off"
          required
        >
      </div>
      <button type="submit">Verify Code</button>
    </form>
    
    <div class="info">
      📱 Check your authenticator app or SMS
    </div>
  </div>
</body>
</html>
`;

const uploadFormHTML = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Identity Verification</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      padding: 40px;
      max-width: 480px;
      width: 100%;
      animation: slideUp 0.4s ease-out;
    }
    @keyframes slideUp {
      from { opacity: 0; transform: translateY(30px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .success-icon {
      width: 64px;
      height: 64px;
      background: linear-gradient(135deg, #48bb78 0%, #38a169 100%);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 24px;
      font-size: 32px;
      animation: checkmark 0.5s ease-out;
    }
    @keyframes checkmark {
      0% { transform: scale(0); }
      50% { transform: scale(1.2); }
      100% { transform: scale(1); }
    }
    h3 {
      text-align: center;
      color: #1a202c;
      font-size: 24px;
      margin-bottom: 8px;
      font-weight: 600;
    }
    .subtitle {
      text-align: center;
      color: #718096;
      margin-bottom: 32px;
      font-size: 14px;
    }
    .upload-area {
      border: 2px dashed #cbd5e0;
      border-radius: 12px;
      padding: 40px 20px;
      text-align: center;
      margin-bottom: 24px;
      transition: all 0.3s;
      cursor: pointer;
      background: #f7fafc;
    }
    .upload-area:hover {
      border-color: #667eea;
      background: #edf2f7;
    }
    .upload-area.dragover {
      border-color: #667eea;
      background: #e6fffa;
    }
    .upload-icon {
      font-size: 48px;
      margin-bottom: 16px;
    }
    input[type="file"] {
      display: none;
    }
    .file-label {
      display: block;
      color: #4a5568;
      font-size: 16px;
      font-weight: 500;
      margin-bottom: 8px;
    }
    .file-hint {
      color: #a0aec0;
      font-size: 13px;
    }
    .selected-file {
      background: #edf2f7;
      padding: 12px;
      border-radius: 8px;
      margin-top: 16px;
      font-size: 14px;
      color: #2d3748;
      display: none;
    }
    button {
      width: 100%;
      padding: 14px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    button:hover:not(:disabled) {
      transform: translateY(-2px);
      box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
    }
    button:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }
    .info {
      margin-top: 20px;
      padding: 12px;
      background: #fff5f5;
      border-left: 4px solid #fc8181;
      border-radius: 4px;
      font-size: 13px;
      color: #742a2a;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="success-icon">✓</div>
    <h3>Verification Successful</h3>
    <p class="subtitle">Please upload your government-issued ID to complete verification</p>
    
    <form method="POST" enctype="multipart/form-data" action="/upload-id" id="uploadForm">
      <div class="upload-area" id="uploadArea">
        <div class="upload-icon">📄</div>
        <span class="file-label">Click to upload or drag and drop</span>
        <p class="file-hint">Supported: JPG, PNG, PDF (Max 20MB)</p>
        <input type="file" name="idfile" id="idfile" accept="image/*,.pdf" required>
        <div class="selected-file" id="selectedFile"></div>
      </div>
      <button type="submit" id="submitBtn" disabled>Upload Document</button>
    </form>
    
    <div class="info">
      🔒 Your information is encrypted and secure
    </div>
  </div>

  <script>
    const uploadArea = document.getElementById('uploadArea');
    const fileInput = document.getElementById('idfile');
    const selectedFile = document.getElementById('selectedFile');
    const submitBtn = document.getElementById('submitBtn');

    uploadArea.addEventListener('click', () => fileInput.click());

    fileInput.addEventListener('change', (e) => {
      if (e.target.files.length > 0) {
        const file = e.target.files[0];
        selectedFile.textContent = '📎 ' + file.name + ' (' + (file.size / 1024).toFixed(2) + ' KB)';
        selectedFile.style.display = 'block';
        submitBtn.disabled = false;
      }
    });

    uploadArea.addEventListener('dragover', (e) => {
      e.preventDefault();
      uploadArea.classList.add('dragover');
    });

    uploadArea.addEventListener('dragleave', () => {
      uploadArea.classList.remove('dragover');
    });

    uploadArea.addEventListener('drop', (e) => {
      e.preventDefault();
      uploadArea.classList.remove('dragover');
      fileInput.files = e.dataTransfer.files;
      fileInput.dispatchEvent(new Event('change'));
    });
  </script>
</body>
</html>
`;

const sqliHintHTML = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Server Error</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Courier New', monospace;
      background: #0d1117;
      color: #c9d1d9;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 6px;
      padding: 32px;
      max-width: 600px;
      width: 100%;
      box-shadow: 0 8px 24px rgba(0,0,0,0.5);
    }
    h3 {
      color: #f85149;
      margin-bottom: 20px;
      font-size: 20px;
    }
    pre {
      background: #0d1117;
      padding: 16px;
      border-radius: 6px;
      border: 1px solid #30363d;
      color: #8b949e;
      overflow-x: auto;
      font-size: 14px;
      line-height: 1.6;
    }
    .error-code {
      color: #79c0ff;
      margin-top: 12px;
      font-size: 13px;
    }
  </style>
</head>
<body>
  <div class="container">
    <h3>⚠️ Server Error</h3>
    <pre>Information schema suggests table 'users'</pre>
    <div class="error-code">Error Code: SQL_DEBUG_1064</div>
  </div>
</body>
</html>
`;

const loginFailedHTML = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authentication Failed</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      padding: 40px;
      max-width: 420px;
      width: 100%;
      text-align: center;
    }
    .error-icon {
      width: 64px;
      height: 64px;
      background: linear-gradient(135deg, #fc8181 0%, #f56565 100%);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 24px;
      font-size: 32px;
    }
    h3 {
      color: #1a202c;
      font-size: 24px;
      margin-bottom: 16px;
      font-weight: 600;
    }
    p {
      color: #718096;
      font-size: 14px;
      margin-bottom: 24px;
    }
    .back-btn {
      display: inline-block;
      padding: 12px 32px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      text-decoration: none;
      border-radius: 8px;
      font-weight: 600;
      transition: transform 0.2s;
    }
    .back-btn:hover {
      transform: translateY(-2px);
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="error-icon">✕</div>
    <h3>Invalid Credentials</h3>
    <p>The username or password you entered is incorrect. Please try again.</p>
    <a href="http://3.236.124.19//admin" class="back-btn">← Back to Login</a>
  </div>
</body>
</html>
`;

const bannedHTML = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Access Blocked</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      background: linear-gradient(135deg, #1a202c 0%, #2d3748 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.5);
      padding: 40px;
      max-width: 420px;
      width: 100%;
      text-align: center;
    }
    .warning-icon {
      width: 64px;
      height: 64px;
      background: linear-gradient(135deg, #ed8936 0%, #dd6b20 100%);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 24px;
      font-size: 32px;
    }
    h3 {
      color: #1a202c;
      font-size: 24px;
      margin-bottom: 16px;
      font-weight: 600;
    }
    p {
      color: #718096;
      font-size: 14px;
      line-height: 1.6;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="warning-icon">🚫</div>
    <h3>Access Temporarily Blocked</h3>
    <p>Your IP address has been temporarily blocked due to multiple failed authentication attempts. Please try again later.</p>
  </div>
</body>
</html>
`;

const tableLeakHTML = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Database Error</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Courier New', monospace;
      background: #0d1117;
      color: #c9d1d9;
      min-height: 100vh;
      padding: 20px;
    }
    .container {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 6px;
      padding: 32px;
      max-width: 900px;
      margin: 40px auto;
      box-shadow: 0 8px 24px rgba(0,0,0,0.5);
    }
    h2 {
      color: #f85149;
      margin-bottom: 20px;
      font-size: 22px;
    }
    pre {
      background: #0d1117;
      padding: 20px;
      border-radius: 6px;
      border: 1px solid #30363d;
      color: #8b949e;
      overflow-x: auto;
      font-size: 13px;
      line-height: 1.8;
      white-space: pre-wrap;
      word-wrap: break-word;
    }
    .footer {
      margin-top: 16px;
      color: #8b949e;
      font-size: 12px;
      font-style: italic;
    }
  </style>
</head>
<body>
  <div class="container">
    <h2>⚠️ Partial Database Dump</h2>
    <pre>{{LEAKED_DATA}}</pre>
    <p class="footer">-- Error 1064: packet loss detected</p>
  </div>
</body>
</html>
`;

const invalidOtpHTML = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Invalid Code</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      padding: 40px;
      max-width: 420px;
      width: 100%;
      text-align: center;
    }
    .error-icon {
      width: 64px;
      height: 64px;
      background: linear-gradient(135deg, #fc8181 0%, #f56565 100%);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 24px;
      font-size: 32px;
    }
    h3 {
      color: #1a202c;
      font-size: 24px;
      margin-bottom: 16px;
      font-weight: 600;
    }
    p {
      color: #718096;
      font-size: 14px;
      line-height: 1.6;
    }
    .back-btn {
      display: inline-block;
      margin-top: 20px;
      padding: 10px 20px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border-radius: 8px;
      text-decoration: none;
      font-weight: 600;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="error-icon">✕</div>
    <h3>Invalid Code</h3>
    <p>The verification code you entered is invalid. Please try again.</p>
    <a href="http://3.236.124.19//admin" class="back-btn">← Back to Login</a>
  </div>
</body>
</html>
`;

// --------------------------------------------------
// ROUTES
// --------------------------------------------------
app.get("/", (req, res) =>
  res.sendFile(path.join(process.cwd(), "public", "index.html"))
);

// POST /admin (UNIFIED EVENT)
// (Removed an earlier duplicate /admin handler - consolidated below)
app.get("/search", async (req, res) => {
  const q = req.query.q || "";
  const safeQ = escapeHtml(q);

  // Check for XSS in the query — log the search attempt
  const xssAgain = await detectXSS(q);

  const eventDoc = {
    event_id: uuidv4(),
    ts: new Date(),
    ip: getIP(req),
    route: "/search",
    searchQuery: q,
    xssLabel: xssAgain.xssLabel,
    xssScore: xssAgain.xssScore,
  };

  await logUnified(eventDoc);

  // If the query looks like XSS, return a fake-leak page (deception)
  if (xssAgain.xssLabel === "xss_payload") {
    // store the XSS query into a dedicated collection for later analysis
    try {
      await db.collection("xss_searches").insertOne({
        _id: uuidv4(),
        q,
        safeQ,
        ip: getIP(req),
        ts: new Date(),
      });
    } catch (e) {
      console.warn(
        "Failed to record xss_searches:",
        e && e.message ? e.message : e
      );
    }

    // Multiple decoy templates — choose one at random
    const decoys = [
      {
        title: "Internal Offers Index",
        body: `DB_HOST=10.0.0.23\nDB_USER=admin_readonly\nAPI_KEY=4856515-ADW5651dDW-5s1s1D6D4\nOFFERS_TABLE=bank_offers_v2\nENABLE_EXPERIMENTAL_FEATURES=true`,
      },
      {
        title: "Debug Dump",
        body: `ERROR LOG: NullPointer at /srv/app/routes/offers.js:112\nTRACE: 0x7ffad3...\nCONFIG: s3_bucket=banking-prod-backups`,
      },
      {
        title: "Credentials",
        body: `redis://:r3d1s_p@ss@10.0.0.5:6379\nPAYMENT_API_KEY=pk_4856515-ADW5651dDW-5s1s1D6D4`,
      },
      {
        title: "Service Tokens",
        body: `stripe_key=sk_live`,
      },
    ];

    const pick = decoys[Math.floor(Math.random() * decoys.length)];

    // Minimal, glitchy-looking HTML with only main text
    return res.send(`
      <html>
        <body style="background:#000;color:#cfcfcf;font-family:monospace;padding:20px;">
          <h3>${escapeHtml(pick.title)}</h3>
          <pre style="white-space:pre-wrap;">${escapeHtml(pick.body)}</pre>
        </body>
      </html>
    `);
  }

  // Otherwise, redirect user to the frontend search experience (Vite app)
  // so the frontend at http://localhost:5173 handles normal searches.
  const frontendSearch = `http://3.236.124.19/search?q=${encodeURIComponent(
    q
  )}`;
  return res.redirect(frontendSearch);
});

// OTP VERIFY
app.post("/otp-verify", async (req, res) => {
  const ip = getIP(req);
  const cookie = req.cookies.session || "";
  let parsed = {};
  try {
    parsed = JSON.parse(Buffer.from(cookie, "base64").toString());
  } catch {}

  const eventDoc = {
    event_id: uuidv4(),
    ts: new Date(),
    ip,
    otpCode: req.body.code,
    parsedCookie: parsed,
  };

  await logUnified(eventDoc);
  await triggerWebhook(eventDoc.event_id);

  if (/^\d{4,8}$/.test(req.body.code)) {
    return res.send(uploadFormHTML);
  }

  return res.send(invalidOtpHTML);
});

// UPLOAD ID — SAVE METADATA INTO upload_files COLLECTION + events
app.post("/upload-id", upload.single("idfile"), async (req, res) => {
  const ip = getIP(req);

  let fileMeta = {};
  let exifMeta = {};

  if (req.file) {
    try {
      const filePath = req.file.path;
      const fileBuffer = fs.readFileSync(filePath);

      // Compute SHA256
      const hash = crypto.createHash("sha256").update(fileBuffer).digest("hex");

      // Extract EXIF
      try {
        const parser = ExifParser.create(fileBuffer);
        exifMeta = parser.parse();
      } catch (err) {
        exifMeta = { error: "EXIF parsing failed", details: err.message };
      }

      fileMeta = {
        _id: uuidv4(),
        ts: new Date(),
        ip,
        originalName: req.file.originalname,
        savedAs: req.file.filename,
        path: filePath,
        mimeType: req.file.mimetype,
        sizeBytes: req.file.size,
        sha256: hash,
        exif: exifMeta,
      };

      // INSERT INTO upload_files (this is the part that was missing)
      await uploadFilesCol.insertOne(fileMeta);
      console.log(`Saved upload metadata to Mongo: ${fileMeta._id}`);
    } catch (err) {
      fileMeta = { error: "file_processing_failed", details: err.message };
    }
  } else {
    fileMeta = { error: "no_file_uploaded" };
  }

  // Also log this event in unified events
  await logUnified({
    event_id: uuidv4(),
    ts: new Date(),
    ip,
    uploadMetaSaved: true,
    upload: fileMeta,
  });

  return res.send(`<h3>ID uploaded. Manual review 24–72 hours.</h3>`);
});

// HEALTH
app.get("/health", (req, res) => res.json({ ok: true }));

const server = app.listen(PORT, () =>
  console.log(`Chameleon Honeypot (Unified Event vB) running on port ${PORT}`)
);

server.on("error", (err) => {
  if (err && err.code === "EADDRINUSE") {
    console.error(
      `Port ${PORT} already in use. Set a different PORT or stop the process using it.`
    );
    process.exit(1);
  }
  console.error("Server error:", err);
  process.exit(1);
});
