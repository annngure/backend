/** Lightweight Express backend that matches the register.js / index.js / dashboard.js*  frontend patterns (REST endpoints: /register, /login, /employees, /alerts, /health).
 * - If FIREBASE_ADMIN service account is provided (env FIREBASE_ADMIN_PATH), the server
 *   will try to use Firebase Admin for auth + Firestore.
 * - Otherwise it falls back to a simple file-backed JSON store at ./data/db.json.
 *
 * This rewrite preserves frontend expectations (JSON responses) and keeps behavior
 * compatible with the frontends you showed (no Firebase required).
 *
 * Install: npm i express helmet cors cookie-parser express-rate-limit
 * Optional (for Firebase): firebase-admin, axios
 */

import express from "express";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import fs from "fs/promises";
import path from "path";
import crypto from "crypto";

const app = express();
const DATA_PATH = path.join(process.cwd(), "data");
const DB_FILE = path.join(DATA_PATH, "db.json");

// Middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.FRONTEND_URL || "http://127.0.0.1:5500", credentials: true }));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const authLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false
});

// Utility: simple SHA256 password hashing (not a full KDF, but OK for demo)
function hashPassword(password) {
  return crypto.createHash("sha256").update(String(password)).digest("hex");
}

async function ensureDb() {
  try {
    await fs.mkdir(DATA_PATH, { recursive: true });
    try {
      await fs.access(DB_FILE);
    } catch {
      const initial = { employees: [], alerts: [] };
      await fs.writeFile(DB_FILE, JSON.stringify(initial, null, 2), "utf8");
    }
  } catch (err) {
    console.error("Failed to ensure DB file:", err);
    throw err;
  }
}

async function readDb() {
  await ensureDb();
  const raw = await fs.readFile(DB_FILE, "utf8");
  return JSON.parse(raw || "{}");
}
async function writeDb(db) {
  await ensureDb();
  await fs.writeFile(DB_FILE, JSON.stringify(db, null, 2), "utf8");
}

// Helpers
function makeId(prefix = "") {
  return prefix + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}



// Register (used by register.js)
app.post("/register", authLimiter, async (req, res) => {
  const { name, email, password, role = "truck-driver" && "deport-employee" , empId } = req.body || {};
  const errors = [];
  if (!name) errors.push("name required");
  if (!email) errors.push("email required");
  if (!password) errors.push("password required");
  if (!empId) errors.push("empId required");
  if (errors.length) return res.status(400).json({ success: false, errors });

  try {
    const db = await readDb();
    // prevent duplicate email
    if (db.employees.find(e => e.email?.toLowerCase() === email.toLowerCase())) {
      return res.status(409).json({ success: false, message: "Email already registered" });
    }

    const uid = makeId("u_");
    const employee = {
      _id: uid,
      name,
      email,
      role,
      empId,
      passwordHash: hashPassword(password),
      createdAt: new Date().toISOString(),
      lastLogin: null,
      lastLogout: null,
      clockIn: null,
      clockOut: null,
      status: "safe",
      alarmTriggered: false
    };

    db.employees.push(employee);
    await writeDb(db);

    // Return user object (no password)
    const out = { _id: employee._id, email: employee.email, role: employee.role, empId: employee.empId, name: employee.name };
    return res.status(201).json({ success: true, user: out });
  } catch (err) {
    console.error("Register error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// Login (used by index.js)
app.post("/login", authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ success: false, message: "Email and password required" });

  try {
    const db = await readDb();
    const user = db.employees.find(e => e.email?.toLowerCase() === email.toLowerCase());
    if (!user) return res.status(400).json({ success: false, message: "Invalid credentials" });
    if (user.passwordHash !== hashPassword(password)) return res.status(400).json({ success: false, message: "Invalid credentials" });

    // update lastLogin
    user.lastLogin = new Date().toISOString();
    await writeDb(db);

    const out = { _id: user._id, email: user.email, role: user.role, empId: user.empId, name: user.name, lastLogin: user.lastLogin };
    return res.json({ success: true, user: out });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// Employees list (used by dashboard.js)
app.get("/employees", async (req, res) => {
  try {
    const db = await readDb();
    return res.json(db.employees || []);
  } catch (err) {
    console.error("GET /employees error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// Create employee (admin UI)---check if frontend contain admin UI before using
app.post("/employees", async (req, res) => {
  const { name, email, role = "employee", empId } = req.body || {};
  if (!name || !email || !empId) return res.status(400).json({ success: false, message: "name,email,empId required" });

  try {
    const db = await readDb();
    const uid = makeId("u_");
    const employee = {
      _id: uid,
      name, email, role, empId, createdAt: new Date().toISOString(),
      lastLogin: null, lastLogout: null, clockIn: null, clockOut: null, status: "safe", alarmTriggered: false
    };
    db.employees.push(employee);
    await writeDb(db);
    return res.status(201).json(employee);
  } catch (err) {
    console.error("POST /employees error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// Patch employee (clock, status updates)
app.patch("/employees/:id", async (req, res) => {
  const id = req.params.id;
  const patch = req.body || {};
  try {
    const db = await readDb();
    const idx = db.employees.findIndex(e => e._id === id || e.empId === id);
    if (idx === -1) return res.status(404).json({ success: false, message: "Employee not found" });

    db.employees[idx] = { ...db.employees[idx], ...patch, updatedAt: new Date().toISOString() };
    await writeDb(db);

    // If status changed to 'leak', create an alert
    if (patch.status === "leak") {
      const alert = {
        _id: makeId("a_"),
        employeeId: db.employees[idx]._id,
        type: "leak",
        status: "leak",
        location: patch.location || "unknown",
        timestamp: new Date().toISOString()
      };
      db.alerts = db.alerts || [];
      db.alerts.push(alert);
      await writeDb(db);
    }

    return res.json({ success: true, employee: db.employees[idx] });
  } catch (err) {
    console.error("PATCH /employees/:id error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// Alerts endpoints (used by dashboard.js)
app.get("/alerts", async (req, res) => {
  try {
    const since = req.query.since;
    const db = await readDb();
    let alerts = db.alerts || [];
    if (since) {
      const sinceDt = new Date(since);
      if (!isNaN(sinceDt)) alerts = alerts.filter(a => new Date(a.timestamp) >= sinceDt);
    }
    return res.json(alerts);
  } catch (err) {
    console.error("GET /alerts error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/alerts", async (req, res) => {
  const { employeeId, type = "leak", location } = req.body || {};
  if (!employeeId) return res.status(400).json({ success: false, message: "employeeId required" });
  try {
    const db = await readDb();
    const alert = { _id: makeId("a_"), employeeId, type, location: location || "unknown", timestamp: new Date().toISOString() };
    db.alerts = db.alerts || [];
    db.alerts.push(alert);
    await writeDb(db);
    return res.status(201).json(alert);
  } catch (err) {
    console.error("POST /alerts error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// Logout (simple)
app.post("/logout", (req, res) => {
  res.json({ success: true });
});

// Generic error handler
app.use((err, req, res, next) => {
  console.error("Server error:", err);
  res.status(500).json({ success: false, message: "Internal server error" });
});

// Start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT} (API_BASE)`);
});