/** Express Backend - Gas Safety Alert System
 * Simple backend that syncs with Firebase Firestore
 * Frontend handles all auth via Firebase Auth
 * Backend provides backup sync endpoints
 * 
 * Install: npm i express helmet cors cookie-parser express-rate-limit firebase-admin
 */

import express from "express";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import admin from "firebase-admin";
import fs from "fs";
import path from "path";

const app = express();

// Initialize Firebase Admin SDK
const serviceAccountPath = process.env.FIREBASE_ADMIN_PATH || 
  path.join(process.cwd(), "gas-safety-guide-firebase-adminsdk-fbsvc-ff05bb082e.json");

let db = null;

try {
  if (fs.existsSync(serviceAccountPath)) {
    const serviceAccount = JSON.parse(fs.readFileSync(serviceAccountPath, "utf8"));
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      projectId: serviceAccount.project_id
    });
    db = admin.firestore();
    console.log("✓ Firebase Firestore connected");
  } else {
    console.warn("⚠ Firebase service account not found at:", serviceAccountPath);
  }
} catch (err) {
  console.warn("⚠ Firebase initialization error:", err.message);
}

// Middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: "*", credentials: true }));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});

// ==================== ENDPOINTS ====================

// POST /register - Sync registration from frontend (Firebase Auth handles actual registration)
app.post("/register", authLimiter, async (req, res) => {
  const { userId, name, email, role, empId, createdAt } = req.body || {};
  
  if (!userId || !name || !email || !role || !empId) {
    return res.status(400).json({ success: false, message: "Missing required fields" });
  }

  try {
    if (!db) {
      return res.status(503).json({ success: false, message: "Database not initialized" });
    }

    // Store in Firestore with userId as document ID
    const employeeRef = db.collection("employees").doc(userId);
    await employeeRef.set({
      userId,
      name,
      email: email.toLowerCase(),
      role,
      empId,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      lastLogin: null,
      clockIn: null,
      clockOut: null,
      status: "safe"
    }, { merge: true });

    return res.status(201).json({ 
      success: true, 
      message: "User registered successfully",
      user: { userId, name, email, role, empId }
    });
  } catch (err) {
    console.error("Registration sync error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// POST /login - Sync login from frontend
app.post("/login", authLimiter, async (req, res) => {
  const { userId, email, role, lastLogin } = req.body || {};
  
  if (!userId || !email) {
    return res.status(400).json({ success: false, message: "Missing required fields" });
  }

  try {
    if (!db) {
      return res.status(503).json({ success: false, message: "Database not initialized" });
    }

    // Update lastLogin in Firestore
    const employeeRef = db.collection("employees").doc(userId);
    await employeeRef.update({
      lastLogin: admin.firestore.FieldValue.serverTimestamp()
    });

    return res.json({ 
      success: true, 
      message: "Login logged successfully"
    });
  } catch (err) {
    console.error("Login sync error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// GET /employees - Fetch all employees
app.get("/employees", async (req, res) => {
  try {
    if (!db) {
      return res.status(503).json({ success: false, message: "Database not initialized" });
    }

    const snapshot = await db.collection("employees").get();
    const employees = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

    return res.json(employees);
  } catch (err) {
    console.error("GET /employees error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// GET /alerts - Fetch all alerts
app.get("/alerts", async (req, res) => {
  try {
    if (!db) {
      return res.status(503).json({ success: false, message: "Database not initialized" });
    }

    const since = req.query.since;
    let query = db.collection("alerts");
    
    if (since) {
      const sinceDate = new Date(since);
      query = query.where("createdAt", ">=", sinceDate);
    }

    const snapshot = await query.orderBy("createdAt", "desc").get();
    const alerts = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

    return res.json(alerts);
  } catch (err) {
    console.error("GET /alerts error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// POST /alerts - Create alert (called by frontend)
app.post("/alerts", async (req, res) => {
  const { userId, employeeName, location, status } = req.body || {};
  
  if (!userId) {
    return res.status(400).json({ success: false, message: "userId required" });
  }

  try {
    if (!db) {
      return res.status(503).json({ success: false, message: "Database not initialized" });
    }

    const alert = {
      userId,
      employeeName: employeeName || "Unknown",
      location: location || "Unknown",
      status: status || "Gas Leak Detected",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      resolvedAt: null
    };

    const docRef = await db.collection("alerts").add(alert);

    return res.status(201).json({ 
      success: true, 
      alert: { id: docRef.id, ...alert }
    });
  } catch (err) {
    console.error("POST /alerts error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// PATCH /employees/:userId - Update employee
app.patch("/employees/:userId", async (req, res) => {
  const { userId } = req.params;
  const updates = req.body || {};

  try {
    if (!db) {
      return res.status(503).json({ success: false, message: "Database not initialized" });
    }

    const employeeRef = db.collection("employees").doc(userId);
    await employeeRef.update({
      ...updates,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    const snap = await employeeRef.get();
    return res.json({ success: true, employee: { id: userId, ...snap.data() } });
  } catch (err) {
    console.error("PATCH /employees error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// POST /logout - Log logout
app.post("/logout", (req, res) => {
  return res.json({ success: true, message: "Logged out" });
});

// GET /health - Health check
app.get("/health", (req, res) => {
  return res.json({ 
    success: true,
    status: "running",
    firestore: db ? "connected" : "disconnected",
    timestamp: new Date().toISOString()
  });
});

// Generic error handler
app.use((err, req, res, next) => {
  console.error("Server error:", err);
  res.status(500).json({ success: false, message: "Internal server error" });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✓ Server running on http://localhost:${PORT}`);
});
