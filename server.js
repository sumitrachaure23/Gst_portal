require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const session = require("express-session");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.use(session({
    secret: process.env.SESSION_SECRET || "change_this_in_production",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,      // Prevents JS access to cookie (XSS protection)
        secure: process.env.NODE_ENV === "production", // HTTPS only in prod
        maxAge: 1000 * 60 * 60 * 2  // 2 hour session expiry
    }
}));

// ─── MySQL Connection Pool ────────────────────────────────────────────────────
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
}).promise(); // Use promise-based API for cleaner async/await

// ─── Auth Middleware ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
    if (!req.session.user) return res.status(401).json({ error: "Unauthorized" });
    next();
}

function requireAdmin(req, res, next) {
    if (!req.session.user || !req.session.user.is_admin) {
        return res.status(403).json({ error: "Forbidden" });
    }
    next();
}

// ─── Home ─────────────────────────────────────────────────────────────────────
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ─── Register ─────────────────────────────────────────────────────────────────
app.post("/register", async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ error: "All fields are required" });
    }

    if (password.length < 8) {
        return res.status(400).json({ error: "Password must be at least 8 characters" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 12); // 12 rounds (was 10)

        await db.query(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            [name, email.toLowerCase().trim(), hashedPassword]
        );

        res.redirect("/login.html");
    } catch (err) {
        if (err.code === "ER_DUP_ENTRY") {
            return res.status(409).json({ error: "Email already registered" });
        }
        console.error("Register error:", err);
        res.status(500).json({ error: "Registration failed. Please try again." });
    }
});

// ─── Login ────────────────────────────────────────────────────────────────────
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required" });
    }

    try {
        const [results] = await db.query(
            "SELECT * FROM users WHERE email = ?",
            [email.toLowerCase().trim()]
        );

        // Always run bcrypt compare to prevent timing attacks
        const dummyHash = "$2b$12$invalidhashfortimingattackprevention00000000000000000";
        const user = results[0];
        const hashToCompare = user ? user.password : dummyHash;

        const match = await bcrypt.compare(password, hashToCompare);

        if (!user || !match) {
            return res.status(401).json({ error: "Invalid email or password" });
        }

        // Regenerate session on login to prevent session fixation
        req.session.regenerate((err) => {
            if (err) return res.status(500).json({ error: "Login failed" });
            req.session.user = {
                id: user.id,
                name: user.name,
                email: user.email,
                is_admin: user.is_admin || false
            };
            res.redirect("/dashboard.html");
        });
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ error: "Login failed. Please try again." });
    }
});

// ─── Logout ───────────────────────────────────────────────────────────────────
app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.clearCookie("connect.sid");
        res.redirect("/");
    });
});

// ─── GST Calculation ─────────────────────────────────────────────────────────
app.post("/calculate", requireAuth, async (req, res) => {
    const { gst_number, income, gst_rate } = req.body;

    // Validate GST number format (basic Indian GSTIN: 15 chars)
    const gstinRegex = /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$/;
    if (!gstinRegex.test(gst_number)) {
        return res.status(400).json({ error: "Invalid GSTIN format" });
    }

    const incomeVal = parseFloat(income);
    const rateVal = parseFloat(gst_rate);
    const validRates = [0.05, 0.12, 0.18, 0.28];

    if (isNaN(incomeVal) || incomeVal <= 0) {
        return res.status(400).json({ error: "Income must be a positive number" });
    }

    if (!validRates.includes(rateVal)) {
        return res.status(400).json({ error: "Invalid GST rate" });
    }

    const gstAmount = parseFloat((incomeVal * rateVal).toFixed(2));

    try {
        await db.query(
            "INSERT INTO gst_records (user_id, gst_number, income, gst_amount) VALUES (?, ?, ?, ?)",
            [req.session.user.id, gst_number, incomeVal, gstAmount]
        );
        res.redirect("/dashboard.html");
    } catch (err) {
        console.error("Calculate error:", err);
        res.status(500).json({ error: "Failed to save GST record" });
    }
});

// ─── Dashboard Data ───────────────────────────────────────────────────────────
app.get("/dashboard-data", requireAuth, async (req, res) => {
    try {
        const [summary] = await db.query(
            `SELECT
                IFNULL(SUM(income), 0)     AS total_income,
                IFNULL(SUM(gst_amount), 0) AS total_gst,
                COUNT(*)                   AS total_returns
             FROM gst_records
             WHERE user_id = ?`,
            [req.session.user.id]
        );

        const [records] = await db.query(
            `SELECT id, gst_number, income, gst_amount, created_at
             FROM gst_records
             WHERE user_id = ?
             ORDER BY created_at DESC
             LIMIT 10`,
            [req.session.user.id]
        );

        res.json({ ...summary[0], records, user: req.session.user.name });
    } catch (err) {
        console.error("Dashboard data error:", err);
        res.status(500).json({ error: "Failed to fetch dashboard data" });
    }
});

// ─── Admin Data (protected) ───────────────────────────────────────────────────
app.get("/admin-data", requireAdmin, async (req, res) => {
    try {
        const [results] = await db.query(
            `SELECT
                users.name,
                users.email,
                gst_records.gst_number,
                gst_records.income,
                gst_records.gst_amount,
                gst_records.created_at
             FROM gst_records
             JOIN users ON users.id = gst_records.user_id
             ORDER BY gst_records.created_at DESC`
        );
        res.json(results);
    } catch (err) {
        console.error("Admin data error:", err);
        res.status(500).json({ error: "Failed to fetch admin data" });
    }
});

// ─── Session Check (for frontend auth guards) ─────────────────────────────────
app.get("/session-check", (req, res) => {
    if (req.session.user) {
        res.json({ authenticated: true, name: req.session.user.name, is_admin: req.session.user.is_admin });
    } else {
        res.json({ authenticated: false });
    }
});

// ─── Server ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
