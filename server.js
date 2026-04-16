require("dotenv").config();
const express = require("express");
const mysql = require("mysql2/promise");
const session = require("express-session");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 5000;

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.use(
    session({
        secret: process.env.SESSION_SECRET || "change_this_in_production",
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            secure: false, // keep false for localhost
            maxAge: 1000 * 60 * 60 * 2
        }
    })
);

// ─── MySQL Connection Pool ────────────────────────────────────────────────────
const db = mysql.createPool({
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "",
    database: process.env.DB_NAME || "gstportal",
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// ─── Auth Middleware ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({ error: "Unauthorized" });
    }
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
        const hashedPassword = await bcrypt.hash(password, 12);

        await db.query(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            [name.trim(), email.toLowerCase().trim(), hashedPassword]
        );

        return res.redirect("/login.html");
    } catch (err) {
        if (err.code === "ER_DUP_ENTRY") {
            return res.status(409).json({ error: "Email already registered" });
        }
        console.error("Register error:", err);
        return res.status(500).json({ error: "Registration failed. Please try again." });
    }
});

// ─── Login ────────────────────────────────────────────────────────────────────
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required" });
    }

    try {
        const [rows] = await db.query(
            "SELECT * FROM users WHERE email = ?",
            [email.toLowerCase().trim()]
        );

        const user = rows[0];

        if (!user) {
            return res.status(401).json({ error: "Invalid email or password" });
        }

        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            return res.status(401).json({ error: "Invalid email or password" });
        }

        req.session.regenerate((err) => {
            if (err) {
                return res.status(500).json({ error: "Login failed" });
            }

            req.session.user = {
                id: user.id,
                name: user.name,
                email: user.email,
                is_admin: !!user.is_admin
            };

            return res.redirect("/dashboard.html");
        });
    } catch (err) {
        console.error("Login error:", err);
        return res.status(500).json({ error: "Login failed. Please try again." });
    }
});

// ─── Logout ───────────────────────────────────────────────────────────────────
app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.clearCookie("connect.sid");
        res.redirect("/");
    });
});

// ─── Session Check ────────────────────────────────────────────────────────────
app.get("/session-check", (req, res) => {
    if (req.session.user) {
        return res.json({
            authenticated: true,
            id: req.session.user.id,
            name: req.session.user.name,
            email: req.session.user.email,
            is_admin: req.session.user.is_admin
        });
    }

    return res.json({ authenticated: false });
});

// ─── GST Calculation ──────────────────────────────────────────────────────────
app.post("/calculate", requireAuth, async (req, res) => {
    const { gst_number, income, gst_rate } = req.body;

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

        return res.redirect("/dashboard.html");
    } catch (err) {
        console.error("Calculate error:", err);
        return res.status(500).json({ error: "Failed to save GST record" });
    }
});

// ─── Dashboard Data ───────────────────────────────────────────────────────────
app.get("/dashboard-data", requireAuth, async (req, res) => {
    try {
        const [summaryRows] = await db.query(
            `
            SELECT
                COALESCE(SUM(income), 0) AS total_income,
                COALESCE(SUM(gst_amount), 0) AS total_gst,
                COUNT(*) AS total_returns
            FROM gst_records
            WHERE user_id = ?
            `,
            [req.session.user.id]
        );

        const [recordRows] = await db.query(
            `
            SELECT id, gst_number, income, gst_amount, created_at
            FROM gst_records
            WHERE user_id = ?
            ORDER BY created_at DESC
            `,
            [req.session.user.id]
        );

        return res.json({
            summary: {
                total_income: parseFloat(summaryRows[0].total_income || 0),
                total_gst: parseFloat(summaryRows[0].total_gst || 0),
                total_returns: parseInt(summaryRows[0].total_returns || 0)
            },
            records: recordRows
        });
    } catch (err) {
        console.error("Dashboard data error:", err);
        return res.status(500).json({ error: "Failed to load dashboard data" });
    }
});

// ─── Admin Data ───────────────────────────────────────────────────────────────
app.get("/admin-data", requireAdmin, async (req, res) => {
    try {
        const [rows] = await db.query(
            `
            SELECT
                gst_records.id,
                users.name,
                users.email,
                gst_records.gst_number,
                gst_records.income,
                gst_records.gst_amount,
                gst_records.created_at
            FROM gst_records
            INNER JOIN users ON gst_records.user_id = users.id
            ORDER BY gst_records.created_at DESC
            `
        );

        return res.json(rows);
    } catch (err) {
        console.error("Admin data error:", err);
        return res.status(500).json({ error: "Failed to load admin data" });
    }
});

// ─── Optional Health Check ────────────────────────────────────────────────────
app.get("/health", async (req, res) => {
    try {
        await db.query("SELECT 1");
        return res.json({ status: "ok", database: "connected" });
    } catch (err) {
        console.error("Health check error:", err);
        return res.status(500).json({ status: "error", database: "disconnected" });
    }
});

// ─── Start Server ─────────────────────────────────────────────────────────────
app.listen(PORT, "0.0.0.0", async () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);

    try {
        await db.query("SELECT 1");
        console.log("✅ MySQL database connected successfully");
    } catch (err) {
        console.error("❌ MySQL database connection failed:", err.message);
    }
});
