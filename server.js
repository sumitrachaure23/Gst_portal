const express = require("express");
const mysql = require("mysql2");
const session = require("express-session");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use(session({
    secret: "gstsecret",
    resave: false,
    saveUninitialized: false
}));

// MySQL Connection Pool
const db = mysql.createPool({
    host: "localhost",
    user: "root",
    password: "root123",
    database: "gst_portal"
});

// ================= HOME =================
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ================= REGISTER =================
app.post("/register", async (req, res) => {
    const { name, email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    db.query(
        "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
        [name, email, hashedPassword],
        (err) => {
            if (err) return res.send("User already exists");
            res.redirect("/login.html");
        }
    );
});

// ================= LOGIN =================
app.post("/login", (req, res) => {
    const { email, password } = req.body;

    db.query("SELECT * FROM users WHERE email=?", [email], async (err, results) => {

        if (results.length > 0) {
            const match = await bcrypt.compare(password, results[0].password);

            if (match) {
                req.session.user = results[0];
                return res.redirect("/dashboard.html");
            }
        }

        res.send("Invalid Login");
    });
});

// ================= LOGOUT =================
app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

// ================= GST CALCULATION =================
app.post("/calculate", (req, res) => {

    if (!req.session.user) return res.redirect("/login.html");

    const { gst_number, income, gst_rate } = req.body;

    const gstAmount = parseFloat(income) * parseFloat(gst_rate);

    db.query(
        "INSERT INTO gst_records (user_id, gst_number, income, gst_amount) VALUES (?, ?, ?, ?)",
        [req.session.user.id, gst_number, income, gstAmount],
        (err) => {
            if (err) return res.send("Error saving data");

            res.redirect("/dashboard.html");
        }
    );
});

// ================= DASHBOARD DATA =================
app.get("/dashboard-data", (req, res) => {

    if (!req.session.user) return res.json({});

    db.query(
        `SELECT 
            IFNULL(SUM(income),0) AS total_income,
            IFNULL(SUM(gst_amount),0) AS total_gst,
            COUNT(*) AS total_returns
         FROM gst_records
         WHERE user_id=?`,
        [req.session.user.id],
        (err, result) => {
            res.json(result[0]);
        }
    );
});

// ================= ADMIN DATA =================
app.get("/admin-data", (req, res) => {

    db.query(
        `SELECT users.name, gst_records.gst_number,
                gst_records.income, gst_records.gst_amount
         FROM gst_records
         JOIN users ON users.id = gst_records.user_id`,
        (err, results) => {
            res.json(results);
        }
    );
});

// ================= SERVER =================
app.listen(3000, () => {
    console.log("Server running on http://localhost:3000");
});