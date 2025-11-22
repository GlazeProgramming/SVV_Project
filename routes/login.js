const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const db = require("../db");

router.post("/login", (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ success: false, message: "All fields are required" });
    }

    const sql = "SELECT * FROM users WHERE username = ?";
    db.query(sql, [username], async (err, results) => {
        if (err) return res.status(500).json({ success: false, message: "Database error" });
        if (results.length === 0) return res.status(404).json({ success: false, message: "User not found" });

        const user = results[0];
        const match = await bcrypt.compare(password, user.password_hash);

        if (!match) return res.status(401).json({ success: false, message: "Incorrect password" });

        if (!user.is_verified) return res.status(403).json({ success: false, message: "Account not activated" });

        res.json({ success: true, message: "Login successful" });
    });
});

module.exports = router;
