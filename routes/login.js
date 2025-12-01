const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const db = require("../db");
const rateLimit = require("express-rate-limit");

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // max 5 login attempts per 15 minutes per IP
    standardHeaders: true,   
    legacyHeaders: false,    
    message: {
        success: false,
        message: "Too many login attempts from this IP. Please try again later."
    }
});

router.post("/login", loginLimiter, (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ success: false, message: "All fields are required" });
    }

    const usernameRegex = /^[A-Za-z0-9_]+$/;
    const MAX_USERNAME_LEN = 100;
    if (typeof username !== "string") {
        return res.status(400).json({
            success: false,
            message: "Invalid username type"
        });
    }

    const trimmedUsername = username.trim();

    if (trimmedUsername.length < 3 || trimmedUsername.length > MAX_USERNAME_LEN || !usernameRegex.test(trimmedUsername)) {
        return res.status(400).json({
            success: false,
            message: "Invalid username or password" // not too detailed so that the information doesn't leak
        });
    }

    const sql = "SELECT * FROM users WHERE username = ?";
    db.query(sql, [trimmedUsername], async (err, results) => {
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
