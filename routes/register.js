const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const db = require("../db");

// POST /register - Handle user registration
router.post("/register", async (req, res) => {
    const { username, email, password, confirmPassword } = req.body;

    // Server-side validation
    if (!username || !email || !password || !confirmPassword) {
        return res.status(400).json({ 
            success: false, 
            message: "All fields are required" 
        });
    }

    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ 
            success: false, 
            message: "Invalid email format" 
        });
    }

    // Password match validation
    if (password !== confirmPassword) {
        return res.status(400).json({ 
            success: false, 
            message: "Passwords do not match" 
        });
    }

    // Password strength validation (optional but recommended)
    if (password.length < 6) {
        return res.status(400).json({ 
            success: false, 
            message: "Password must be at least 6 characters long" 
        });
    }

    try {
        // Check if email already exists
        const checkEmailQuery = "SELECT * FROM users WHERE email = ?";
        db.query(checkEmailQuery, [email], async (err, results) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).json({ 
                    success: false, 
                    message: "Server error occurred" 
                });
            }

            if (results.length > 0) {
                return res.status(409).json({ 
                    success: false, 
                    message: "Email already registered" 
                });
            }

            // Hash password
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            // Generate verification token
            const verificationToken = crypto.randomBytes(32).toString("hex");

            // Insert user into database
            const insertQuery = `
                INSERT INTO users (username, email, password_hash, verification_token, is_verified) 
                VALUES (?, ?, ?, ?, ?)
            `;
            
            db.query(
                insertQuery, 
                [username, email, hashedPassword, verificationToken, false], 
                (err, result) => {
                    if (err) {
                        console.error("Database insertion error:", err);
                        return res.status(500).json({ 
                            success: false, 
                            message: "Failed to create account" 
                        });
                    }

                    // Success response
                    res.status(201).json({
                        success: true,
                        message: "Account created successfully! Please verify your email.",
                        userId: result.insertId,
                        verificationToken: verificationToken // In production, send this via email
                    });
                }
            );
        });

    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).json({ 
            success: false, 
            message: "Server error occurred" 
        });
    }
});

module.exports = router;