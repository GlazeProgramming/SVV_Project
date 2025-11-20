const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const db = require("../db");

router.post("/register", async (req, res) => {
    const { firstname, lastname, dob, phonenumber, username, email, password, confirmPassword } = req.body;

    // Required fields
    if (!firstname || !dob || !phonenumber || !username || !email || !password || !confirmPassword) {
        return res.status(400).json({ 
            success: false, 
            message: "All fields are required except last name" 
        });
    }

    // Firstname format & minimum length
    const nameRegex = /^[A-Za-z ]{3,}$/;
    if (!nameRegex.test(firstname)) {
        return res.status(400).json({
            success: false,
            message: "Firstname must be at least 3 letters (A–Z only)"
        });
    }

    // Phonenumber Format Validation
    const phoneRegex = /^\+[1-9]\d{1,14}$/;
    if (!phoneRegex.test(phonenumber)) {
        return res.status(400).json({ 
            success: false, 
            message: "Invalid phonenumber format" 
        });
    }
	
	// Email Format Validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ 
            success: false, 
            message: "Invalid email format" 
        });
    }
	
	// Password Match check
    if (password !== confirmPassword) {
        return res.status(400).json({ 
            success: false, 
            message: "Passwords do not match" 
        });
    }
    
    // Password length check
    if (password.length < 6) {
        return res.status(400).json({ 
            success: false, 
            message: "Password must be at least 6 characters long" 
        });
    }

    try {
        // Database Email Uniqueness Check
        const checkEmailQuery = "SELECT id FROM users WHERE email = ? LIMIT 1"; 
        
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

            // Combined Password Complexity Check
            // Requires: at least one lowercase, one uppercase, one digit, and one special character.
            const complexityRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{6,}$/;

            if (!complexityRegex.test(password)) {
                return res.status(400).json({ 
                    success: false, 
                    message: "Password must include an uppercase letter, a lowercase letter, a digit, and a special character." 
                });
            }

            // Insertion
            
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            const verificationToken = crypto.randomBytes(32).toString("hex");

            const insertQuery = `
                INSERT INTO users (username, email, password_hash, verification_token, is_verified) 
                VALUES (?, ?, ?, ?, ?)
            `;
            
            db.query(
                insertQuery, 
                [firstname, lastname, dob, phonenumber, username, email, hashedPassword, verificationToken, false], 
                (err, result) => {
                    if (err) {
                        console.error("Database insertion error:", err);
                        return res.status(500).json({ 
                            success: false, 
                            message: "Failed to create account" 
                        });
                    }

                    res.status(201).json({
                        success: true,
                        message: "Account created successfully! Please verify your email.",
                        userId: result.insertId,
                        verificationToken: verificationToken
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