const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const db = require("../db");

// untuk email verif
const nodemailer = require("nodemailer");
const transporter_gmail = nodemailer.createTransport({
    port: 465,
    host: "smtp.gmail.com",
    secure: true,
    auth: {
        user: 'edwanotruyadika26@gmail.com',
        pass: 'lxfk nlhj umcy vuit',
    },
    tls: {
        rejectUnauthorized: false
    }
});


const KEY = crypto
.createHash('sha256')
.update(process.env.ENC_KEY || 'default_key')
.digest();

function deriveIV(text){
    return crypto.createHash('sha256')
    .update(process.env.SECRET_KEY + text)
    .digest()
    .subarray(0, 16);  // aes-cbc IV = 16 bytes
}

function encrypt(text){
    const iv = deriveIV(process.env.ENC_KEY);
    const cipher = crypto.createCipheriv('aes-256-cbc', KEY, iv);
    const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    return encrypted.toString('hex');
}

function decrypt(text){
    const iv = deriveIV(process.env.ENC_KEY);
    const encrypteddec = Buffer.from(text, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', KEY, iv);
    return (Buffer.concat([decipher.update(encrypteddec), decipher.final()])).toString();
}

router.get("/getdata", async (req, res) => {
    db.query(
        "SELECT id, firstname, lastname, DATE(dob) AS dob, phonenumber, username, email FROM users WHERE is_verified = 1",
        (err, result) => {
            if (err) {
                console.error("Database selection error:", err);
                return res.status(500).json({
                    success: false,
                    message: "Failed to get data"
                });
            } 

            return res.status(200).json(result);
        }
    );
});

router.post("/register", async (req, res) => {
    const { firstname, lastname, dob, phonenumber, username, email, password, confirmPassword, terms } = req.body;

    // Required fields
    if (!firstname || !dob || !phonenumber || !username || !email || !password || !confirmPassword) {
        return res.status(400).json({ 
            success: false, 
            message: "All fields are required except last name" 
        });
    }

    // Terms and Conditions agreement check
    if (!terms || (terms !== true && terms !== "true" && terms !== "on")) {
        return res.status(400).json({ 
            success: false, 
            message: "You must agree to the Terms & Conditions to register" 
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
        // Database Email Uniqueness Check - only check verified users
        const checkEmailQuery = "SELECT id FROM users WHERE email = ? AND is_verified = 1 LIMIT 1"; 
        
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

            // Check username uniqueness - only check verified users
            const checkUsernameQuery = "SELECT id FROM users WHERE username = ? AND is_verified = 1 LIMIT 1";

            db.query(checkUsernameQuery, [username], async (usernameErr, usernameResults) => {
                if (usernameErr) {
                    console.error("Database error:", usernameErr);
                    return res.status(500).json({ 
                        success: false, 
                        message: "Server error occurred" 
                    });
                }

                if (usernameResults.length > 0) {
                    return res.status(409).json({ 
                        success: false, 
                        message: "Username already taken" 
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

                // Store only minimal data (email, username, password, token) for verification
                // Sensitive data (firstname, lastname, phonenumber, dob) will be stored AFTER verification
                const saltRounds = 10;
                const hashedPassword = await bcrypt.hash(password, saltRounds);

                const verificationToken = crypto.randomBytes(32).toString("hex");
                const expiresAt = new Date(Date.now() + 1 * 60 * 1000);
                
                // Store sensitive data as JSON string in verification_token field temporarily
                // This allows us to retrieve it after verification without changing DB schema
                const pendingData = JSON.stringify({
                    firstname,
                    lastname,
                    dob,
                    phonenumber,
                    token: verificationToken
                });
                
                // Insert minimal data: use placeholder values for required NOT NULL fields
                // These will be updated with real values after email verification
                const insertQuery = `
                    INSERT INTO users (
                        firstname, lastname, dob, phonenumber, username, email, password_hash,
                        verification_token, token_expires_at, is_verified
                    ) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                `;
                
                // Store real data in verification_token as JSON, use placeholders for required fields
                db.query(
                    insertQuery, 
                    ['PENDING', '', '2000-01-01', '+00000000000', username, email, hashedPassword, pendingData, expiresAt],
                    (err, result) => {
                        if (err) {
                            console.error("Database insertion error:", err);
                            return res.status(500).json({ 
                                success: false, 
                                message: "Failed to create account" 
                            });
                        }
                        
                        // kirim email otp
                        var kalhtml = "<h3>OTP</h3>";
                        kalhtml = kalhtml + "<h1>Your Verification token is " + verificationToken + "<h1>"; 
                        const mailData = {
                            from: 'edwanotruyadika26@gmail.com',
                            to: email,
                            subject: 'Your OTP Code',
                            html: kalhtml
                        };
                        // transporter_gmail.sendMail(mailData, function (err, info) { });
                        transporter_gmail.sendMail(mailData, function (err, info) {
                            if (err) {
                                console.log("Error: ", err);
                            } else {
                                console.log("Sent: ", info);
                            }
                        });

                        res.status(201).json({
                            success: true,
                            message: "Registration successful! Please verify your email. Your account details will be saved after verification.",
                            verificationToken: verificationToken
                        });
                    }
                );
            });
        });

    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).json({ 
            success: false, 
            message: "Server error occurred" 
        });
    }
});


router.post("/activate", (req, res) => {
    const { username, token } = req.body;

    if (!username || !token) {
        return res.status(400).json({
            success: false,
            message: "Username and token are required"
        });
    }

    // Check for pending registration
    const sql = `
        SELECT id, is_verified, verification_token, token_expires_at
        FROM users 
        WHERE username = ? AND is_verified = 0
    `;

    db.query(sql, [username], (err, rows) => {
        if (err) {
            console.error("DB error during activation:", err);
            return res.status(500).json({
                success: false,
                message: "Database error"
            });
        }

        if (rows.length === 0) {
            return res.status(400).json({
                success: false,
                message: "Pending registration not found"
            });
        }

        const user = rows[0];

        // Parse the stored JSON data
        let pendingData;
        try {
            pendingData = JSON.parse(user.verification_token);
        } catch (parseErr) {
            console.error("Error parsing pending data:", parseErr);
            return res.status(500).json({
                success: false,
                message: "Invalid registration data"
            });
        }

        // Verify token matches
        if (pendingData.token !== token) {
            return res.status(400).json({
                success: false,
                message: "Invalid verification token"
            });
        }

        // Check if token expired
        if (!user.token_expires_at || new Date() > new Date(user.token_expires_at)) {
            const deleteSql = "DELETE FROM users WHERE id = ?";

            db.query(deleteSql, [user.id], (delErr) => {
                if (delErr) {
                    console.error("Error deleting expired user:", delErr);
                    return res.status(500).json({
                        success: false,
                        message: "Verification token has expired. Please try registering again later."
                    });
                }

                return res.status(400).json({
                    success: false,
                    message: "Verification token has expired. Please register again."
                });
            });

            return;
        }

        // NOW store the actual user details after successful verification
        const updateSql = `
            UPDATE users
            SET firstname = ?,
                lastname = ?,
                dob = ?,
                phonenumber = ?,
                is_verified = 1,
                verification_token = NULL,
                token_expires_at = NULL
            WHERE id = ?
        `;

        db.query(
            updateSql, 
            [pendingData.firstname, pendingData.lastname || null, pendingData.dob, pendingData.phonenumber, user.id],
            (updateErr) => {
                if (updateErr) {
                    console.error("Activation update error:", updateErr);
                    return res.status(500).json({
                        success: false,
                        message: "Failed to activate account"
                    });
                }

                return res.json({
                    success: true,
                    message: "Account activated successfully! Your details have been saved."
                });
            }
        );
    });
});

module.exports = router;