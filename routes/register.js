const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const db = require("../db");
const rateLimit = require("express-rate-limit");

// for email verification
const nodemailer = require("nodemailer");
const transporter_gmail = nodemailer.createTransport({
    port: 465,
    host: "smtp.gmail.com",
    secure: true,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
    tls: {
        rejectUnauthorized: false
    }
});

// Rate limiter for registration
const registerLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 5, // Allow max 5 registration attempts per minute per IP
    message: {
        success: false,
        message: "Too many registration attempts. Please try again later."
    }
});

// Limit for /activate (OTP/token)
const activateLimiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 10, 
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: "Too many activation attempts from this IP. Please try again later."
    }
});

// Limit for endpoint getdata
const publicReadLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 60, // max 60 hit per minutes per IP
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: "Too many requests from this IP. Please slow down."
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

router.get("/getdata", publicReadLimiter, async (req, res) => {
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

function updatePendingUser(existingUserId, finalUsername, email, hashedPassword, verificationToken, pendingData, expiresAt, callback) {
    const updateQuery = `
        UPDATE users SET 
            firstname = 'PENDING',
            lastname = '',
            dob = '2000-01-01',
            phonenumber = '+00000000000',
            username = ?,
            email = ?,
            password_hash = ?,
            verification_token = ?,
            pending_data = ?,
            token_expires_at = ?,
            is_verified = 0,
            created_at = CURRENT_TIMESTAMP
        WHERE id = ?
    `;

    db.query(updateQuery,
        [finalUsername, email, hashedPassword, verificationToken, pendingData, expiresAt, existingUserId],
        (err, result) => {
        if (err) return callback(err);
        callback(null);
    });
}

function sendOtpAndRespond(res, email, verificationToken) {
    let kalhtml = "<h3>OTP</h3>";
    kalhtml += "<h1>Your Verification token is " + verificationToken + "<h1>"; 

    const mailData = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Your OTP Code',
        html: kalhtml
    };

    transporter_gmail.sendMail(mailData, function (err, info) {
        if (err) {
            console.log("Error: ", err);
        } else {
            console.log("Sent: ", info);
        }
    });

    return res.status(201).json({
        success: true,
        message: "Registration successful! Please verify your email. Your account details will be saved after verification.",
        verificationToken: verificationToken
    });
}

// This prevents code duplication in the main route
async function proceedToUsernameCheck(req, res, username, email, password, existingUserId = null)  {
    // Re-declare local variables needed in this scope
    const { firstname, lastname, dob, phonenumber } = req.body;
	
	// Username format validation
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
            message: "Username can only contain letters, numbers, and underscores, and must be at least 3 characters long."
        });
    }

    const finalUsername = trimmedUsername;
	
	const dobDate = new Date(dob);
	const today = new Date();
	const age = today.getFullYear() - dobDate.getFullYear() - 
	    (today.getMonth() < dobDate.getMonth() || 
	     (today.getMonth() === dobDate.getMonth() && today.getDate() < dobDate.getDate()) ? 1 : 0);

	if (age < 18) {
	    return res.status(400).json({ 
	        success: false, 
	        message: "You must be at least 18 years old to register." 
	    });
	}
	if (age > 100) {
	    return res.status(400).json({ 
	        success: false, 
	        message: "Invalid date of birth." 
	    });
	}
    
    // Check username uniqueness - only check verified users
    const checkUsernameQuery = "SELECT id FROM users WHERE username = ? AND is_verified = 1 LIMIT 1";

    db.query(checkUsernameQuery, [finalUsername], async (usernameErr, usernameResults) => {
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
        const complexityRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{6,}$/;

        if (!complexityRegex.test(password)) {
            return res.status(400).json({ 
                success: false, 
                message: "Password must include an uppercase letter, a lowercase letter, a digit, and a special character." 
            });
        }

        // Hashing and Insertion
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const verificationToken = crypto.randomBytes(32).toString("hex");
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000); 
        /*Best practices for email verification tokens:
          Minimum 10 minutes
          Generally 15–30 minutes
          Can take up to 1 hour for large applications
        */
        
        // Store sensitive data as JSON string in verification_token field temporarily
        const pendingData = JSON.stringify({
            firstname,
            lastname,
            dob,
            phonenumber,
            token: verificationToken
        });
        
        // If there is an existing User ID → UPDATE the old row
        if (existingUserId) {
            return updatePendingUser(
                existingUserId,
                finalUsername,
                email,
                hashedPassword,
                verificationToken,
                pendingData,
                expiresAt,
                (err) => {
                    if (err) {
                        console.error("UPDATE error:", err);
                        return res.status(500).json({
                            success: false,
                            message: "Failed to update existing pending registration"
                        });
                    }

                    // send email OTP
                    sendOtpAndRespond(res, email, verificationToken);
                }
            );
        }

        // If there is no existingUserId → INSERT new row
        const insertQuery = `
            INSERT INTO users (
                firstname, lastname, dob, phonenumber, username, email, password_hash,
                verification_token, pending_data, token_expires_at, is_verified
            ) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
        `;
        
        db.query(
            insertQuery, 
            ['PENDING', '', '2000-01-01', '+00000000000', finalUsername, email, hashedPassword, verificationToken, pendingData, expiresAt],
            (err, result) => {
                if (err) {
                    // Email duplicated (race condition prevented by UNIQUE constraint)
                    if (err.code === "ER_DUP_ENTRY") {
                        return res.status(409).json({
                            success: false,
                            message: "Email already registered. Please use another email."
                        });
                    }
                    
                    console.error("Database insertion error:", err);
                    return res.status(500).json({ 
                        success: false, 
                        message: "Failed to create account" 
                    });
                }
                
                // send email otp
                sendOtpAndRespond(res, email, verificationToken);
            }
        );
    });
}


router.post("/register", registerLimiter, async (req, res) => {
    const { firstname, lastname, dob, phonenumber, username, email, password, confirmPassword, terms } = req.body;

    // Required fields check
    if (!firstname || !dob || !phonenumber || !username || !email || !password || !confirmPassword) {
        return res.status(400).json({ 
            success: false, 
            message: "All fields are required except last name" 
        });
    }

    const MAX_USERNAME_LEN = 100;
    const MAX_NAME_LEN = 30; // Protection for verification_token field
	const MAX_PHONE_DIGITS = 20;
	const MAX_PHONE_FULL_LEN = 30; 
    const MAX_EMAIL_LEN = 255; 
    const MAX_PASSWORD_LEN = 128;

    if (username.length > MAX_USERNAME_LEN) {
        return res.status(400).json({ success: false, message: `Username cannot exceed ${MAX_USERNAME_LEN} characters.` });
    }

    if (firstname.length > MAX_NAME_LEN) {
        return res.status(400).json({ success: false, message: `Firstname cannot exceed ${MAX_NAME_LEN} characters.` });
    }
    
    // Lastname is optional, but still needs a length check if provided
    if (lastname && lastname.length > MAX_NAME_LEN) { 
        return res.status(400).json({ success: false, message: `Lastname cannot exceed ${MAX_NAME_LEN} characters.` });
    }

	if (phonenumber.length > MAX_PHONE_FULL_LEN) {
	        return res.status(400).json({ success: false, message: `The phone number is too long. The total length (code + local) cannot exceed ${MAX_PHONE_FULL_LEN} characters.` });
	    }

    if (email.length > MAX_EMAIL_LEN) {
        return res.status(400).json({ success: false, message: `Email cannot exceed ${MAX_EMAIL_LEN} characters.` });
    }

    // Password length check
    if (password.length > MAX_PASSWORD_LEN) {
        return res.status(400).json({ success: false, message: `Password cannot exceed ${MAX_PASSWORD_LEN} characters.` });
    }

    // Terms and Conditions agreement check
    if (!terms || (terms !== true && terms !== "true" && terms !== "on")) {
        return res.status(400).json({ 
            success: false, 
            message: "You must agree to the Terms & Conditions to register" 
        });
    }

    // Firstname format & minimum length
	const generalNameRegex = /^[A-Za-z ]+$/;

    // 1. Firstname: Check minimum length (3) AND format
    if (firstname.length < 3 || !generalNameRegex.test(firstname)) {
        return res.status(400).json({
            success: false,
            message: "Firstname must be at least 3 characters and can only contain letters and spaces."
        });
    }

    // 2. Lastname: Check format ONLY if provided
    if (lastname && !generalNameRegex.test(lastname)) {
         return res.status(400).json({
            success: false,
            message: "Lastname can only contain letters and spaces."
        });
    }

    // Phonenumber Format Validation
	const combinedPhoneRegex = /^\+\d{8,19}$/;
    if (!combinedPhoneRegex.test(phonenumber)) {
        return res.status(400).json({ 
            success: false, 
            message: "Invalid phone number format. Must start with '+' followed by 8 to 19 digits." 
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
    
    // Password length check (minimum)
    if (password.length < 6) {
        return res.status(400).json({ 
            success: false, 
            message: "Password must be at least 6 characters long" 
        });
    }

    try {
        // Step 1: Database Email Uniqueness Check (Check for ALL users, verified or not)
        const checkEmailQuery = "SELECT id, is_verified FROM users WHERE email = ? LIMIT 1"; 
        
        db.query(checkEmailQuery, [email], async (err, results) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).json({ 
                    success: false, 
                    message: "Server error occurred" 
                });
            }

            if (results.length > 0) {
                const existingUser = results[0];
                
                // Case A: Email belongs to an already verified user
                if (existingUser.is_verified === 1) {
                    return res.status(409).json({ 
                        success: false, 
                        message: "Email already registered and verified." 
                    });
                } 
                // Email exists but not verified 
                // then use UPDATE flow
                return proceedToUsernameCheck(req, res, username, email, password, existingUser.id);
                
                /*
                // Case B: Email belongs to an unverified user (delete old entry)
                else {
                    const deleteUnverifiedQuery = "DELETE FROM users WHERE id = ?";
                    db.query(deleteUnverifiedQuery, [existingUser.id], (deleteErr) => {
                        if (deleteErr) {
                            console.error("Database deletion error for unverified user:", deleteErr);
                            // Log the error but continue, as the deletion is not critical to stop registration
                        }
                        // Continue to username check and insertion after deleting the old row
                        proceedToUsernameCheck(req, res, username, email, password); 
                    });
                    return; // Stop current execution flow
                }
                */
            }

            // Case C: Email is not found in the database (proceed normally)
            proceedToUsernameCheck(req, res, username, email, password);
        });

    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).json({ 
            success: false, 
            message: "Server error occurred" 
        });
    }
});

router.post("/activate", activateLimiter, (req, res) => {
    const { username, token } = req.body;

    if (!username || !token) {
        return res.status(400).json({
            success: false,
            message: "Username and token are required"
        });
    }

    // Username validation (reuse same rule)
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
            message: "Invalid username format"
        });
    }

    // Token format validation (lebih bagus dicek dulu sebelum query DB)
    if (!/^[a-f0-9]{64}$/i.test(token)) {
        return res.status(400).json({
            success: false,
            message: "Invalid token format"
        });
    }

    // Check for pending registration
    const sql = `
        SELECT id, is_verified, verification_token, token_expires_at
        FROM users 
        WHERE username = ? AND is_verified = 0
    `;

    db.query(sql, [trimmedUsername], (err, rows) => {
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
            pendingData = JSON.parse(user.pending_data);
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