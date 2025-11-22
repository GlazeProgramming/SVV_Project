require("dotenv").config();
const express = require("express");
const cors = require("cors");
const db = require("./db"); // Import database connection
const registerRoute = require("./routes/register"); // Import registration route

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // For parsing form data

// Serve static files (HTML, CSS, JS)
app.use(express.static("public"));

// Test route
app.get("/", (req, res) => {
    res.send("Node.js backend is running!");
});

// Register route
app.use("/", registerRoute);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
	
	console.log(`\n🎉 Ready to sign up! Open this link in your browser:`);
    console.log(`   http://localhost:${PORT}/signup.html`);
    console.log(`\n`);

    const loginRoute = require("./routes/login");
    app.use("/", loginRoute);

});

const rateLimit = require("express-rate-limit");

// Define rate limiter for login route
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 login requests per `window` (15 mins)
    message: {
        success: false,
        message: "Too many login attempts. Please try again after 15 minutes."
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// Import login route if you have one
const loginRoute = require("./routes/login"); // your login route

// Apply rate limiter **only to login route**
app.use("/login", loginLimiter, loginRoute);
