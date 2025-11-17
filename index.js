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
});