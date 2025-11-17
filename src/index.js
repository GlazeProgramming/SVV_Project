require("dotenv").config();
const express = require("express");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

// Test route
app.get("/", (req, res) => {
    res.send("Node.js backend is running!");
});

app.listen(process.env.PORT || 3000, () => {
    console.log("Server running on port " + process.env.PORT);
});
