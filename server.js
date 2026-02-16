require("dotenv").config();

const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const connectDB = require("./db");
const authRoutes = require("./authRoutes");
const protect = require("./authMiddleware");

const app = express();

/* ---------------- DATABASE ---------------- */
connectDB();

/* ---------------- SECURITY ---------------- */
app.use(helmet());

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 100
}));

/* ---------------- BODY PARSER FIX ---------------- */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* ---------------- COOKIES ---------------- */
app.use(cookieParser());

/* ---------------- ROUTES ---------------- */

// health check
app.get("/", (req, res) => {
  res.send("Cyber Auth API Live 🚀");
});

// auth routes
app.use("/api/auth", authRoutes);

// protected test route
app.get("/api/private", protect, (req, res) => {
  res.json({
    msg: "Welcome authenticated user",
    user: req.user
  });
});

/* ---------------- ERROR HANDLER ---------------- */
app.use((err, req, res, next) => {
  console.error("SERVER ERROR:", err);
  res.status(500).json({ msg: "Server error" });
});

/* ---------------- SERVER ---------------- */
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log("API running on port " + PORT);
});
