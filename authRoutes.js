const router = require("express").Router();
const User = require("./User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

/* ---------------- TOKEN FUNCTIONS ---------------- */
const createAccess = (id) =>
  jwt.sign({ id }, process.env.JWT_ACCESS_SECRET, { expiresIn: "15m" });

const createRefresh = (id) =>
  jwt.sign({ id }, process.env.JWT_REFRESH_SECRET, { expiresIn: "7d" });

/* ---------------- REGISTER ---------------- */
router.post("/register", async (req, res) => {
  try {
    // SAFE BODY READ
    const { username, email, password } = req.body || {};

    // VALIDATION
    if (!username || !email || !password) {
      return res.status(400).json({ msg: "All fields required" });
    }

    const exist = await User.findOne({ email });
    if (exist) return res.status(400).json({ msg: "Email already exists" });

    const hash = await bcrypt.hash(password, 12);

    await User.create({
      username,
      email,
      password: hash
    });

    res.json({ msg: "Account created" });

  } catch (err) {
    console.error("REGISTER ERROR:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

/* ---------------- LOGIN ---------------- */
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password)
      return res.status(400).json({ msg: "Email & password required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ msg: "User not found" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ msg: "Wrong password" });

    const accessToken = createAccess(user._id);
    const refreshToken = createRefresh(user._id);

    user.refreshToken = refreshToken;
    await user.save();

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      sameSite: "strict",
      secure: false,
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({ accessToken });

  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ msg: "Server error" });
  }
});

/* ---------------- REFRESH ---------------- */
router.post("/refresh", async (req, res) => {
  try {
    const token = req.cookies.refreshToken;
    if (!token) return res.status(401).json({ msg: "No refresh token" });

    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.id);

    if (!user || user.refreshToken !== token)
      return res.status(403).json({ msg: "Invalid refresh token" });

    res.json({ accessToken: createAccess(user._id) });

  } catch {
    res.status(403).json({ msg: "Refresh expired" });
  }
});

/* ---------------- LOGOUT ---------------- */
router.post("/logout", async (req, res) => {
  try {
    const token = req.cookies.refreshToken;
    if (token) {
      const decoded = jwt.decode(token);
      if (decoded) await User.findByIdAndUpdate(decoded.id, { refreshToken: null });
    }

    res.clearCookie("refreshToken");
    res.json({ msg: "Logged out" });

  } catch {
    res.status(500).json({ msg: "Server error" });
  }
});

module.exports = router;
