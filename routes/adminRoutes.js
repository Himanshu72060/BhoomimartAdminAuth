const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Admin = require("../models/Admin");

const router = express.Router();

// ✅ Signup
router.post("/signup", async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const existingAdmin = await Admin.findOne({ email });
        if (existingAdmin) return res.status(400).json({ message: "Email already exists" });

        const hashedPassword = await bcrypt.hash(password, 10);
        const admin = new Admin({ name, email, password: hashedPassword });
        await admin.save();
        res.status(201).json({ message: "Admin registered successfully" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ✅ Login
router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const admin = await Admin.findOne({ email });
        if (!admin) return res.status(400).json({ message: "Invalid email or password" });

        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) return res.status(400).json({ message: "Invalid email or password" });

        const token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET, { expiresIn: "1d" });
        res.json({ token, admin: { id: admin._id, name: admin.name, email: admin.email } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ✅ Middleware to verify token
const auth = (req, res, next) => {
    const token = req.headers["authorization"];
    if (!token) return res.status(401).json({ message: "No token provided" });

    jwt.verify(token.split(" ")[1], process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ message: "Invalid token" });
        req.adminId = decoded.id;
        next();
    });
};

// ✅ Get all admins
router.get("/", auth, async (req, res) => {
    const admins = await Admin.find().select("-password");
    res.json(admins);
});

// ✅ Get single admin
router.get("/:id", auth, async (req, res) => {
    const admin = await Admin.findById(req.params.id).select("-password");
    if (!admin) return res.status(404).json({ message: "Admin not found" });
    res.json(admin);
});

// ✅ Update admin
router.put("/:id", auth, async (req, res) => {
    const { name, email, password } = req.body;
    let updateData = { name, email };
    if (password) updateData.password = await bcrypt.hash(password, 10);

    const updatedAdmin = await Admin.findByIdAndUpdate(req.params.id, updateData, { new: true }).select("-password");
    res.json(updatedAdmin);
});

// ✅ Delete admin
router.delete("/:id", auth, async (req, res) => {
    await Admin.findByIdAndDelete(req.params.id);
    res.json({ message: "Admin deleted" });
});

module.exports = router;
