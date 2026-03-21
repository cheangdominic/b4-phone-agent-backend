import express from "express";
import pool from "./db-connection.js";
import bcrypt from "bcrypt";
import cors from "cors";
import crypto from "crypto";
import nodemailer from "nodemailer";

const app = express();

app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  }),
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.post("/signup", async (req, res) => {
  const { email, password } = req.body;

  try {
    const [existing] = await pool.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);

    if (existing.length > 0) {
      return res.status(400).json({ error: "email already taken" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO users (email, password, admin) VALUES (?, ?, ?)",
      [email, hashedPassword, false],
    );

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await pool.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);

    if (rows.length === 0) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    res.status(200).json({ message: "Login successful", email });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;

  try {
    const [rows] = await pool.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);

    if (rows.length > 0) {
      const token = crypto.randomBytes(32).toString("hex");
      const expiry = Date.now() + 1000 * 60 * 15;

      await pool.query(
        "UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?",
        [token, expiry, email],
      );

      const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: process.env.EMAIL,
          pass: process.env.EMAIL_PASS,
        },
      });

      const resetLink = `http://localhost:5173/reset-password?token=${token}`;

      await transporter.sendMail({
        to: email,
        subject: "Reset Your Password",
        html: `<p>Click to reset your password:</p><a href="${resetLink}">${resetLink}</a>`,
      });
    }

    res.json({
      message: "If an account exists, a reset link has been sent.",
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/reset-password", async (req, res) => {
  const token = req.query.token;
  const { password, confirmPassword } = req.body;

  try {
    if (!password || !confirmPassword) {
      return res.status(400).json({ error: "Missing fields" });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ error: "Passwords do not match" });
    }

    const [rows] = await pool.query(
      "SELECT * FROM users WHERE reset_token = ?",
      [token],
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: "Token expired or does not exist" });
    }

    const user = rows[0];

    if (Date.now() > user.reset_token_expiry) {
      return res.status(401).json({ error: "Token expired" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const matchOld = await bcrypt.compare(password, user.password);

    if (matchOld) {
      return res.status(400).json({
        error: "New password must be different from the current password",
      });
    }

    await pool.query(
      "UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE email = ?",
      [hashedPassword, user.email],
    );
    res.status(200).json({ message: "Password has been reset successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/verify-token", async (req, res) => {
  const token = req.query.token;

  const [rows] = await pool.query("SELECT * FROM users WHERE reset_token = ?", [
    token,
  ]);

  if (rows.length === 0) {
    return res.json({ valid: false });
  }

  const user = rows[0];
  if (Date.now() > user.reset_token_expiry) {
    return res.json({ valid: false });
  }

  res.json({ valid: true });
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
