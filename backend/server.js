import express from "express";
import pool from "./db-connection.js";
import bcrypt from "bcrypt";
import cors from "cors";
import crypto from "crypto";
import nodemailer from "nodemailer";
import dotenv from "dotenv";
import twilio from "twilio";

dotenv.config();

const app = express();

app.use(
  cors({
    origin: ["https://valleybalfour.dev", "http://localhost:5173"],
    credentials: true,
  }),
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const VoiceResponse = twilio.twiml.VoiceResponse;

const router = express.Router();

import fetch from "node-fetch";

export async function getAIResponse(prompt) {
  try {
    const model = "google/gemma-2-9b-instruct";
    const response = await fetch(
      `https://api-inference.huggingface.co/models/${model}`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${process.env.HF_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          inputs: prompt,
          parameters: { max_new_tokens: 150, temperature: 0.7 },
        }),
      },
    );

    const data = await response.json();
    if (Array.isArray(data) && data[0]?.generated_text) {
      return data[0].generated_text.trim();
    }

    console.error("HuggingFace unexpected response:", data);
    return "Sorry, I couldn’t generate a response.";
  } catch (err) {
    console.error("Error calling HuggingFace:", err);
    return "Sorry, I couldn’t generate a response.";
  }
}

router.post("/signup", async (req, res) => {
  const { email, password } = req.body;
  try {
    const [existing] = await pool.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);
    if (existing.length > 0)
      return res.status(400).json({ error: "Email already taken" });

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

router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await pool.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);
    if (rows.length === 0)
      return res.status(401).json({ error: "Invalid email or password" });

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(401).json({ error: "Invalid email or password" });

    res.status(200).json({ message: "Login successful", email });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

router.post("/forgot-password", async (req, res) => {
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
        auth: { user: process.env.EMAIL, pass: process.env.EMAIL_PASS },
      });

      const resetLink = `https://valleybalfour.dev/b4backend/reset-password?token=${token}`;

      await transporter.sendMail({
        to: email,
        subject: "Reset Your Password",
        html: `<p>Click to reset your password:</p><a href="${resetLink}">${resetLink}</a>`,
      });
    }
    res.json({ message: "If an account exists, a reset link has been sent." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/reset-password", async (req, res) => {
  const token = req.query.token;
  const { password, confirmPassword } = req.body;

  try {
    if (!password || !confirmPassword)
      return res.status(400).json({ error: "Missing fields" });

    if (password !== confirmPassword)
      return res.status(400).json({ error: "Passwords do not match" });

    const [rows] = await pool.query(
      "SELECT * FROM users WHERE reset_token = ?",
      [token],
    );
    if (rows.length === 0)
      return res.status(401).json({ error: "Token expired or does not exist" });

    const user = rows[0];

    if (Date.now() > user.reset_token_expiry)
      return res.status(401).json({ error: "Token expired" });

    const matchOld = await bcrypt.compare(password, user.password);
    if (matchOld)
      return res.status(400).json({
        error: "New password must be different from the current password",
      });

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      "UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE email = ?",
      [hashedPassword, user.email],
    );

    res.status(200).json({ message: "Password has been reset successfully" });
  } catch (err) {
    console.error("Forgot Password Error", err);
    res.status(500).json({ error: "Server error" });
  }
});

const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);

router.post("/call", async (req, res) => {
  const { email, goal, phoneNumber } = req.body;

  if (!email || !goal || !phoneNumber) {
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    const callId = crypto.randomBytes(8).toString("hex");

    const aiMessage = await getAIResponse(goal);

    await pool.query(
      "INSERT INTO conversations (call_id, email, message, sender) VALUES (?, ?, ?, ?)",
      [callId, email, goal, "user"],
    );
    await pool.query(
      "INSERT INTO conversations (call_id, email, message, sender) VALUES (?, ?, ?, ?)",
      [callId, email, aiMessage, "ai"],
    );

    const call = await client.calls.create({
      to: phoneNumber,
      from: process.env.TWILIO_PHONE_NUMBER,
      url: `https://valleybalfour.dev/b4backend/voice?call_id=${callId}`,
    });

    res.json({
      call_id: callId,
      twilioCallSid: call.sid,
    });
  } catch (err) {
    console.error("Error starting call:", err);
    res.status(500).json({ error: "Failed to start call" });
  }
});

router.post("/voice", async (req, res) => {
  const twiml = new VoiceResponse();
  const callId = req.query.call_id;

  if (!callId) {
    twiml.say("Error: call ID missing.");
    return res.type("text/xml").send(twiml.toString());
  }

  let aiMessage = "Hello! How can I help you today?";
  try {
    const [rows] = await pool.query(
      "SELECT message FROM conversations WHERE call_id = ? AND sender = 'ai' ORDER BY id DESC LIMIT 1",
      [callId],
    );
    if (rows.length > 0) aiMessage = rows[0].message;
  } catch (err) {
    console.error("DB error:", err);
  }

  const gather = twiml.gather({
    input: "speech",
    action: `/b4backend/process-speech?call_id=${callId}`,
    method: "POST",
  });

  gather.say(aiMessage);

  res.type("text/xml");
  res.send(twiml.toString());
});

router.post("/process-speech", async (req, res) => {
  const twiml = new VoiceResponse();
  const userSpeech = req.body.SpeechResult || "";
  const callId = req.query.call_id;

  if (!callId) {
    twiml.say("Error: call ID missing.");
    return res.type("text/xml").send(twiml.toString());
  }

  console.log("User said:", userSpeech);

  try {
    await pool.query(
      "INSERT INTO conversations (call_id, sender, message) VALUES (?, 'user', ?)",
      [callId, userSpeech],
    );

    const [conversationRows] = await pool.query(
      "SELECT sender, message FROM conversations WHERE call_id = ? ORDER BY id ASC",
      [callId],
    );

    let prompt = "";
    conversationRows.forEach((row) => {
      prompt += `${row.sender === "user" ? "User" : "AI"}: ${row.message}\n`;
    });
    prompt += "AI:";

    const aiResponse = await getAIResponse(prompt);

    await pool.query(
      "INSERT INTO conversations (call_id, sender, message) VALUES (?, 'ai', ?)",
      [callId, aiResponse],
    );

    twiml.say(aiResponse);

    const gather = twiml.gather({
      input: "speech",
      action: `/b4backend/process-speech?call_id=${callId}`,
      method: "POST",
    });

    res.type("text/xml");
    res.send(twiml.toString());
  } catch (err) {
    console.error("Error processing speech:", err);
    twiml.say("Sorry, something went wrong.");
    res.type("text/xml");
    res.send(twiml.toString());
  }
});

router.get("/", (req, res) => {
  res.setHeader("Content-Type", "text/html");
  res.send("<h1>Backend is running!</h1>");
});

app.use("/b4backend", router);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
