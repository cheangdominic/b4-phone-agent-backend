import express from "express";
import pool from "./db-connection.js";
import bcrypt from "bcrypt";
import cors from "cors";
import crypto from "crypto";
import nodemailer from "nodemailer";
import dotenv from "dotenv";
import twilio from "twilio";
import fetch from "node-fetch";

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
const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);

async function getAIResponse(prompt) {
  try {
    const response = await fetch(
      "https://router.huggingface.co/v1/chat/completions",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${process.env.HF_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: "gpt2",
          messages: [
            { role: "system", content: "You are a helpful AI." },
            { role: "user", content: prompt },
          ],
          max_tokens: 100,
          temperature: 0.7,
        }),
      },
    );

    const data = await response.json();
    console.log("HF CHAT RESPONSE:", data);

    return data.choices?.[0]?.message?.content || "No response.";
  } catch (err) {
    console.error("HF ERROR:", err);
    return "AI service error.";
  }
}

const router = express.Router();

router.get("/", (req, res) => {
  res.type("text/html");
  res.send("<h1>Backend is running!</h1>");
});

router.post("/signup", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: "Missing fields" });

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
  if (!email || !password)
    return res.status(400).json({ error: "Missing fields" });

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

router.post("/call", async (req, res) => {
  const { email, goal, phoneNumber } = req.body;

  if (!email || !goal || !phoneNumber)
    return res.status(400).json({ error: "Missing fields" });

  try {
    const [result] = await pool.query("INSERT INTO calls (email) VALUES (?)", [
      email,
    ]);
    const callId = result.insertId;

    const aiMessage = await getAIResponse(goal);

    await pool.query(
      "INSERT INTO conversations (call_id, sender, message) VALUES (?, ?, ?), (?, ?, ?)",
      [callId, "user", goal, callId, "ai", aiMessage],
    );

    const call = await client.calls.create({
      to: phoneNumber,
      from: process.env.TWILIO_PHONE_NUMBER,
      url: `https://valleybalfour.dev/voice?call_id=${callId}`,
    });

    res.json({ call_id: callId, twilioCallSid: call.sid });
  } catch (err) {
    console.error("FULL ERROR:", err);
    res.status(500).json({ error: err.message });
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
    console.error(err);
  }

  const gather = twiml.gather({
    input: "speech",
    action: `/process-speech?call_id=${callId}`,
    method: "POST",
  });
  gather.say(aiMessage);

  res.type("text/xml");
  res.send(twiml.toString());
});

router.post("/process-speech", async (req, res) => {
  const twiml = new VoiceResponse();
  const callId = req.query.call_id;
  const userSpeech = req.body.SpeechResult || "";

  if (!callId) {
    twiml.say("Error: call ID missing.");
    return res.type("text/xml").send(twiml.toString());
  }

  try {
    await pool.query(
      "INSERT INTO conversations (call_id, sender, message) VALUES (?, ?, ?)",
      [callId, "user", userSpeech],
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
      "INSERT INTO conversations (call_id, sender, message) VALUES (?, ?, ?)",
      [callId, "ai", aiResponse],
    );

    twiml.say(aiResponse);
    const gather = twiml.gather({
      input: "speech",
      action: `/process-speech?call_id=${callId}`,
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

router.get("/is-admin", async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: "Email is required" });

  try {
    const [rows] = await pool.query("SELECT admin FROM users WHERE email = ?", [
      email,
    ]);
    if (rows.length === 0)
      return res.status(404).json({ error: "User not found" });

    res.json({ admin: !!rows[0].admin });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

app.use("", router);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
