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
  const url = "https://api.openai.com/v1/chat/completions";

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
      },
      body: JSON.stringify({
        model: "gpt-3.5-turbo",
        messages: [
          { role: "system", content: "You are a helpful AI voice assistant." },
          { role: "user", content: prompt },
        ],
        temperature: 0.7,
      }),
      signal: controller.signal,
    });

    clearTimeout(timeout);

    const text = await response.text();

    if (!response.ok) {
      switch (response.status) {
        case 401:
          return "AI Error: Invalid OpenAI API key.";
        case 429:
          return "AI Error: Rate limit exceeded. Try again shortly.";
        case 500:
        case 502:
        case 503:
          return "AI Error: OpenAI servers are having issues.";
        default:
          return `AI Error (${response.status}): ${text.substring(0, 200)}`;
      }
    }

    let data;
    try {
      data = JSON.parse(text);
    } catch {
      return "AI Error: Invalid JSON from OpenAI.";
    }

    const aiMessage = data?.choices?.[0]?.message?.content;
    return aiMessage ? aiMessage.trim() : "AI Error: No response from OpenAI.";
  } catch (err) {
    if (err.name === "AbortError") return "AI Error: Request timed out.";
    return `AI Error: ${err.message}`;
  }
}

function escapeHtml(text) {
  if (!text) return "";
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
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

    const match = await bcrypt.compare(password, rows[0].password);
    if (!match)
      return res.status(401).json({ error: "Invalid email or password" });

    res.status(200).json({ message: "Login successful", email });
  } catch {
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
      url: `https://valleybalfour.dev/b4backend/voice?call_id=${callId}`,
    });

    res.json({ call_id: callId, twilioCallSid: call.sid });
  } catch (err) {
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
  } catch {}

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
    twiml.gather({
      input: "speech",
      action: `/b4backend/process-speech?call_id=${callId}`,
      method: "POST",
    });

    res.type("text/xml");
    res.send(twiml.toString());
  } catch {
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
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

router.get("/ai-response", async (req, res) => {
  const { prompt } = req.query;
  if (!prompt)
    return res.status(400).json({ error: "Missing prompt parameter." });

  try {
    const aiResponse = await getAIResponse(prompt);
    res.json({
      prompt,
      response: aiResponse,
      timestamp: new Date().toISOString(),
      status: "success",
    });
  } catch (err) {
    res
      .status(500)
      .json({
        error: "Failed to get AI response",
        details: err.message,
        timestamp: new Date().toISOString(),
      });
  }
});

router.get("/ai-response/html", async (req, res) => {
  const { prompt } = req.query;

  if (!prompt) {
    return res.send(`
      <!DOCTYPE html><html><head><title>AI Response Tester</title></head>
      <body>
        <form method="get" action="/b4backend/ai-response/html">
          <input type="text" name="prompt" required>
          <button type="submit">Get AI Response</button>
        </form>
      </body></html>
    `);
  }

  try {
    const aiResponse = await getAIResponse(prompt);
    res.send(`
      <!DOCTYPE html><html><head><title>AI Response</title></head>
      <body>
        <div>Prompt: ${escapeHtml(prompt)}</div>
        <div>Response: ${escapeHtml(aiResponse)}</div>
        <div>Generated: ${new Date().toISOString()}</div>
      </body></html>
    `);
  } catch (err) {
    res.send(`
      <!DOCTYPE html><html><head><title>Error</title></head>
      <body>
        <div>Error: ${escapeHtml(err.message)}</div>
      </body></html>
    `);
  }
});

app.use("/b4backend", router);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
