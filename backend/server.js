import express from "express";
import pool from "./db-connection.js";
import bcrypt from "bcrypt";
import cors from "cors";
import dotenv from "dotenv";
import twilio from "twilio";
import fetch from "node-fetch";
import jwt from "jsonwebtoken";
import xss from "xss";
import helmet from "helmet";
import crypto from "crypto";
import nodemailer from "nodemailer";

dotenv.config();

const app = express();

app.use(helmet());

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

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  jwt.verify(
    token,
    process.env.JWT_SECRET,
    {
      issuer: "b4-phone-agent",
      audience: "users",
    },
    (err, user) => {
      if (err) {
        return res.status(403).json({ error: "Invalid or expired token." });
      }
      req.user = user;
      next();
    },
  );
};

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
  let { email, password } = req.body;

  email = xss(email).trim();

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Invalid email format" });
  }

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
  let { email, password } = req.body;

  email = xss(email).trim();

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Invalid email format" });
  }

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

    const token = jwt.sign(
      { email: user.email, admin: user.admin },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
        issuer: "b4-phone-agent",
        audience: "users",
      },
    );

    res.status(200).json({ message: "Login successful", email, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

router.post("/call", authenticateToken, async (req, res) => {
  let { goal, phoneNumber } = req.body;

  goal = xss(goal).trim();
  phoneNumber = xss(phoneNumber).trim();

  const email = req.user.email;

  if (!goal || !phoneNumber)
    return res.status(400).json({ error: "Missing fields" });

  try {
    await pool.query("UPDATE users SET api_calls = COALESCE(api_calls, 0) + 1 WHERE email = ?", [email]);
    const [userRows] = await pool.query("SELECT api_calls FROM users WHERE email = ?", [email]);
    const totalCalls = userRows[0].api_calls;

    let warningMessage = null;
    if (totalCalls > 20) {
      warningMessage = "Limit Reached: You have consumed your 20 free API calls. Additional charges may apply.";
    }

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

      const resetLink = `http://localhost:5173/reset-password?token=${token}`;

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

router.get("/api-usage", authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT api_calls FROM users WHERE email = ?",
      [req.user.email],
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const used = rows[0].api_calls || 0;
    const limit = 20;
    const remaining = Math.max(limit - used, 0);

    res.json({
      used,
      limit,
      remaining,
    });
  } catch (err) {
    console.error("API USAGE ERROR:", err);
    res.status(500).json({ error: "Server error" });
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
  let userSpeech = req.body.SpeechResult || "";
  userSpeech = xss(userSpeech);

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

router.get("/my-dashboard", authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT email, api_calls, admin FROM users WHERE email = ?", [req.user.email]);

    if (rows.length > 0) {
      res.json({ 
        email: rows[0].email, 
        api_calls: rows[0].api_calls, 
        is_admin: rows[0].admin
      });
    } else {
      res.status(404).json({ error: "User not found" });
    }

  } catch (err) {
    console.error("DASHBOARD CRASH:", err);
    res.status(500).json({ error: "Server error" });
  }
});

router.get("/admin/usage", authenticateToken, async (req, res) => {
  if (!req.user.admin) return res.status(403).json({ error: "Admin access required." });

  try {
    const [rows] = await pool.query("SELECT id, email, api_calls, admin FROM users ORDER BY api_calls DESC");
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.use("", router);
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
