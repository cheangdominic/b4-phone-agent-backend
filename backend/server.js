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
import Groq from "groq-sdk";

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

const groq = new Groq({
  apiKey: process.env.GROQ_API_KEY,
});

async function getAIResponse(messages) {
  try {
    const completion = await groq.chat.completions.create({
      model: "llama-3.3-70b-versatile",
      messages: messages,
      temperature: 0.8,
      max_tokens: 100,
    });

    const aiMessage = completion.choices?.[0]?.message?.content;
    return aiMessage ? aiMessage.trim() : "AI Error: No response from Groq.";
  } catch (err) {
    if (err.status === 401) return "AI Error: Invalid Groq API key.";
    if (err.status === 429) return "AI Error: Rate limit exceeded.";
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
    await pool.query(
      "UPDATE users SET api_calls = COALESCE(api_calls, 0) + 1 WHERE email = ?",
      [email],
    );
    const [userRows] = await pool.query(
      "SELECT api_calls FROM users WHERE email = ?",
      [email],
    );
    const totalCalls = userRows[0].api_calls;

    let warningMessage = null;
    if (totalCalls > 20) {
      warningMessage =
        "Limit Reached: You have consumed your 20 free API calls. Additional charges may apply.";
    }

    const [result] = await pool.query("INSERT INTO calls (email) VALUES (?)", [
      email,
    ]);
    const callId = result.insertId;

    const messages = [
      {
        role: "system",
        content: `You are an AI-powered outbound phone assistant.

CRITICAL RULES FOR VOICE:

- Speak in short, natural responses (1–2 sentences, occasionally 3 max)
- Keep things conversational, not robotic
- Do NOT ramble or give long speeches
- Sound like a real human on a phone call

CONVERSATION STYLE:

- It’s okay to briefly explain something if needed
- Not every response needs to be a question
- Mix between:
  - short statements
  - light explanations
  - occasional questions

- Questions should feel natural, not forced

BAD:
"Do you do marketing? What tools? What budget?"

GOOD:
"Got it — a lot of people I talk to are handling that manually right now.  
Curious, are you doing that yourself or with a team?"

FLOW:

1. Start casual
2. Add context naturally
3. Guide the conversation (not interrogate)
4. Keep it low-pressure

TONE:

- Friendly
- Calm
- Slightly persuasive
- Never dramatic or intense

IMPORTANT:

- Avoid sounding scripted
- Avoid asking too many questions in a row
- Let the conversation breathe

This is a LIVE PHONE CALL.`,
      },
      { role: "user", content: goal },
    ];

    const aiMessage = await getAIResponse(messages);

    await pool.query(
      "INSERT INTO conversations (call_id, sender, message) VALUES (?, ?, ?), (?, ?, ?)",
      [callId, "user", goal, callId, "ai", aiMessage],
    );

    const call = await client.calls.create({
      to: phoneNumber,
      from: process.env.TWILIO_PHONE_NUMBER,
      url: `http://localhost:5173/voice?call_id=${callId}`,
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

  const endPhrases = ["goodbye", "talk to you later", "bye", "have a nice day"];
  const isEnding = endPhrases.some((phrase) =>
    aiMessage.toLowerCase().includes(phrase),
  );

  if (isEnding) {
    twiml.say({ voice: "Polly.Amy" }, aiMessage);
    twiml.hangup();
  } else {
    const gather = twiml.gather({
      input: "speech",
      action: `/b4backend/process-speech?call_id=${callId}`,
      method: "POST",
      timeout: 8,
      speechTimeout: "auto",
    });
    gather.say({ voice: "Polly.Amy" }, aiMessage);
    twiml.redirect(`/b4backend/voice?call_id=${callId}`);
  }

  res.type("text/xml").send(twiml.toString());
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

    const messages = conversationRows.map((row) => ({
      role: row.sender === "user" ? "user" : "assistant",
      content: row.message,
    }));

    messages.unshift({
      role: "system",
      content: `You are an AI-powered outbound phone assistant.

CRITICAL RULES FOR VOICE:

- Speak in short, natural responses (1–2 sentences, occasionally 3 max)
- Keep things conversational, not robotic
- Do NOT ramble or give long speeches
- Sound like a real human on a phone call

CONVERSATION STYLE:

- It’s okay to briefly explain something if needed
- Not every response needs to be a question
- Mix between:
  - short statements
  - light explanations
  - occasional questions

- Questions should feel natural, not forced

BAD:
"Do you do marketing? What tools? What budget?"

GOOD:
"Got it — a lot of people I talk to are handling that manually right now.  
Curious, are you doing that yourself or with a team?"

FLOW:

1. Start casual
2. Add context naturally
3. Guide the conversation (not interrogate)
4. Keep it low-pressure

TONE:

- Friendly
- Calm
- Slightly persuasive
- Never dramatic or intense

IMPORTANT:

- Avoid sounding scripted
- Avoid asking too many questions in a row
- Let the conversation breathe

This is a LIVE PHONE CALL.`,
    });

    const aiResponse = await getAIResponse(messages);
    await pool.query(
      "INSERT INTO conversations (call_id, sender, message) VALUES (?, ?, ?)",
      [callId, "ai", aiResponse],
    );

    const endPhrases = [
      "goodbye",
      "talk to you later",
      "bye",
      "have a nice day",
    ];
    const isEnding = endPhrases.some((phrase) =>
      aiResponse.toLowerCase().includes(phrase),
    );

    if (isEnding) {
      twiml.say({ voice: "Polly.Amy" }, aiResponse);
      twiml.hangup();
    } else {
      const gather = twiml.gather({
        input: "speech",
        action: `/b4backend/process-speech?call_id=${callId}`,
        method: "POST",
        timeout: 8,
        speechTimeout: "auto",
      });
      gather.say({ voice: "Polly.Amy" }, aiResponse);
      twiml.redirect(`/b4backend/voice?call_id=${callId}`);
    }

    res.type("text/xml").send(twiml.toString());
  } catch {
    twiml.say("Sorry, something went wrong.");
    res.type("text/xml");
    res.send(twiml.toString());
  }
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

router.get("/my-dashboard", authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT email, api_calls, admin FROM users WHERE email = ?",
      [req.user.email],
    );

    if (rows.length > 0) {
      res.json({
        email: rows[0].email,
        api_calls: rows[0].api_calls,
        is_admin: rows[0].admin,
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
  if (!req.user.admin)
    return res.status(403).json({ error: "Admin access required." });

  try {
    const [rows] = await pool.query(
      "SELECT id, email, api_calls, admin FROM users ORDER BY api_calls DESC",
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

router.get("/ai-response", async (req, res) => {
  const { prompt } = req.query;
  if (!prompt)
    return res.status(400).json({ error: "Missing prompt parameter." });

  try {
    const messages = [
      { role: "system", content: "You are a helpful AI assistant." },
      { role: "user", content: prompt },
    ];

    const aiResponse = await getAIResponse(messages);
    res.json({
      prompt,
      response: aiResponse,
      timestamp: new Date().toISOString(),
      status: "success",
    });
  } catch (err) {
    res.status(500).json({
      error: "Failed to get AI response",
      details: err.message,
      timestamp: new Date().toISOString(),
    });
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
    const messages = [
      { role: "system", content: "You are a helpful AI assistant." },
      { role: "user", content: prompt },
    ];

    const aiResponse = await getAIResponse(messages);
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

router.get("/admin/stats", authenticateToken, async (req, res) => {
  if (!req.user.admin)
    return res.status(403).json({ error: "Admin only" });

  try {
    const [[{ totalCalls }]] = await pool.query(
      "SELECT COUNT(*) as totalCalls FROM calls"
    );

    const [[{ todayCalls }]] = await pool.query(`
      SELECT COUNT(*) as todayCalls 
      FROM calls 
      WHERE DATE(started_at) = CURDATE()
    `);

    const [[{ avgCalls }]] = await pool.query(`
      SELECT AVG(api_calls) as avgCalls FROM users
    `);

    res.json({
      totalCalls,
      todayCalls,
      avgCalls: Math.round(avgCalls || 0),
    });
  } catch (err) {
    console.error("STATS ERROR:", err);
    res.status(500).json({ error: err.message });
  }
});

router.get("/admin/usage-trend", authenticateToken, async (req, res) => {
  if (!req.user.admin) return res.status(403).json({ error: "Admin only" });

  try {
    const [rows] = await pool.query(`
      SELECT 
        DATE(started_at) as date,
        COUNT(*) as calls
      FROM calls
      GROUP BY DATE(started_at)
      ORDER BY date ASC
      LIMIT 7
    `);

    const formatted = rows.map(r => ({
      day: new Date(r.date).toLocaleDateString("en-US", { weekday: "short" }),
      calls: Number(r.calls),
    }));

    res.json(formatted);
  } catch (err) {
    console.error("USAGE TREND ERROR:", err);
    res.status(500).json({ error: err.message });
  }
});

router.get("/admin/user-calls", authenticateToken, async (req, res) => {
  if (!req.user.admin) return res.status(403).json({ error: "Admin only" });

  try {
    const [rows] = await pool.query(`
      SELECT email as name, api_calls as calls
      FROM users
      ORDER BY api_calls DESC
      LIMIT 5
    `);

    res.json(rows);
  } catch (err) {
    console.error("USER CALLS ERROR:", err);
    res.status(500).json({ error: err.message });
  }
});

router.get("/admin/avg-messages", authenticateToken, async (req, res) => {
  if (!req.user.admin) return res.status(403).json({ error: "Admin only" });

  try {
    const [[{ avgMessages }]] = await pool.query(`
      SELECT AVG(msg_count) as avgMessages FROM (
        SELECT COUNT(*) as msg_count
        FROM conversations
        GROUP BY call_id
      ) as sub
    `);

    res.json({ avgMessages: Math.round(avgMessages || 0) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/admin/conversation-stats", authenticateToken, async (req, res) => {
  if (!req.user.admin) return res.status(403).json({ error: "Admin only" });
  
  try {
    const [[{ totalMessages }]] = await pool.query(
      "SELECT COUNT(*) as totalMessages FROM conversations"
    );
    
    const [[{ userMessages }]] = await pool.query(
      "SELECT COUNT(*) as userMessages FROM conversations WHERE sender = 'user'"
    );
    
    const [[{ aiMessages }]] = await pool.query(
      "SELECT COUNT(*) as aiMessages FROM conversations WHERE sender = 'ai'"
    );
    
    const [[{ avgMessagesPerCall }]] = await pool.query(`
      SELECT AVG(msg_count) as avgMessagesPerCall FROM (
        SELECT COUNT(*) as msg_count
        FROM conversations
        GROUP BY call_id
      ) as sub
    `);
    
    res.json({
      totalMessages,
      userMessages,
      aiMessages,
      avgMessagesPerCall: Math.round(avgMessagesPerCall || 0)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/admin/daily-messages", authenticateToken, async (req, res) => {
  if (!req.user.admin) return res.status(403).json({ error: "Admin only" });
  
  try {
    const [rows] = await pool.query(`
      SELECT 
        DATE(created_at) as date,
        SUM(CASE WHEN sender = 'user' THEN 1 ELSE 0 END) as userMessages,
        SUM(CASE WHEN sender = 'ai' THEN 1 ELSE 0 END) as aiMessages
      FROM conversations
      GROUP BY DATE(created_at)
      ORDER BY date ASC
      LIMIT 7
    `);
    
    const formatted = rows.map(r => ({
      day: new Date(r.date).toLocaleDateString("en-US", { weekday: "short" }),
      userMessages: Number(r.userMessages),
      aiMessages: Number(r.aiMessages)
    }));
    
    res.json(formatted);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/admin/user-activity", authenticateToken, async (req, res) => {
  if (!req.user.admin) return res.status(403).json({ error: "Admin only" });
  
  try {
    const [rows] = await pool.query(`
      SELECT 
        u.email,
        u.api_calls,
        COUNT(DISTINCT c.id) as unique_calls,
        COUNT(DISTINCT conv.id) as total_messages
      FROM users u
      LEFT JOIN calls c ON u.email = c.email
      LEFT JOIN conversations conv ON c.id = conv.call_id
      GROUP BY u.email, u.api_calls
      ORDER BY u.api_calls DESC
    `);
    
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/admin/hourly-distribution", authenticateToken, async (req, res) => {
  if (!req.user.admin) return res.status(403).json({ error: "Admin only" });
  
  try {
    const [rows] = await pool.query(`
      SELECT 
        HOUR(started_at) as hour,
        COUNT(*) as calls
      FROM calls
      GROUP BY HOUR(started_at)
      ORDER BY hour ASC
    `);
    
    const formatted = rows.map(r => ({
      hour: `${String(r.hour).padStart(2, '0')}:00`,
      calls: Number(r.calls)
    }));
    
    res.json(formatted);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/admin/top-users", authenticateToken, async (req, res) => {
  if (!req.user.admin) return res.status(403).json({ error: "Admin only" });
  
  try {
    const [rows] = await pool.query(`
      SELECT 
        u.email,
        u.api_calls,
        COUNT(DISTINCT c.id) as total_calls
      FROM users u
      LEFT JOIN calls c ON u.email = c.email
      GROUP BY u.email, u.api_calls
      ORDER BY total_calls DESC
      LIMIT 10
    `);
    
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/admin/recent-activity", authenticateToken, async (req, res) => {
  if (!req.user.admin) return res.status(403).json({ error: "Admin only" });
  
  try {
    const [rows] = await pool.query(`
      SELECT 
        c.id as call_id,
        c.email,
        c.started_at,
        COUNT(conv.id) as message_count
      FROM calls c
      LEFT JOIN conversations conv ON c.id = conv.call_id
      GROUP BY c.id, c.email, c.started_at
      ORDER BY c.started_at DESC
      LIMIT 10
    `);
    
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.use("", router);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
