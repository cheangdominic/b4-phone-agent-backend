import express from "express";
import connection from "./db-connection.js";
import bcrypt from "bcrypt";

const app = express();
app.use(express.urlencoded({ extended: true }));

app.post("/signup", async (req, res) => {
  const { username, password } = req.body;

  try {
    const [existing] = await connection.query(
      "SELECT * FROM users WHERE username = ?",
      [username],
    );

    if (existing.length > 0) {
      console.log("Username already taken");
      return res.redirect("/signup");
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await connection.query(
      "INSERT INTO users (username, password) VALUES (?, ?)",
      [username, hashedPassword],
    );

    console.log("User registered:", username);
    res.redirect("/login");
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const [rows] = await connection.query(
      "SELECT * FROM users WHERE username = ?",
      [username],
    );

    if (rows.length === 0) {
      console.log("Invalid username or password");
      return res.redirect("/login");
    }

    const user = rows[0];

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      console.log("Invalid username or password");
      return res.redirect("/login");
    }

    console.log("Login successful:", username);
    res.redirect("/dashboard");
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
