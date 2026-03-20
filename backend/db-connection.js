const mysql = require("mysql2/promise");
const dotenv = require("dotenv");
dotenv.config();

async function connectDB() {
  try {
    const connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      port: process.env.DB_PORT,
    });

    console.log("✅ Connected to MySQL!");
    await connection.end();
  } catch (err) {
    console.error("❌ Connection failed:", err.message);
  }
}

connectDB();
