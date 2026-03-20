const mysql = require("mysql2/promise");
const dotenv = require("dotenv");
dotenv.config();

async function connectDB() {
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      port: process.env.DB_PORT,
    });

    console.log("✅ Connected to MySQL!");
  } catch (err) {
    console.error("❌ Connection failed:", err.message);
  }
}

await connectDB();

export default connection;