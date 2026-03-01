import express from "express"
import session from "express-session"
import bcrypt from "bcrypt"
import pkg from "pg"
import cors from "cors"
import dotenv from "dotenv"

dotenv.config()

const { Pool } = pkg
const app = express()

const PORT = process.env.PORT || 3000
const isProduction = process.env.NODE_ENV === "production"

/* ---------- PostgreSQL Connection ---------- */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL + (isProduction ? "?sslmode=require" : ""),
  ssl: isProduction ? { rejectUnauthorized: false } : false
})

console.log("DATABASE_URL:", process.env.DATABASE_URL)

pool.connect()
  .then(client => {
    console.log("PostgreSQL connected")
    client.release()
  })
  .catch(err => console.error("DB connection error:", err))

/* ---------- Middleware ---------- */
app.use(express.json())

app.use(
  cors({
    origin: process.env.CLIENT_URL,
    credentials: true
  })
)

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: isProduction,      // true in production (HTTPS)
      sameSite: isProduction ? "none" : "lax"
    }
  })
)

/* ---------- Auth Guard ---------- */
function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "Unauthorized" })
  }
  next()
}

/* ---------- Routes ---------- */

// SIGNUP
app.post("/signup", async (req, res) => {
  const { email, password } = req.body

  const existing = await pool.query(
    "SELECT id FROM users WHERE email = $1",
    [email]
  )

  if (existing.rows.length > 0) {
    return res.status(400).json({ error: "User exists" })
  }

  const hashed = await bcrypt.hash(password, 10)

  await pool.query(
    "INSERT INTO users (email, password) VALUES ($1, $2)",
    [email, hashed]
  )

  res.json({ success: true })
})

// LOGIN
app.post("/login", async (req, res) => {
  const { email, password } = req.body

  const result = await pool.query(
    "SELECT * FROM users WHERE email = $1",
    [email]
  )

  if (result.rows.length === 0) {
    return res.status(401).json({ error: "Invalid credentials" })
  }

  const user = result.rows[0]
  const match = await bcrypt.compare(password, user.password)

  if (!match) {
    return res.status(401).json({ error: "Invalid credentials" })
  }

  req.session.user = { id: user.id, email: user.email }

  res.json({ success: true })
})

// CURRENT USER
app.get("/me", requireAuth, (req, res) => {
  res.json(req.session.user)
})

// LOGOUT
app.post("/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }))
})

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})