
require("dotenv").config();

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();

app.use(express.json({ limit: "20kb" }));

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  throw new Error("Set SESSION_SECRET to a random secret of at least 32 characters.");
}

if (!DATABASE_URL) {
  throw new Error("DATABASE_URL is missing. Configure PostgreSQL first.");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

const COOKIE_NAME = "velora_session";
const SESSION_DAYS = 7;

const VIP_PLANS = {
  1: { cost: 1500, reward: 200 },
  2: { cost: 5000, reward: 800 },
  3: { cost: 10000, reward: 1750 },
  4: { cost: 25000, reward: 4100 },
  5: { cost: 50000, reward: 7500 },
  6: { cost: 100000, reward: 15000 }
};

// ---------------- DATABASE ----------------

async function setupDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS velora_users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(60) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      balance NUMERIC(14,2) NOT NULL DEFAULT 0,
      earnings NUMERIC(14,2) NOT NULL DEFAULT 0,
      vip_level INTEGER NOT NULL DEFAULT 0,
      last_claim_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS velora_activity (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES velora_users(id)
        ON DELETE CASCADE,
      description TEXT NOT NULL,
      amount NUMERIC(14,2) NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  console.log("VELORA database tables are ready.");
}

// ---------------- SESSION SECURITY ----------------

function sign(value) {
  return crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(value)
    .digest("base64url");
}

function createSession(userId) {
  const payload = Buffer.from(JSON.stringify({
    userId,
    expires: Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000
  })).toString("base64url");

  return payload + "." + sign(payload);
}

function readSession(token) {
  if (!token || typeof token !== "string") return null;

  const parts = token.split(".");
  if (parts.length !== 2) return null;

  const [payload, signature] = parts;
  const expected = sign(payload);

  const a = Buffer.from(signature);
  const b = Buffer.from(expected);

  if (a.length !== b.length ||
      !crypto.timingSafeEqual(a, b)) {
    return null;
  }

  try {
    const data = JSON.parse(
      Buffer.from(payload, "base64url").toString()
    );

    if (!Number.isInteger(data.userId)) return null;
    if (data.expires < Date.now()) return null;

    return data.userId;
  } catch {
    return null;
  }
}

function setSessionCookie(res, userId) {
  const token = createSession(userId);

  const secure = process.env.NODE_ENV === "production"
    ? "; Secure"
    : "";

  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}${secure}`
  );
}

function clearSessionCookie(res) {
  const secure = process.env.NODE_ENV === "production"
    ? "; Secure"
    : "";

  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0${secure}`
  );
}

function getCookie(req, name) {
  const cookieHeader = req.headers.cookie || "";

  const item = cookieHeader
    .split(";")
    .map(x => x.trim())
    .find(x => x.startsWith(name + "="));

  return item ? decodeURIComponent(item.slice(name.length + 1)) : null;
}

async function requireLogin(req, res, next) {
  try {
    const userId = readSession(getCookie(req, COOKIE_NAME));

    if (!userId) {
      return res.status(401).json({
        error: "Please log in again."
      });
    }

    const result = await pool.query(
      `SELECT id, name, email, balance, earnings,
              vip_level, last_claim_at
       FROM velora_users
       WHERE id = $1`,
      [userId]
    );

    if (!result.rows.length) {
      clearSessionCookie(res);
      return res.status(401).json({
        error: "Account not found. Please log in again."
      });
    }

    req.user = result.rows[0];
    next();
  } catch (error) {
    next(error);
  }
}

// ---------------- HELPERS ----------------

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    balance: Number(user.balance),
    earnings: Number(user.earnings),
    vipLevel: Number(user.vip_level)
  };
}

async function addActivity(client, userId, description, amount) {
  await client.query(
    `INSERT INTO velora_activity
      (user_id, description, amount)
     VALUES ($1, $2, $3)`,
    [userId, description, amount]
  );
}

async function getUser(client, userId) {
  const result = await client.query(
    `SELECT id, name, email, balance, earnings,
            vip_level, last_claim_at
     FROM velora_users
     WHERE id = $1`,
    [userId]
  );

  return result.rows[0];
}

// ---------------- HOME ----------------

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "VELORA EARN practice backend is running.",
    mode: "practice"
  });
});

// ---------------- SIGN UP ----------------

app.post("/api/signup", async (req, res, next) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (name.length < 2 || name.length > 60) {
      return res.status(400).json({
        error: "Enter a name between 2 and 60 characters."
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
        email.length > 255) {
      return res.status(400).json({
        error: "Enter a valid email address."
      });
    }

    if (password.length < 8 || password.length > 100) {
      return res.status(400).json({
        error: "Password must contain 8 to 100 characters."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO velora_users
        (name, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, name, email, balance, earnings, vip_level`,
      [name, email, passwordHash]
    );

    const user = result.rows[0];

    setSessionCookie(res, user.id);

    res.status(201).json({
      success: true,
      message: "Your VELORA account has been created.",
      user: publicUser(user)
    });

  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        error: "This email already has an account. Please log in."
      });
    }

    next(error);
  }
});

// ---------------- LOGIN ----------------

app.post("/api/login", async (req, res, next) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    const result = await pool.query(
      `SELECT id, name, email, password_hash,
              balance, earnings, vip_level
       FROM velora_users
       WHERE email = $1`,
      [email]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        error: "Incorrect email or password."
      });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: "Incorrect email or password."
      });
    }

    setSessionCookie(res, user.id);

    res.json({
      success: true,
      message: "Login successful.",
      user: publicUser(user)
    });

  } catch (error) {
    next(error);
  }
});

// ---------------- CURRENT USER ----------------

app.get("/api/me", requireLogin, (req, res) => {
  res.json({
    success: true,
    user: publicUser(req.user)
  });
});

// ---------------- LOGOUT ----------------

app.post("/api/logout", (req, res) => {
  clearSessionCookie(res);

  res.json({
    success: true,
    message: "You have logged out."
  });
});

// ---------------- DEMO WALLET CREDIT ----------------

app.post("/api/practice/credit", requireLogin, async (req, res, next) => {
  const amount = Number(req.body.amount);

  const allowedAmounts = [5000, 10000, 25000];

  if (!allowedAmounts.includes(amount)) {
    return res.status(400).json({
      error: "Choose one of the available demo credit amounts."
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    await client.query(
      `UPDATE velora_users
       SET balance = balance + $1
       WHERE id = $2`,
      [amount, req.user.id]
    );

    await addActivity(
      client,
      req.user.id,
      "Demo credits added",
      amount
    );

    const user = await getUser(client, req.user.id);

    await client.query("COMMIT");

    res.json({
      success: true,
      message: "Demo credits added.",
      user: publicUser(user)
    });

  } catch (error) {
    await client.query("ROLLBACK");
    next(error);
  } finally {
    client.release();
  }
});

// ---------------- PRACTICE VIP ACTIVATION ----------------

app.post("/api/practice/activate-vip", requireLogin, async (req, res, next) => {
  const level = Number(req.body.level);
  const plan = VIP_PLANS[level];

  if (!plan) {
    return res.status(400).json({
      error: "Invalid VIP plan."
    });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const result = await client.query(
      `SELECT id, balance, vip_level
       FROM velora_users
       WHERE id = $1
       FOR UPDATE`,
      [req.user.id]
    );

    const user = result.rows[0];

    if (level <= Number(user.vip_level)) {
      await client.query("ROLLBACK");

      return res.status(400).json({
        error: "You already have this VIP level or a higher one."
      });
    }

    if (Number(user.balance) < plan.cost) {
      await client.query("ROLLBACK");

      return res.status(400).json({
        error: "Insufficient practice balance. Add demo credits first."
      });
    }

    await client.query(
      `UPDATE velora_users
       SET balance = balance - $1,
           vip_level = $2
       WHERE id = $3`,
      [plan.cost, level, req.user.id]
    );

    await addActivity(
      client,
      req.user.id,
      `VIP ${level} practice activation`,
      -plan.cost
    );

    const updated = await getUser(client, req.user.id);

    await client.query("COMMIT");

    res.json({
      success: true,
      message: `VIP ${level} practice plan activated.`,
      user: publicUser(updated)
    });

  } catch (error) {
    await client.query("ROLLBACK");
    next(error);
  } finally {
    client.release();
  }
});

// ---------------- DAILY PRACTICE CLAIM ----------------

app.post("/api/practice/claim", requireLogin, async (req, res, next) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const result = await client.query(
      `SELECT id, balance, earnings, vip_level, last_claim_at
       FROM velora_users
       WHERE id = $1
       FOR UPDATE`,
      [req.user.id]
    );

    const user = result.rows[0];
    const level = Number(user.vip_level);

    if (!VIP_PLANS[level]) {
      await client.query("ROLLBACK");

      return res.status(400).json({
        error: "Activate a practice VIP plan before claiming."
      });
    }

    if (user.last_claim_at) {
      const nextClaim = new Date(user.last_claim_at).getTime()
        + 24 * 60 * 60 * 1000;

      if (Date.now() < nextClaim) {
        const remaining = nextClaim - Date.now();
        const hours = Math.ceil(remaining / 3600000);

        await client.query("ROLLBACK");

        return res.status(400).json({
          error: `Your next practice claim is available in about ${hours} hour(s).`
        });
      }
    }

    const reward = VIP_PLANS[level].reward;

    await client.query(
      `UPDATE velora_users
       SET balance = balance + $1,
           earnings = earnings + $1,
           last_claim_at = NOW()
       WHERE id = $2`,
      [reward, req.user.id]
    );

    await addActivity(
      client,
      req.user.id,
      "Daily practice reward",
      reward
    );

    const updated = await getUser(client, req.user.id);

    await client.query("COMMIT");

    res.json({
      success: true,
      message: `${moneyText(reward)} practice reward claimed successfully.`,
      user: publicUser(updated)
    });

  } catch (error) {
    await client.query("ROLLBACK");
    next(error);
  } finally {
    client.release();
  }
});

function moneyText(amount) {
  return "₦" + Number(amount).toLocaleString("en-NG");
}

// ---------------- ACTIVITY ----------------

app.get("/api/activity", requireLogin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT description, amount, created_at
       FROM velora_activity
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT 50`,
      [req.user.id]
    );

    res.json({
      success: true,
      activity: result.rows.map(item => ({
        description: item.description,
        amount: Number(item.amount),
        createdAt: item.created_at
      }))
    });

  } catch (error) {
    next(error);
  }
});

// ---------------- ERRORS ----------------

app.use((error, req, res, next) => {
  console.error(error);

  if (res.headersSent) return next(error);

  res.status(500).json({
    error: "A server error occurred. Please try again."
  });
});

// ---------------- START SERVER ----------------

setupDatabase()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`VELORA EARN running on port ${PORT}`);
      console.log("Mode: PRACTICE ONLY");
    });
  })
  .catch(error => {
    console.error("Could not start VELORA EARN:", error);
    process.exit(1);
  });
