import "dotenv/config";
import express from "express";
import bcrypt from "bcryptjs";
import { MongoClient } from "mongodb";
import path from "node:path";
import { fileURLToPath } from "node:url";

const app = express();
const port = Number(process.env.PORT || 3000);
const mongoUri = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017";
const databaseName = process.env.MONGODB_DB || "ai_shield";
const mongoClient = new MongoClient(mongoUri);
const currentFile = fileURLToPath(import.meta.url);
const currentDirectory = path.dirname(currentFile);
let mongoConnection;
let databaseSetup;

function ensureMongoConnection() {
  mongoConnection ??= mongoClient.connect().catch(error => {
    mongoConnection = undefined;
    throw error;
  });
  return mongoConnection;
}

function ensureDatabase() {
  databaseSetup ??= (async () => {
    await ensureMongoConnection();
    await mongoClient.db(databaseName).collection("users").createIndex({ email: 1 }, { unique: true });
  })().catch(error => {
    databaseSetup = undefined;
    throw error;
  });
  return databaseSetup;
}

app.use(express.json());
app.use(express.static(currentDirectory));

app.get("/api/health", async (_request, response) => {
  try {
    await ensureDatabase();
    await mongoClient.db(databaseName).command({ ping: 1 });
    response.json({ ok: true, database: databaseName });
  } catch {
    response.status(503).json({ ok: false, message: "MongoDB is not connected." });
  }
});

app.post("/api/auth/login", async (request, response) => {
  const { email, password } = request.body || {};

  if (typeof email !== "string" || typeof password !== "string" || !email.trim() || !password) {
    return response.status(400).json({ message: "Email and password are required." });
  }

  try {
    await ensureDatabase();
    const users = mongoClient.db(databaseName).collection("users");
    const normalizedEmail = email.trim().toLowerCase();
    const user = await users.findOne({ email: normalizedEmail });

    if (!user) {
      return response.status(401).json({ message: "Account not found. Create an account first." });
    }

    const passwordMatches = await bcrypt.compare(password, user.passwordHash);
    if (!passwordMatches) {
      return response.status(401).json({ message: "Invalid email or password." });
    }

    response.json({ user: { id: user._id, email: user.email } });
  } catch {
    response.status(503).json({ message: "MongoDB is unavailable." });
  }
});

app.post("/api/auth/register", async (request, response) => {
  const { email, password } = request.body || {};

  if (typeof email !== "string" || typeof password !== "string" || !email.trim() || password.length < 8) {
    return response.status(400).json({ message: "Use a valid email and an 8+ character password." });
  }

  try {
    await ensureDatabase();
    const users = mongoClient.db(databaseName).collection("users");
    const normalizedEmail = email.trim().toLowerCase();
    const existingUser = await users.findOne({ email: normalizedEmail });

    if (existingUser) {
      return response.status(409).json({ message: "An account with this email already exists." });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const result = await users.insertOne({
      email: normalizedEmail,
      passwordHash,
      createdAt: new Date()
    });

    response.status(201).json({ user: { id: result.insertedId, email: normalizedEmail } });
  } catch {
    response.status(503).json({ message: "MongoDB is unavailable." });
  }
});

async function startServer() {
  await ensureDatabase();
  app.listen(port, () => console.log(`AI Shield running at http://localhost:${port}`));
}

if (process.env.VERCEL !== "1") {
  startServer().catch(error => {
    console.error("Unable to start AI Shield:", error.message);
    process.exit(1);
  });
}

export default app;
