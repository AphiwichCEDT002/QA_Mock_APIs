const express = require("express");
const app = express();
app.use(express.json());

// ─── In-memory DB ───────────────────────────────────────────────────────────
let users = [
  { userId: 1, name: "Admin User", email: "admin@email.com", password: "Admin123", phone: "0800000000", role: "Admin" },
  { userId: 2, name: "Staff User", email: "staff@email.com", password: "Staff123", phone: "0800000001", role: "Staff" },
  { userId: 3, name: "John Doe",   email: "dup@test.com",   password: "Pass1234", phone: "0812345678", role: "Customer" },
];

let reservations = [
  { reservationId: 5001, customerId: 3, customerName: "John Smith", tableId: 3, date: "2026-05-20", time: "18:00", guestCount: 4, specialRequest: "Window seat", status: "CONFIRMED" },
];
let tables = [
  { tableId: 1, capacity: 2, status: "AVAILABLE" },
  { tableId: 2, capacity: 4, status: "OCCUPIED" },
  { tableId: 3, capacity: 4, status: "AVAILABLE" },
  { tableId: 4, capacity: 6, status: "AVAILABLE" },
  { tableId: 5, capacity: 8, status: "OUT_OF_SERVICE" },
];
let loginAttempts = {}; // email -> count
let nextUserId = 100;
let nextReservationId = 5002;

const OPERATING_HOURS = { open: 10, close: 22 }; // 10:00 - 22:00

// ─── Helpers ─────────────────────────────────────────────────────────────────
function generateToken(user) {
  // Simple fake JWT-like token (not real JWT)
  const payload = Buffer.from(JSON.stringify({ userId: user.userId, role: user.role, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 })).toString("base64");
  return `fake.${payload}.token`;
}

function verifyToken(req) {
  const auth = req.headers["authorization"] || "";
  if (!auth.startsWith("Bearer ")) return null;
  const token = auth.slice(7);
  try {
    const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64").toString());
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

function requireAuth(req, res) {
  const user = verifyToken(req);
  if (!user) {
    res.status(401).json({ error: "Authentication required" });
    return null;
  }
  return user;
}

function requireRole(req, res, ...roles) {
  const user = requireAuth(req, res);
  if (!user) return null;
  if (roles.length && !roles.includes(user.role)) {
    res.status(403).json({ error: "Forbidden: insufficient permissions" });
    return null;
  }
  return user;
}

function isWithinOperatingHours(time) {
  const [h] = time.split(":").map(Number);
  return h >= OPERATING_HOURS.open && h < OPERATING_HOURS.close;
}

function isFutureDateTime(date, time) {
  const dt = new Date(`${date}T${time}:00`);
  return dt > new Date();
}

function findAvailableTable(guestCount, date, time) {
  const bookedTableIds = reservations
    .filter((r) => r.date === date && r.time === time && r.status === "CONFIRMED")
    .map((r) => r.tableId);

  return tables.find(
    (t) => t.status === "AVAILABLE" && t.capacity >= guestCount && !bookedTableIds.includes(t.tableId)
  );
}

// ─── Middleware: logger ───────────────────────────────────────────────────────
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// ─── Auth APIs ───────────────────────────────────────────────────────────────

// POST /auth/register
app.post("/v1/auth/register", (req, res) => {
  const { name, email, password, phone } = req.body || {};

  if (!name || !email || !password) {
    return res.status(400).json({ error: "Invalid input data", details: "name, email, password are required" });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Invalid input data", details: "Invalid email format" });
  }``
  if (password.length < 8) {
    return res.status(400).json({ error: "Invalid input data", details: "Password must be at least 8 characters" });
  }
  if (users.find((u) => u.email === email)) {
    return res.status(409).json({ error: "Email already exists" });
  }

  const userId = nextUserId++;
  users.push({ userId, name, email, password, phone: phone || null, role: "Customer" });

  return res.status(201).json({ userId, message: "Registration successful" });
});

// POST /auth/login
app.post("/v1/auth/login", (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ error: "Invalid input data", details: "email and password are required" });
  }

  // Login attempt limit (max 5)
  loginAttempts[email] = (loginAttempts[email] || 0) + 1;
  if (loginAttempts[email] > 5) {
    return res.status(429).json({ error: "Too many login attempts. Please try again later." });
  }

  const user = users.find((u) => u.email === email && u.password === password);
  if (!user) {
    return res.status(401).json({ error: "Invalid email or password" });
  }

  // Reset attempts on success
  loginAttempts[email] = 0;
  const token = generateToken(user);
  return res.json({ token, role: user.role });
});

// ─── Reservation APIs ─────────────────────────────────────────────────────────

// POST /reservations
app.post("/v1/reservations", (req, res) => {
  const authUser = requireAuth(req, res);
  if (!authUser) return;

  const { date, time, guestCount, specialRequest } = req.body || {};

  if (!date || !time || guestCount == null) {
    return res.status(400).json({ error: "Invalid input data", details: "date, time, guestCount are required" });
  }
  if (guestCount < 1 || guestCount > 10) {
    return res.status(400).json({ error: "Invalid input data", details: "Guest count must be between 1 and 10" });
  }
  if (!isFutureDateTime(date, time)) {
    return res.status(400).json({ error: "Invalid input data", details: "Reservation must be a future date/time" });
  }
  if (!isWithinOperatingHours(time)) {
    return res.status(400).json({ error: "Invalid input data", details: `Reservation must be within operating hours (${OPERATING_HOURS.open}:00 - ${OPERATING_HOURS.close}:00)` });
  }

  const table = findAvailableTable(guestCount, date, time);
  if (!table) {
    return res.status(409).json({ error: "Table not available for the requested time and guest count" });
  }

  const user = users.find((u) => u.userId === authUser.userId);
  const reservationId = nextReservationId++;
  reservations.push({
    reservationId,
    customerId: authUser.userId,
    customerName: user?.name || "Unknown",
    tableId: table.tableId,
    date,
    time,
    guestCount,
    specialRequest: specialRequest || null,
    status: "CONFIRMED",
  });

  return res.status(201).json({ reservationId, status: "CONFIRMED" });
});

// DELETE /reservations/:reservationId
app.delete("/v1/reservations/:reservationId", (req, res) => {
  const authUser = requireAuth(req, res);
  if (!authUser) return;

  const id = parseInt(req.params.reservationId);
  const reservation = reservations.find((r) => r.reservationId === id);

  if (!reservation) {
    return res.status(404).json({ error: "Reservation not found" });
  }

  // Customer can only cancel their own; Staff/Admin can cancel any
  if (authUser.role === "Customer" && reservation.customerId !== authUser.userId) {
    return res.status(403).json({ error: "Forbidden: you can only cancel your own reservations" });
  }

  // Must cancel at least 1 hour before
  const reservationDt = new Date(`${reservation.date}T${reservation.time}:00`);
  const oneHourBefore = new Date(reservationDt.getTime() - 60 * 60 * 1000);
  if (new Date() > oneHourBefore) {
    return res.status(400).json({ error: "Invalid input data", details: "Cancellation must be at least 1 hour before reservation time" });
  }

  reservation.status = "CANCELLED";
  return res.json({ message: "Reservation cancelled" });
});

// GET /reservations/my  (Customer)
app.get("/v1/reservations/my", (req, res) => {
  const authUser = requireAuth(req, res);
  if (!authUser) return;

  const myReservations = reservations.filter((r) => r.customerId === authUser.userId);
  return res.json(myReservations);
});

// ─── Table Management APIs (Staff) ───────────────────────────────────────────

// GET /tables
app.get("/v1/tables", (req, res) => {
  const authUser = requireRole(req, res, "Staff", "Admin");
  if (!authUser) return;

  return res.json(tables);
});

// PATCH /tables/:tableId/status  (Staff)
app.patch("/v1/tables/:tableId/status", (req, res) => {
  const authUser = requireRole(req, res, "Staff", "Admin");
  if (!authUser) return;

  const VALID_STATUSES = ["AVAILABLE", "OCCUPIED", "CHECK_IN", "OUT_OF_SERVICE"];
  const { status } = req.body || {};
  const tableId = parseInt(req.params.tableId);
  const table = tables.find((t) => t.tableId === tableId);

  if (!table) return res.status(404).json({ error: "Table not found" });
  if (!VALID_STATUSES.includes(status)) {
    return res.status(400).json({ error: "Invalid input data", details: `status must be one of: ${VALID_STATUSES.join(", ")}` });
  }

  table.status = status;
  return res.json({ tableId, status });
});

// ─── Admin APIs ───────────────────────────────────────────────────────────────

// GET /admin/reservations
app.get("/v1/admin/reservations", (req, res) => {
  const authUser = requireRole(req, res, "Admin");
  if (!authUser) return;

  return res.json(reservations);
});

// ─── Catch-all 404 ────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found" });
});

// ─── Start ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`- Restaurant Reservation Mock API`);
  console.log(`- Running at http://localhost:${PORT}/v1`);
  console.log(`- Pre-seeded accounts:`);
  console.log(`    Admin  → admin@email.com  / Admin123`);
  console.log(`    Staff  → staff@email.com  / Staff123`);
  console.log(`    (Register a new Customer account via POST /v1/auth/register)\n`);
});
