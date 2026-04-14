const express = require("express");
const app = express();
const crypto = require("crypto");
app.use(express.json());

// ─── In-memory DB ─────────────────────────────────────────────────────────────
const resetTokens     = new Map();  // token -> { email, newPassword, expiresAt, used }
const blacklistedTokens = new Set();

let users = [
  { userId: 1, name: "Admin User", email: "admin@email.com", password: "Admin123",  phone: "0800000000",  role: "Admin"    },
  { userId: 2, name: "Staff User", email: "staff@email.com", password: "Staff123",  phone: "0800000001",  role: "Staff"    },
  { userId: 3, name: "John Doe",   email: "dup@test.com",    password: "Pass1234",  phone: "0812345678",  role: "Customer" },
  { userId: 4, name: "Jane Smith", email: "test@example.com",password: "Pass1234",  phone: "0812345679",  role: "Customer" },
];

let tables = [
  { tableId: 1, capacity: 2,  status: "AVAILABLE"      },
  { tableId: 2, capacity: 4,  status: "OCCUPIED"        },
  { tableId: 3, capacity: 4,  status: "AVAILABLE"       },
  { tableId: 4, capacity: 6,  status: "AVAILABLE"       },
  { tableId: 5, capacity: 8,  status: "OUT_OF_SERVICE"  },
  { tableId: 6, capacity: 10, status: "AVAILABLE"       },
];

let reservations = [
  {
    reservationId: 5001,
    customerId: 3,
    customerName: "John Doe",
    tableId: 3,
    date: "2026-05-20",
    time: "18:00",
    guestCount: 4,
    specialRequest: "Window seat",
    status: "CONFIRMED",
  },
];

let restaurantSettings = {
  name: "The Reserve Restaurant",
  address: "123 Main Street, Bangkok",
  pricePerPerson: 299.00,
  operatingHours: { open: 10, close: 22 },
  tableCount: 6,
};

let loginAttempts    = {};
let nextUserId       = 100;
let nextReservationId = 5002;

// ─── Helpers ──────────────────────────────────────────────────────────────────
function generateToken(user) {
  const payload = Buffer.from(
    JSON.stringify({ userId: user.userId, role: user.role, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 })
  ).toString("base64");
  return `fake.${payload}.token`;
}

function verifyToken(req, res) {
  const auth = req.headers["authorization"] || "";
  if (!auth.startsWith("Bearer ")) return null;
  const token = auth.slice(7);
  try {
    if (blacklistedTokens.has(token)) {
      res.status(401).json({ error: "Unauthorized", details: "Token has been invalidated" });
      return null;
    }
    const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64").toString());
    if (payload.exp < Date.now()) {
      res.status(401).json({ error: "Unauthorized", details: "Token has expired" });
      return null;
    }
    return payload;
  } catch {
    res.status(401).json({ error: "Unauthorized", details: "Invalid token" });
    return null;
  }
}

function requireAuth(req, res) {
  const user = verifyToken(req, res);
  if (!user) return null;
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
  const { open, close } = restaurantSettings.operatingHours;
  if (close > open) return h >= open && h < close;
  return h >= open || h < close; // cross-midnight
}

function isFutureDateTime(date, time) {
  return new Date(`${date}T${time}:00`) > new Date();
}

function validatePassword(password) {
  if (password.length < 8)        return "Password must be at least 8 characters";
  if (!/[A-Z]/.test(password))    return "Password must contain at least 1 uppercase letter";
  if (!/[0-9]/.test(password))    return "Password must contain at least 1 number";
  return null;
}

function validatePhone(phone) {
  if (!/^\d+$/.test(phone))  return "Phone number must contain digits only";
  if (phone.length < 10)     return "Phone number must be at least 10 digits";
  if (phone.length > 15)     return "Phone number must not exceed 15 digits";
  return null;
}

// Overlap-aware table finder: treats each reservation as occupying a 1-hour slot
function findAvailableTable(guestCount, date, time) {
  const [reqH, reqM] = time.split(":").map(Number);
  const reqStart = reqH * 60 + reqM;
  const reqEnd   = reqStart + 60;

  const bookedTableIds = reservations
    .filter((r) => {
      if (r.date !== date || r.status !== "CONFIRMED") return false;
      const [rH, rM] = r.time.split(":").map(Number);
      const rStart = rH * 60 + rM;
      const rEnd   = rStart + 60;
      return reqStart < rEnd && reqEnd > rStart; // overlap check
    })
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

// ═════════════════════════════════════════════════════════════════════════════
// AUTH APIs
// ═════════════════════════════════════════════════════════════════════════════

// POST /v1/auth/register
app.post("/v1/auth/register", (req, res) => {
  const { name, email, password, phone } = req.body || {};

  if (!name || !email || !password) {
    return res.status(400).json({ error: "Invalid input data", details: "name, email, password are required" });
  }

  // Verify Name rejects numbers/special characters
  if (!/^[a-zA-Z\s]+$/.test(name)) {
    return res.status(400).json({ error: "Invalid input data", details: "Name must contain only letters and spaces" });
  }

  // Verify Email rejects invalid format
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Invalid input data", details: "Invalid email format" });
  }

  // Password validations (min length, uppercase, number)
  const pwErr = validatePassword(password);
  if (pwErr) return res.status(400).json({ error: "Invalid input data", details: pwErr });

  // Phone validations (optional field)
  if (phone !== undefined && phone !== null && phone !== "") {
    const phoneErr = validatePhone(phone);
    if (phoneErr) return res.status(400).json({ error: "Invalid input data", details: phoneErr });
  }

  // Verify Registration fails with duplicate Email
  if (users.find((u) => u.email === email)) {
    return res.status(409).json({ error: "Email already exists" });
  }

  const userId = nextUserId++;
  users.push({ userId, name, email, password, phone: phone || null, role: "Customer" });
  return res.status(201).json({ userId, message: "Registration successful" });
});

// POST /v1/auth/login
app.post("/v1/auth/login", (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ error: "Invalid input data", details: "email and password are required" });
  }

  loginAttempts[email] = (loginAttempts[email] || 0) + 1;
  if (loginAttempts[email] > 5) {
    return res.status(429).json({ error: "Too many login attempts. Please try again later." });
  }

  const user = users.find((u) => u.email === email && u.password === password);
  if (!user) {
    return res.status(401).json({ error: "Invalid email or password" });
  }

  loginAttempts[email] = 0;
  return res.json({ token: generateToken(user), role: user.role });
});

// POST /v1/auth/logout
app.post("/v1/auth/logout", (req, res) => {
  const auth = req.headers["authorization"] || "";
  if (auth.startsWith("Bearer ")) {
    blacklistedTokens.add(auth.slice(7));
  }
  return res.json({ message: "Logged out successfully" });
});

// POST /v1/auth/forgot-password
// Body: { email, newPassword, confirmPassword }
// Validates password here so reset-password only needs the token
app.post("/v1/auth/forgot-password", (req, res) => {
  const { email, newPassword, confirmPassword } = req.body || {};

  if (!email || !newPassword || !confirmPassword) {
    return res.status(400).json({ error: "Invalid input data", details: "email, newPassword, confirmPassword are required" });
  }

  // New and Confirm Password Mismatch
  if (newPassword !== confirmPassword) {
    return res.status(400).json({ error: "Invalid input data", details: "Passwords do not match" });
  }

  const pwErr = validatePassword(newPassword);
  if (pwErr) return res.status(400).json({ error: "Invalid input data", details: pwErr });

  const user = users.find((u) => u.email === email);
  if (!user) {
    // Prevent email enumeration
    return res.status(200).json({ message: "If this email exists, a reset link has been sent" });
  }

  const token     = crypto.randomBytes(32).toString("hex");
  const expiresAt = Date.now() + 15 * 60 * 1000; // 15 minutes
  resetTokens.set(token, { email, newPassword, expiresAt, used: false });

  return res.status(200).json({
    message: "If this email exists, a reset link has been sent",
    resetToken: token,
  });
});

// POST /v1/auth/reset-password
// Body: { token }  — password already validated in forgot-password
app.post("/v1/auth/reset-password", (req, res) => {
  const { token } = req.body || {};

  if (!token) {
    return res.status(400).json({ error: "Invalid input data", details: "token is required" });
  }

  const record = resetTokens.get(token);

  // Attempt to use an Expired Token
  if (!record || Date.now() > record.expiresAt) {
    return res.status(400).json({ error: "Invalid or expired token" });
  }

  // Token Re-use Prevention
  if (record.used) {
    return res.status(400).json({ error: "Token has already been used" });
  }

  // Successful password reset
  const user = users.find((u) => u.email === record.email);
  user.password = record.newPassword;

  record.used = true;
  resetTokens.set(token, record);

  return res.status(200).json({ message: "Password reset successful" });
});

// ═════════════════════════════════════════════════════════════════════════════
// RESERVATION APIs
// ═════════════════════════════════════════════════════════════════════════════

// POST /v1/reservations
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
    const { open, close } = restaurantSettings.operatingHours;
    return res.status(400).json({ error: "Invalid input data", details: `Reservation must be within operating hours (${open}:00 - ${close}:00)` });
  }

  // Special Request max 200 chars
  if (specialRequest && specialRequest.length > 200) {
    return res.status(400).json({ error: "Invalid input data", details: "Special request must not exceed 200 characters" });
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

  return res.status(201).json({ reservationId, tableId: table.tableId, status: "CONFIRMED" });
});

// GET /v1/reservations/my
app.get("/v1/reservations/my", (req, res) => {
  const authUser = requireAuth(req, res);
  if (!authUser) return;
  return res.json(reservations.filter((r) => r.customerId === authUser.userId));
});

// PATCH /v1/reservations/:reservationId  — Modify reservation
app.patch("/v1/reservations/:reservationId", (req, res) => {
  const authUser = requireAuth(req, res);
  if (!authUser) return;

  const id          = parseInt(req.params.reservationId);
  const reservation = reservations.find((r) => r.reservationId === id);

  if (!reservation) {
    return res.status(404).json({ error: "Reservation not found" });
  }
  if (authUser.role === "Customer" && reservation.customerId !== authUser.userId) {
    return res.status(403).json({ error: "Forbidden: you can only modify your own reservations" });
  }
  if (reservation.status === "CANCELLED") {
    return res.status(400).json({ error: "Invalid input data", details: "Cannot modify a cancelled reservation" });
  }

  // Must modify before reservation start time
  const reservationDt = new Date(`${reservation.date}T${reservation.time}:00`);
  if (new Date() >= reservationDt) {
    return res.status(400).json({ error: "Invalid input data", details: "Cannot modify reservation at or after start time" });
  }

  const { date, time, guestCount, specialRequest } = req.body || {};

  const newDate       = date        || reservation.date;
  const newTime       = time        || reservation.time;
  const newGuestCount = guestCount  != null ? guestCount : reservation.guestCount;
  const newSpecial    = specialRequest !== undefined ? specialRequest : reservation.specialRequest;

  if (newGuestCount < 1 || newGuestCount > 10) {
    return res.status(400).json({ error: "Invalid input data", details: "Guest count must be between 1 and 10" });
  }
  if (!isFutureDateTime(newDate, newTime)) {
    return res.status(400).json({ error: "Invalid input data", details: "Reservation must be a future date/time" });
  }
  if (!isWithinOperatingHours(newTime)) {
    return res.status(400).json({ error: "Invalid input data", details: "Reservation must be within operating hours" });
  }
  if (newSpecial && newSpecial.length > 200) {
    return res.status(400).json({ error: "Invalid input data", details: "Special request must not exceed 200 characters" });
  }

  // Find available table for new slot (excluding this reservation)
  const tempReservations = reservations.filter((r) => r.reservationId !== id);
  const [reqH, reqM] = newTime.split(":").map(Number);
  const reqStart = reqH * 60 + reqM;
  const reqEnd   = reqStart + 60;

  const bookedTableIds = tempReservations
    .filter((r) => {
      if (r.date !== newDate || r.status !== "CONFIRMED") return false;
      const [rH, rM] = r.time.split(":").map(Number);
      const rStart = rH * 60 + rM;
      return reqStart < rStart + 60 && reqEnd > rStart;
    })
    .map((r) => r.tableId);

  const newTable = tables.find(
    (t) => t.status === "AVAILABLE" && t.capacity >= newGuestCount && !bookedTableIds.includes(t.tableId)
  );
  if (!newTable) {
    return res.status(409).json({ error: "Table not available for the new time and guest count" });
  }

  reservation.date           = newDate;
  reservation.time           = newTime;
  reservation.guestCount     = newGuestCount;
  reservation.specialRequest = newSpecial;
  reservation.tableId        = newTable.tableId;

  return res.json({ reservationId: id, status: reservation.status, tableId: newTable.tableId });
});

// DELETE /v1/reservations/:reservationId  — Cancel reservation
app.delete("/v1/reservations/:reservationId", (req, res) => {
  const authUser = requireAuth(req, res);
  if (!authUser) return;

  const id          = parseInt(req.params.reservationId);
  const reservation = reservations.find((r) => r.reservationId === id);

  if (!reservation) {
    return res.status(404).json({ error: "Reservation not found" });
  }
  if (authUser.role === "Customer" && reservation.customerId !== authUser.userId) {
    return res.status(403).json({ error: "Forbidden: you can only cancel your own reservations" });
  }

  // Already cancelled
  if (reservation.status === "CANCELLED") {
    return res.status(400).json({ error: "Invalid input data", details: "Reservation is already cancelled" });
  }

  // Must cancel at least 1 hour before
  const reservationDt  = new Date(`${reservation.date}T${reservation.time}:00`);
  const oneHourBefore  = new Date(reservationDt.getTime() - 60 * 60 * 1000);
  if (new Date() >= oneHourBefore) {
    return res.status(400).json({ error: "Invalid input data", details: "Cancellation must be at least 1 hour before reservation time" });
  }

  reservation.status = "CANCELLED";

  // Release table back to AVAILABLE if no other confirmed reservations for that table
  const stillBooked = reservations.some(
    (r) => r.tableId === reservation.tableId && r.reservationId !== id && r.status === "CONFIRMED"
  );
  if (!stillBooked) {
    const table = tables.find((t) => t.tableId === reservation.tableId);
    if (table && table.status === "OCCUPIED") table.status = "AVAILABLE";
  }

  return res.json({ message: "Reservation cancelled", reservationId: id });
});

// ═════════════════════════════════════════════════════════════════════════════
// TABLE MANAGEMENT APIs (Staff / Admin)
// ═════════════════════════════════════════════════════════════════════════════

// GET /v1/tables
app.get("/v1/tables", (req, res) => {
  const authUser = requireRole(req, res, "Staff", "Admin");
  if (!authUser) return;
  return res.json(tables);
});

// POST /v1/tables  — Add table (Admin only)
app.post("/v1/tables", (req, res) => {
  const authUser = requireRole(req, res, "Admin");
  if (!authUser) return;

  const { capacity } = req.body || {};

  if (capacity == null) {
    return res.status(400).json({ error: "Invalid input data", details: "capacity is required" });
  }
  if (!Number.isInteger(capacity) || capacity < 1) {
    return res.status(400).json({ error: "Invalid input data", details: "capacity must be a positive integer" });
  }

  const tableId = tables.length > 0 ? Math.max(...tables.map((t) => t.tableId)) + 1 : 1;
  const newTable = { tableId, capacity, status: "AVAILABLE" };
  tables.push(newTable);
  restaurantSettings.tableCount = tables.length;

  return res.status(201).json(newTable);
});

// PATCH /v1/tables/:tableId/status  — Update table status (Staff / Admin)
app.patch("/v1/tables/:tableId/status", (req, res) => {
  const authUser = requireRole(req, res, "Staff", "Admin");
  if (!authUser) return;

  const VALID_STATUSES = ["AVAILABLE", "OCCUPIED", "CHECK_IN", "OUT_OF_SERVICE"];
  const { status }  = req.body || {};
  const tableId     = parseInt(req.params.tableId);
  const table       = tables.find((t) => t.tableId === tableId);

  if (!table) {
    return res.status(404).json({ error: "Table not found" });
  }
  if (!VALID_STATUSES.includes(status)) {
    return res.status(400).json({ error: "Invalid input data", details: `status must be one of: ${VALID_STATUSES.join(", ")}` });
  }

  table.status = status;
  return res.json({ tableId, status });
});

// ═════════════════════════════════════════════════════════════════════════════
// ADMIN APIs
// ═════════════════════════════════════════════════════════════════════════════

// GET /v1/admin/reservations
app.get("/v1/admin/reservations", (req, res) => {
  const authUser = requireRole(req, res, "Admin");
  if (!authUser) return;

  // Optional query filters: ?status=CONFIRMED&date=2026-05-20
  let result = [...reservations];
  if (req.query.status) result = result.filter((r) => r.status === req.query.status);
  if (req.query.date)   result = result.filter((r) => r.date   === req.query.date);

  return res.json(result);
});

// GET /v1/admin/settings
app.get("/v1/admin/settings", (req, res) => {
  const authUser = requireRole(req, res, "Admin");
  if (!authUser) return;
  return res.json(restaurantSettings);
});

// PATCH /v1/admin/settings
app.patch("/v1/admin/settings", (req, res) => {
  const authUser = requireRole(req, res, "Admin");
  if (!authUser) return;

  const { name, address, pricePerPerson, operatingHours, tableCount } = req.body || {};

  if (name !== undefined) {
    if (typeof name !== "string" || name.trim() === "") {
      return res.status(400).json({ error: "Invalid input data", details: "name must be a non-empty string" });
    }
    restaurantSettings.name = name.trim();
  }

  if (address !== undefined) {
    restaurantSettings.address = address;
  }

  if (pricePerPerson !== undefined) {
    if (typeof pricePerPerson !== "number" || pricePerPerson < 0) {
      return res.status(400).json({ error: "Invalid input data", details: "pricePerPerson must be a non-negative number" });
    }
    restaurantSettings.pricePerPerson = pricePerPerson;
  }

  if (operatingHours !== undefined) {
    const { open, close } = operatingHours;
    if (open == null || close == null || open < 0 || open > 23 || close < 0 || close > 23) {
      return res.status(400).json({ error: "Invalid input data", details: "operatingHours.open and .close must be integers 0-23" });
    }
    restaurantSettings.operatingHours = { open, close };
  }

  if (tableCount !== undefined) {
    if (!Number.isInteger(tableCount) || tableCount < 0) {
      return res.status(400).json({ error: "Invalid input data", details: "tableCount must be a non-negative integer" });
    }
    restaurantSettings.tableCount = tableCount;
  }

  return res.json({ message: "Settings updated", settings: restaurantSettings });
});

// ─── Search/Filter helpers ────────────────────────────────────────────────────
// GET /v1/reservations?name=&status=&date=&keyword=
app.get("/v1/reservations", (req, res) => {
  const authUser = requireRole(req, res, "Staff", "Admin");
  if (!authUser) return;

  let result = [...reservations];
  const { name, status, date, keyword } = req.query;

  // Exact name search
  if (name) result = result.filter((r) => r.customerName === name);

  // Category / status filter
  if (status) result = result.filter((r) => r.status === status);

  // Date filter
  if (date) result = result.filter((r) => r.date === date);

  // Keyword partial match on customerName or specialRequest
  if (keyword) {
    const kw = keyword.toLowerCase();
    result = result.filter(
      (r) =>
        r.customerName.toLowerCase().includes(kw) ||
        (r.specialRequest && r.specialRequest.toLowerCase().includes(kw))
    );
  }

  return res.json(result);
});

// ─── Catch-all 404 ────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found" });
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🍽  Restaurant Reservation Mock API`);
  console.log(`   Running at http://localhost:${PORT}/v1\n`);
  console.log(`   Pre-seeded accounts:`);
  console.log(`     Admin    → admin@email.com   / Admin123`);
  console.log(`     Staff    → staff@email.com   / Staff123`);
  console.log(`     Customer → dup@test.com      / Pass1234`);
  console.log(`     Customer → test@example.com  / Pass1234`);
  console.log(`\n   Endpoints:`);
  console.log(`     POST   /v1/auth/register`);
  console.log(`     POST   /v1/auth/login`);
  console.log(`     POST   /v1/auth/logout`);
  console.log(`     POST   /v1/auth/forgot-password`);
  console.log(`     POST   /v1/auth/reset-password`);
  console.log(`     POST   /v1/reservations`);
  console.log(`     GET    /v1/reservations          (Staff/Admin + filters)`);
  console.log(`     GET    /v1/reservations/my       (Customer)`);
  console.log(`     PATCH  /v1/reservations/:id`);
  console.log(`     DELETE /v1/reservations/:id`);
  console.log(`     GET    /v1/tables                (Staff/Admin)`);
  console.log(`     POST   /v1/tables                (Admin)`);
  console.log(`     PATCH  /v1/tables/:id/status     (Staff/Admin)`);
  console.log(`     GET    /v1/admin/reservations    (Admin)`);
  console.log(`     GET    /v1/admin/settings        (Admin)`);
  console.log(`     PATCH  /v1/admin/settings        (Admin)\n`);
});