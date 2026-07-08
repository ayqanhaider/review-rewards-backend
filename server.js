/**
 * Review Rewards – Shared Backend API
 * In-memory storage (upgradeable to any DB like Supabase/PlanetScale)
 * Deploy FREE on: Render.com, Railway.app, or Glitch.com
 */

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || "rr-super-secret-key-change-in-prod";

app.use(cors());
app.use(express.json());

// ─── IN-MEMORY DATABASE ───────────────────────────────────────────────────────
const db = {
  users: [
    // Pre-seeded admin
    {
      id: "admin-001",
      name: "Admin",
      phone: "03128515146",
      password: bcrypt.hashSync("freetopin2010", 10),
      role: "admin",
      balance: 0,
      createdAt: new Date().toISOString(),
    },
    // Demo worker
    {
      id: "worker-001",
      name: "Ayqan Haider",
      phone: "03335366928",
      password: bcrypt.hashSync("freetopin2010", 10),
      role: "worker",
      balance: 0,
      createdAt: new Date().toISOString(),
    },
  ],
  tasks: [
    {
      id: uuidv4(),
      title: "Google Maps Review",
      description: "Visit the link and leave a 5-star review for the restaurant. Screenshot required.",
      link: "https://maps.google.com",
      reward: 50,
      category: "Review",
      estimatedTime: "3 min",
      totalSlots: 20,
      filledSlots: 7,
      status: "active",
      createdAt: new Date().toISOString(),
      createdBy: "admin-001",
    },
    {
      id: uuidv4(),
      title: "Product Feedback Survey",
      description: "Fill out a 5-question survey about a new shampoo. Takes about 5 minutes.",
      link: "https://forms.google.com",
      reward: 35,
      category: "Survey",
      estimatedTime: "5 min",
      totalSlots: 50,
      filledSlots: 12,
      status: "active",
      createdAt: new Date().toISOString(),
      createdBy: "admin-001",
    },
    {
      id: uuidv4(),
      title: "App Store Rating",
      description: "Download the app, rate 5 stars and leave a positive review.",
      link: "https://play.google.com",
      reward: 40,
      category: "Review",
      estimatedTime: "4 min",
      totalSlots: 30,
      filledSlots: 30,
      status: "full",
      createdAt: new Date().toISOString(),
      createdBy: "admin-001",
    },
  ],
  submissions: [
    {
      id: uuidv4(),
      taskId: null, // will be set after tasks are seeded
      workerId: "worker-001",
      proof: "screenshot_url_here",
      status: "pending",
      reward: 50,
      submittedAt: new Date(Date.now() - 86400000).toISOString(),
    },
  ],
  withdrawals: [
    {
      id: uuidv4(),
      workerId: "worker-001",
      amount: 200,
      method: "EasyPaisa",
      accountNo: "03111234567",
      status: "paid",
      requestedAt: new Date(Date.now() - 172800000).toISOString(),
      processedAt: new Date(Date.now() - 86400000).toISOString(),
    },
  ],
};

// Link demo submission to first task
db.submissions[0].taskId = db.tasks[0].id;

// ─── HELPERS ─────────────────────────────────────────────────────────────────
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
};

const adminOnly = (req, res, next) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only" });
  next();
};

const findUser = (id) => db.users.find((u) => u.id === id);

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────

// POST /api/auth/register (workers only)
app.post("/api/auth/register", async (req, res) => {
  const { name, phone, password } = req.body;
  if (!name || !phone || !password)
    return res.status(400).json({ error: "All fields required" });
  if (db.users.find((u) => u.phone === phone))
    return res.status(400).json({ error: "Phone already registered" });

  const user = {
    id: uuidv4(),
    name,
    phone,
    password: await bcrypt.hash(password, 10),
    role: "worker",
    balance: 0,
    createdAt: new Date().toISOString(),
  };
  db.users.push(user);

  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, user: { id: user.id, name, phone, role: "worker", balance: 0 } });
});

// POST /api/auth/login
app.post("/api/auth/login", async (req, res) => {
  const { phone, password } = req.body;
  const user = db.users.find((u) => u.phone === phone);
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: "Invalid credentials" });

  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
  res.json({
    token,
    user: { id: user.id, name: user.name, phone: user.phone, role: user.role, balance: user.balance },
  });
});

// GET /api/auth/me
app.get("/api/auth/me", authMiddleware, (req, res) => {
  const user = findUser(req.user.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json({ id: user.id, name: user.name, phone: user.phone, role: user.role, balance: user.balance });
});

// ─── TASKS ROUTES ─────────────────────────────────────────────────────────────

// GET /api/tasks – workers see active tasks they haven't submitted
app.get("/api/tasks", authMiddleware, (req, res) => {
  const { category, status } = req.query;
  let tasks = db.tasks;

  if (req.user.role === "worker") {
    const submitted = db.submissions
      .filter((s) => s.workerId === req.user.id)
      .map((s) => s.taskId);
    tasks = tasks.filter((t) => t.status === "active" && !submitted.includes(t.id));
  }

  if (category && category !== "All") tasks = tasks.filter((t) => t.category === category);
  if (status) tasks = tasks.filter((t) => t.status === status);

  res.json(tasks);
});

// POST /api/tasks – admin creates a task
app.post("/api/tasks", authMiddleware, adminOnly, (req, res) => {
  const { title, description, link, reward, category, estimatedTime, totalSlots } = req.body;
  if (!title || !description || !link || !reward || !category || !totalSlots)
    return res.status(400).json({ error: "Missing required fields" });

  const task = {
    id: uuidv4(),
    title,
    description,
    link,
    reward: parseInt(reward),
    category,
    estimatedTime: estimatedTime || "5 min",
    totalSlots: parseInt(totalSlots),
    filledSlots: 0,
    status: "active",
    createdAt: new Date().toISOString(),
    createdBy: req.user.id,
  };
  db.tasks.push(task);
  res.json(task);
});

// PATCH /api/tasks/:id – admin updates task
app.patch("/api/tasks/:id", authMiddleware, adminOnly, (req, res) => {
  const task = db.tasks.find((t) => t.id === req.params.id);
  if (!task) return res.status(404).json({ error: "Task not found" });
  Object.assign(task, req.body);
  res.json(task);
});

// DELETE /api/tasks/:id – admin deletes task
app.delete("/api/tasks/:id", authMiddleware, adminOnly, (req, res) => {
  const idx = db.tasks.findIndex((t) => t.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Task not found" });
  db.tasks.splice(idx, 1);
  res.json({ success: true });
});

// ─── SUBMISSIONS ROUTES ───────────────────────────────────────────────────────

// GET /api/submissions – admin sees all, worker sees own
app.get("/api/submissions", authMiddleware, (req, res) => {
  let subs = db.submissions;
  if (req.user.role === "worker") {
    subs = subs.filter((s) => s.workerId === req.user.id);
  }
  // Enrich with task + worker info
  const enriched = subs.map((s) => ({
    ...s,
    task: db.tasks.find((t) => t.id === s.taskId) || null,
    worker: (() => {
      const w = findUser(s.workerId);
      return w ? { id: w.id, name: w.name, phone: w.phone } : null;
    })(),
  }));
  res.json(enriched.sort((a, b) => new Date(b.submittedAt) - new Date(a.submittedAt)));
});

// POST /api/submissions – worker submits proof
app.post("/api/submissions", authMiddleware, (req, res) => {
  if (req.user.role !== "worker") return res.status(403).json({ error: "Workers only" });
  const { taskId, proof } = req.body;
  if (!taskId || !proof) return res.status(400).json({ error: "taskId and proof required" });

  const task = db.tasks.find((t) => t.id === taskId);
  if (!task) return res.status(404).json({ error: "Task not found" });
  if (task.status !== "active") return res.status(400).json({ error: "Task is not active" });

  // Check duplicate
  if (db.submissions.find((s) => s.taskId === taskId && s.workerId === req.user.id))
    return res.status(400).json({ error: "Already submitted this task" });

  const sub = {
    id: uuidv4(),
    taskId,
    workerId: req.user.id,
    proof,
    status: "pending",
    reward: task.reward,
    submittedAt: new Date().toISOString(),
  };
  db.submissions.push(sub);

  // Update task slots
  task.filledSlots += 1;
  if (task.filledSlots >= task.totalSlots) task.status = "full";

  res.json(sub);
});

// PATCH /api/submissions/:id – admin approves/rejects
app.patch("/api/submissions/:id", authMiddleware, adminOnly, (req, res) => {
  const sub = db.submissions.find((s) => s.id === req.params.id);
  if (!sub) return res.status(404).json({ error: "Submission not found" });

  const { status } = req.body;
  if (!["approved", "rejected"].includes(status))
    return res.status(400).json({ error: "Status must be approved or rejected" });

  const prevStatus = sub.status;
  sub.status = status;
  sub.processedAt = new Date().toISOString();

  // Credit worker on approval
  if (status === "approved" && prevStatus === "pending") {
    const worker = findUser(sub.workerId);
    if (worker) worker.balance += sub.reward;
  }
  // Deduct if un-approving
  if (status === "rejected" && prevStatus === "approved") {
    const worker = findUser(sub.workerId);
    if (worker) worker.balance = Math.max(0, worker.balance - sub.reward);
  }

  res.json(sub);
});

// ─── WITHDRAWALS ROUTES ───────────────────────────────────────────────────────

// GET /api/withdrawals
app.get("/api/withdrawals", authMiddleware, (req, res) => {
  let wds = db.withdrawals;
  if (req.user.role === "worker") wds = wds.filter((w) => w.workerId === req.user.id);
  const enriched = wds.map((w) => ({
    ...w,
    worker: (() => {
      const u = findUser(w.workerId);
      return u ? { id: u.id, name: u.name, phone: u.phone } : null;
    })(),
  }));
  res.json(enriched.sort((a, b) => new Date(b.requestedAt) - new Date(a.requestedAt)));
});

// POST /api/withdrawals – worker requests
app.post("/api/withdrawals", authMiddleware, (req, res) => {
  if (req.user.role !== "worker") return res.status(403).json({ error: "Workers only" });
  const { amount, method, accountNo } = req.body;
  if (!amount || !method || !accountNo) return res.status(400).json({ error: "All fields required" });

  const worker = findUser(req.user.id);
  if (!worker) return res.status(404).json({ error: "User not found" });

  const amt = parseInt(amount);
  if (amt < 200) return res.status(400).json({ error: "Minimum withdrawal is Rs 200" });
  if (amt > worker.balance) return res.status(400).json({ error: "Insufficient balance" });

  // Hold balance
  worker.balance -= amt;

  const wd = {
    id: uuidv4(),
    workerId: req.user.id,
    amount: amt,
    method,
    accountNo,
    status: "pending",
    requestedAt: new Date().toISOString(),
  };
  db.withdrawals.push(wd);
  res.json(wd);
});

// PATCH /api/withdrawals/:id – admin marks paid/rejected
app.patch("/api/withdrawals/:id", authMiddleware, adminOnly, (req, res) => {
  const wd = db.withdrawals.find((w) => w.id === req.params.id);
  if (!wd) return res.status(404).json({ error: "Withdrawal not found" });

  const { status } = req.body;
  if (!["paid", "rejected"].includes(status))
    return res.status(400).json({ error: "Status must be paid or rejected" });

  // Refund if rejected
  if (status === "rejected" && wd.status === "pending") {
    const worker = findUser(wd.workerId);
    if (worker) worker.balance += wd.amount;
  }

  wd.status = status;
  wd.processedAt = new Date().toISOString();
  res.json(wd);
});

// ─── ADMIN STATS ──────────────────────────────────────────────────────────────

app.get("/api/admin/stats", authMiddleware, adminOnly, (req, res) => {
  const workers = db.users.filter((u) => u.role === "worker");
  const pendingSubs = db.submissions.filter((s) => s.status === "pending");
  const pendingWds = db.withdrawals.filter((w) => w.status === "pending");
  const totalPaid = db.withdrawals
    .filter((w) => w.status === "paid")
    .reduce((sum, w) => sum + w.amount, 0);
  const totalRewarded = db.submissions
    .filter((s) => s.status === "approved")
    .reduce((sum, s) => sum + s.reward, 0);

  res.json({
    totalWorkers: workers.length,
    activeTasks: db.tasks.filter((t) => t.status === "active").length,
    totalTasks: db.tasks.length,
    pendingSubmissions: pendingSubs.length,
    pendingWithdrawals: pendingWds.length,
    totalRewarded,
    totalPaid,
    totalSubmissions: db.submissions.length,
  });
});

// GET /api/admin/workers
app.get("/api/admin/workers", authMiddleware, adminOnly, (req, res) => {
  const workers = db.users.filter((u) => u.role === "worker").map((u) => ({
    id: u.id,
    name: u.name,
    phone: u.phone,
    balance: u.balance,
    createdAt: u.createdAt,
    submissionsCount: db.submissions.filter((s) => s.workerId === u.id).length,
    approvedCount: db.submissions.filter((s) => s.workerId === u.id && s.status === "approved").length,
  }));
  res.json(workers);
});

// ─── HEALTH CHECK ─────────────────────────────────────────────────────────────
app.get("/api/health", (req, res) => res.json({ status: "ok", timestamp: new Date().toISOString() }));

app.listen(PORT, () => {
  console.log(`✅ Review Rewards API running on http://localhost:${PORT}`);
  console.log(`   Admin login: 03001234567 / admin123`);
  console.log(`   Worker login: 03111234567 / worker123`);
});
