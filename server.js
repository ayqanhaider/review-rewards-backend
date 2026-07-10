/**
 * Review Rewards Backend v2
 * Persistent storage via Supabase PostgreSQL
 * Free Email OTP via Nodemailer
 */

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { createClient } = require("@supabase/supabase-js");
const nodemailer = require("nodemailer");

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || "rr-secret-change-in-prod";

// ─── SUPABASE ─────────────────────────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ─── EMAIL (Nodemailer via Gmail) ─────────────────────────────────────────────
const mailer = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS, // Gmail App Password
  },
});

app.use(cors());
app.use(express.json());

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

const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// ─── AUTH: SEND OTP ──────────────────────────────────────────────────────────
app.post("/api/auth/send-otp", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });

  const otp = generateOTP();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 min

  // Save OTP
  await supabase.from("otps").insert({ email, otp, expires_at: expiresAt.toISOString() });

  // Send email
  try {
    await mailer.sendMail({
      from: `"Review Rewards" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Your Review Rewards OTP Code",
      html: `
        <div style="font-family:Arial,sans-serif;max-width:400px;margin:0 auto;background:#111;color:#fff;padding:32px;border-radius:12px">
          <h2 style="color:#99F775;margin-bottom:8px">Review Rewards</h2>
          <p style="color:#aaa;margin-bottom:24px">Your verification code:</p>
          <div style="background:#222;border-radius:8px;padding:20px;text-align:center;font-size:36px;font-weight:800;letter-spacing:8px;color:#99F775">${otp}</div>
          <p style="color:#666;font-size:13px;margin-top:16px">This code expires in 10 minutes. Do not share it with anyone.</p>
        </div>`,
    });
    res.json({ success: true, message: "OTP sent to email" });
  } catch (e) {
    console.error("Email error:", e.message);
    res.status(500).json({ error: "Failed to send email. Check email config." });
  }
});

// ─── AUTH: VERIFY OTP ─────────────────────────────────────────────────────────
app.post("/api/auth/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  const { data } = await supabase
    .from("otps")
    .select("*")
    .eq("email", email)
    .eq("otp", otp)
    .eq("used", false)
    .gte("expires_at", new Date().toISOString())
    .order("created_at", { ascending: false })
    .limit(1);

  if (!data || data.length === 0) return res.status(400).json({ error: "Invalid or expired OTP" });

  // Mark used
  await supabase.from("otps").update({ used: true }).eq("id", data[0].id);
  res.json({ success: true });
});

// ─── AUTH: REGISTER ───────────────────────────────────────────────────────────
app.post("/api/auth/register", async (req, res) => {
  const { name, email, phone, password, referralCode } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: "Required fields missing" });

  // Check existing
  const { data: existing } = await supabase.from("users").select("id").eq("email", email).limit(1);
  if (existing && existing.length > 0) return res.status(400).json({ error: "Email already registered" });

  const password_hash = await bcrypt.hash(password, 10);

  // Find referrer
  let referredBy = null;
  if (referralCode) {
    const { data: referrer } = await supabase.from("users").select("id").eq("referral_code", referralCode).limit(1);
    if (referrer && referrer.length > 0) referredBy = referrer[0].id;
  }

  const { data: user, error } = await supabase
    .from("users")
    .insert({ name, email, phone, password_hash, role: "worker", referred_by: referredBy })
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });

  // Give referral bonus to referrer
  if (referredBy) {
    await supabase.rpc("increment_balance", { user_id: referredBy, amount: 100 });
  }

  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, balance: user.balance, referral_code: user.referral_code } });
});

// ─── AUTH: LOGIN ──────────────────────────────────────────────────────────────
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const { data: users } = await supabase.from("users").select("*").eq("email", email).limit(1);
  const user = users?.[0];

  if (!user || !(await bcrypt.compare(password, user.password_hash)))
    return res.status(401).json({ error: "Invalid email or password" });

  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, phone: user.phone, role: user.role, balance: user.balance, referral_code: user.referral_code } });
});

// ─── AUTH: ME ─────────────────────────────────────────────────────────────────
app.get("/api/auth/me", authMiddleware, async (req, res) => {
  const { data: user } = await supabase.from("users").select("id,name,email,phone,role,balance,total_earned,referral_code,created_at").eq("id", req.user.id).single();
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json(user);
});

// ─── AUTH: UPDATE PROFILE ────────────────────────────────────────────────────
app.patch("/api/auth/profile", authMiddleware, async (req, res) => {
  const { name, phone, currentPassword, newPassword } = req.body;
  const { data: user } = await supabase.from("users").select("*").eq("id", req.user.id).single();
  if (!user) return res.status(404).json({ error: "User not found" });

  const updates = {};
  if (name) updates.name = name;
  if (phone) updates.phone = phone;

  if (newPassword) {
    if (!currentPassword) return res.status(400).json({ error: "Current password required" });
    if (!(await bcrypt.compare(currentPassword, user.password_hash)))
      return res.status(401).json({ error: "Current password incorrect" });
    updates.password_hash = await bcrypt.hash(newPassword, 10);
  }

  const { data: updated } = await supabase.from("users").update(updates).eq("id", req.user.id).select().single();
  res.json({ id: updated.id, name: updated.name, email: updated.email, phone: updated.phone });
});

// ─── TASKS ────────────────────────────────────────────────────────────────────
app.get("/api/tasks", authMiddleware, async (req, res) => {
  let query = supabase.from("tasks").select("*").order("created_at", { ascending: false });

  if (req.user.role === "worker") {
    // Get submitted task IDs
    const { data: subs } = await supabase.from("submissions").select("task_id").eq("worker_id", req.user.id);
    const submittedIds = subs?.map(s => s.task_id) || [];
    query = query.eq("status", "active");
    if (submittedIds.length > 0) query = query.not("id", "in", `(${submittedIds.map(id => `"${id}"`).join(",")})`);
  }

  if (req.query.category && req.query.category !== "All") query = query.eq("category", req.query.category);

  const { data } = await query;
  res.json(data || []);
});

app.post("/api/tasks", authMiddleware, adminOnly, async (req, res) => {
  const { title, description, link, reward, category, estimatedTime, totalSlots } = req.body;
  if (!title || !description || !link || !reward || !category || !totalSlots)
    return res.status(400).json({ error: "All fields required" });

  const { data, error } = await supabase.from("tasks").insert({
    title, description, link,
    reward: parseInt(reward),
    category,
    estimated_time: estimatedTime || "5 min",
    total_slots: parseInt(totalSlots),
    created_by: req.user.id,
  }).select().single();

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.patch("/api/tasks/:id", authMiddleware, adminOnly, async (req, res) => {
  const updates = {};
  const fields = ["title", "description", "link", "reward", "category", "estimated_time", "total_slots", "status"];
  fields.forEach(f => { if (req.body[f] !== undefined) updates[f] = req.body[f]; });
  if (req.body.estimatedTime) updates.estimated_time = req.body.estimatedTime;
  if (req.body.totalSlots) updates.total_slots = req.body.totalSlots;

  const { data, error } = await supabase.from("tasks").update(updates).eq("id", req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete("/api/tasks/:id", authMiddleware, adminOnly, async (req, res) => {
  await supabase.from("tasks").delete().eq("id", req.params.id);
  res.json({ success: true });
});

// ─── SUBMISSIONS ─────────────────────────────────────────────────────────────
app.get("/api/submissions", authMiddleware, async (req, res) => {
  let query = supabase.from("submissions").select(`*, task:tasks(title,category,reward), worker:users!submissions_worker_id_fkey(id,name,email,phone)`).order("submitted_at", { ascending: false });
  if (req.user.role === "worker") query = query.eq("worker_id", req.user.id);
  const { data } = await query;
  res.json(data || []);
});

app.post("/api/submissions", authMiddleware, async (req, res) => {
  if (req.user.role !== "worker") return res.status(403).json({ error: "Workers only" });
  const { taskId, proof } = req.body;

  const { data: task } = await supabase.from("tasks").select("*").eq("id", taskId).single();
  if (!task) return res.status(404).json({ error: "Task not found" });
  if (task.status !== "active") return res.status(400).json({ error: "Task not active" });

  const { data: existing } = await supabase.from("submissions").select("id").eq("task_id", taskId).eq("worker_id", req.user.id).limit(1);
  if (existing?.length > 0) return res.status(400).json({ error: "Already submitted" });

  const { data: sub, error } = await supabase.from("submissions").insert({ task_id: taskId, worker_id: req.user.id, proof, reward: task.reward }).select().single();
  if (error) return res.status(500).json({ error: error.message });

  // Update slots
  const newFilled = task.filled_slots + 1;
  const newStatus = newFilled >= task.total_slots ? "full" : "active";
  await supabase.from("tasks").update({ filled_slots: newFilled, status: newStatus }).eq("id", taskId);

  res.json(sub);
});

app.patch("/api/submissions/:id", authMiddleware, adminOnly, async (req, res) => {
  const { status } = req.body;
  if (!["approved", "rejected"].includes(status)) return res.status(400).json({ error: "Invalid status" });

  const { data: sub } = await supabase.from("submissions").select("*").eq("id", req.params.id).single();
  if (!sub) return res.status(404).json({ error: "Not found" });

  await supabase.from("submissions").update({ status, processed_at: new Date().toISOString() }).eq("id", req.params.id);

  if (status === "approved" && sub.status === "pending") {
    await supabase.from("users").update({
      balance: supabase.raw(`balance + ${sub.reward}`),
      total_earned: supabase.raw(`total_earned + ${sub.reward}`)
    }).eq("id", sub.worker_id);
    // Use RPC instead
    const { data: worker } = await supabase.from("users").select("balance,total_earned").eq("id", sub.worker_id).single();
    if (worker) {
      await supabase.from("users").update({ balance: worker.balance + sub.reward, total_earned: worker.total_earned + sub.reward }).eq("id", sub.worker_id);
    }
  }

  if (status === "rejected" && sub.status === "approved") {
    const { data: worker } = await supabase.from("users").select("balance").eq("id", sub.worker_id).single();
    if (worker) await supabase.from("users").update({ balance: Math.max(0, worker.balance - sub.reward) }).eq("id", sub.worker_id);
  }

  res.json({ success: true, status });
});

// ─── WITHDRAWALS ─────────────────────────────────────────────────────────────
app.get("/api/withdrawals", authMiddleware, async (req, res) => {
  let query = supabase.from("withdrawals").select(`*, worker:users!withdrawals_worker_id_fkey(id,name,email,phone)`).order("requested_at", { ascending: false });
  if (req.user.role === "worker") query = query.eq("worker_id", req.user.id);
  const { data } = await query;
  res.json(data || []);
});

app.post("/api/withdrawals", authMiddleware, async (req, res) => {
  if (req.user.role !== "worker") return res.status(403).json({ error: "Workers only" });
  const { amount, method, accountNo, accountName, bankName } = req.body;
  if (!amount || !method || !accountNo || !accountName) return res.status(400).json({ error: "All fields required" });

  const { data: worker } = await supabase.from("users").select("balance").eq("id", req.user.id).single();
  const amt = parseInt(amount);
  if (amt < 200) return res.status(400).json({ error: "Minimum withdrawal is Rs 200" });
  if (amt > worker.balance) return res.status(400).json({ error: "Insufficient balance" });

  await supabase.from("users").update({ balance: worker.balance - amt }).eq("id", req.user.id);

  const { data: wd, error } = await supabase.from("withdrawals").insert({
    worker_id: req.user.id, amount: amt, method, account_no: accountNo, account_name: accountName, bank_name: bankName || null
  }).select().single();

  if (error) return res.status(500).json({ error: error.message });
  res.json(wd);
});

app.patch("/api/withdrawals/:id", authMiddleware, adminOnly, async (req, res) => {
  const { status } = req.body;
  if (!["paid", "rejected"].includes(status)) return res.status(400).json({ error: "Invalid status" });

  const { data: wd } = await supabase.from("withdrawals").select("*").eq("id", req.params.id).single();
  if (!wd) return res.status(404).json({ error: "Not found" });

  if (status === "rejected" && wd.status === "pending") {
    const { data: worker } = await supabase.from("users").select("balance").eq("id", wd.worker_id).single();
    if (worker) await supabase.from("users").update({ balance: worker.balance + wd.amount }).eq("id", wd.worker_id);
  }

  await supabase.from("withdrawals").update({ status, processed_at: new Date().toISOString() }).eq("id", req.params.id);
  res.json({ success: true });
});

// ─── SUPPORT TICKETS ─────────────────────────────────────────────────────────
app.get("/api/support", authMiddleware, async (req, res) => {
  let query = supabase.from("support_tickets").select(`*, worker:users!support_tickets_worker_id_fkey(id,name,email)`).order("created_at", { ascending: false });
  if (req.user.role === "worker") query = query.eq("worker_id", req.user.id);
  const { data } = await query;
  res.json(data || []);
});

app.post("/api/support", authMiddleware, async (req, res) => {
  const { subject, message } = req.body;
  if (!subject || !message) return res.status(400).json({ error: "Subject and message required" });
  const { data, error } = await supabase.from("support_tickets").insert({ worker_id: req.user.id, subject, message }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.patch("/api/support/:id", authMiddleware, adminOnly, async (req, res) => {
  const { status } = req.body;
  await supabase.from("support_tickets").update({ status, resolved_at: status === "resolved" ? new Date().toISOString() : null }).eq("id", req.params.id);
  res.json({ success: true });
});

// ─── ADMIN STATS ─────────────────────────────────────────────────────────────
app.get("/api/admin/stats", authMiddleware, adminOnly, async (req, res) => {
  const [workers, tasks, subs, wds, tickets] = await Promise.all([
    supabase.from("users").select("id", { count: "exact" }).eq("role", "worker"),
    supabase.from("tasks").select("id,status", { count: "exact" }),
    supabase.from("submissions").select("id,status,reward"),
    supabase.from("withdrawals").select("id,status,amount"),
    supabase.from("support_tickets").select("id,status", { count: "exact" }).eq("status", "open"),
  ]);

  const pendingSubs = subs.data?.filter(s => s.status === "pending").length || 0;
  const pendingWds = wds.data?.filter(w => w.status === "pending").length || 0;
  const totalRewarded = subs.data?.filter(s => s.status === "approved").reduce((a, s) => a + s.reward, 0) || 0;
  const totalPaid = wds.data?.filter(w => w.status === "paid").reduce((a, w) => a + w.amount, 0) || 0;

  res.json({
    totalWorkers: workers.count || 0,
    activeTasks: tasks.data?.filter(t => t.status === "active").length || 0,
    totalTasks: tasks.count || 0,
    pendingSubmissions: pendingSubs,
    pendingWithdrawals: pendingWds,
    totalRewarded,
    totalPaid,
    openTickets: tickets.count || 0,
  });
});

app.get("/api/admin/workers", authMiddleware, adminOnly, async (req, res) => {
  const { data: workers } = await supabase.from("users").select("id,name,email,phone,balance,total_earned,referral_code,created_at").eq("role", "worker").order("created_at", { ascending: false });
  if (!workers) return res.json([]);

  const workerIds = workers.map(w => w.id);
  const { data: subs } = await supabase.from("submissions").select("worker_id,status").in("worker_id", workerIds);

  const enriched = workers.map(w => ({
    ...w,
    submissionsCount: subs?.filter(s => s.worker_id === w.id).length || 0,
    approvedCount: subs?.filter(s => s.worker_id === w.id && s.status === "approved").length || 0,
  }));
  res.json(enriched);
});

app.get("/api/health", (req, res) => res.json({ status: "ok", version: "2.0", db: "supabase" }));

app.listen(PORT, () => {
  console.log(`✅ Review Rewards API v2 running on port ${PORT}`);
  console.log(`   Database: Supabase PostgreSQL`);
});
