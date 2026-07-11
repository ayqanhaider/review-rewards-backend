/**
 * Review Rewards Backend v2 - Production Ready
 * Supabase PostgreSQL + Nodemailer OTP
 */

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { createClient } = require("@supabase/supabase-js");
const nodemailer = require("nodemailer");

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "rr-secret-change-in-prod";

// Fall back to your original hardcoded credentials if the environment variables are missing
const SUPABASE_URL = process.env.SUPABASE_URL || "https://yihqpvdsctuhbqzkovbg.supabase.co";
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InlpaHFwdmRzY3R1aGJxemtvdmJnIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc4MzY1ODM0OSwiZXhwIjoyMDk5MjM0MzQ5fQ.exDmVLAdKPOzvS2IzAIDahYkpiyqSwafXbV3p9ZHqkU";
const EMAIL_USER = process.env.EMAIL_USER || "review.1ewards@gmail.com";
const EMAIL_PASS = process.env.EMAIL_PASS || "lopa vmhe zssk btrl";

// Initialize Supabase safely with the fallbacks guaranteed above
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

const supabase = createClient(SUPABASE_URL || "https://placeholder.supabase.co", SUPABASE_SERVICE_KEY || "placeholder");

const mailer = nodemailer.createTransport({
  service: "gmail",
  auth: { 
    user: EMAIL_USER || "", 
    pass: EMAIL_PASS ? EMAIL_PASS.replace(/\s/g, "") : "" 
  },
});

app.use(cors());
app.use(express.json());

// ─── HELPERS ─────────────────────────────────────────────────────────────────
const auth = (req, res, next) => {
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
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin only" });
  }
  next();
};

const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// ─── RENDER HEALTH CHECKS ───────────────────────────────────────────────────
app.get("/", (req, res) => res.send("Review Rewards API is active and running."));
app.get("/api/health", (req, res) => res.json({ status: "ok", version: "2.0", db: "supabase" }));

// ─── SEND OTP ─────────────────────────────────────────────────────────────────
app.post("/api/auth/send-otp", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });
  
  const otp = generateOTP();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  
  try {
    const { error: dbError } = await supabase.from("otps").insert({ email, otp, expires_at: expiresAt });
    if (dbError) throw dbError;

    await mailer.sendMail({
      from: `"Review Rewards" <${EMAIL_USER}>`,
      to: email,
      subject: "Your Review Rewards Verification Code",
      html: `<div style="font-family:Arial,sans-serif;max-width:420px;margin:0 auto;background:#111;color:#fff;padding:32px;border-radius:12px">
        <h2 style="color:#99F775;margin-bottom:8px">Review Rewards</h2>
        <p style="color:#aaa;margin-bottom:24px">Your email verification code:</p>
        <div style="background:#1a1a1a;border-radius:10px;padding:24px;text-align:center;font-size:38px;font-weight:800;letter-spacing:10px;color:#99F775;border:1px solid #2a2a2a">${otp}</div>
        <p style="color:#666;font-size:13px;margin-top:16px">Expires in 10 minutes. Do not share this code with anyone.</p>
        <p style="color:#444;font-size:12px;margin-top:24px">Review Rewards — Earn money completing simple tasks</p>
      </div>`,
    });
    res.json({ success: true });
  } catch (e) {
    console.error("OTP send error:", e.message);
    res.status(500).json({ error: "Server failed to process or send verification code." });
  }
});

// ─── VERIFY OTP ───────────────────────────────────────────────────────────────
app.post("/api/auth/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  try {
    const { data, error } = await supabase.from("otps").select("*")
      .eq("email", email).eq("otp", otp).eq("used", false)
      .gte("expires_at", new Date().toISOString())
      .order("created_at", { ascending: false }).limit(1);
    
    if (error) throw error;
    if (!data?.length) return res.status(400).json({ error: "Invalid or expired code" });
    
    await supabase.from("otps").update({ used: true }).eq("id", data[0].id);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── REGISTER ─────────────────────────────────────────────────────────────────
app.post("/api/auth/register", async (req, res) => {
  const { name, email, phone, password, referralCode } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: "Name, email and password required" });
  
  try {
    const { data: existing } = await supabase.from("users").select("id").eq("email", email).limit(1);
    if (existing?.length) return res.status(400).json({ error: "Email already registered" });
    
    const password_hash = await bcrypt.hash(password, 10);
    let referredBy = null;
    
    if (referralCode) {
      const { data: ref } = await supabase.from("users").select("id").eq("referral_code", referralCode).limit(1);
      if (ref?.length) referredBy = ref[0].id;
    }
    
    const { data: user, error } = await supabase.from("users")
      .insert({ name, email, phone: phone || null, password_hash, role: "worker", referred_by: referredBy })
      .select().single();
      
    if (error) return res.status(500).json({ error: error.message });
    
    if (referredBy) {
      const { data: referrer } = await supabase.from("users").select("balance").eq("id", referredBy).single();
      if (referrer) await supabase.from("users").update({ balance: referrer.balance + 100 }).eq("id", referredBy);
    }
    
    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, balance: user.balance, referral_code: user.referral_code } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── LOGIN ────────────────────────────────────────────────────────────────────
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const { data: users } = await supabase.from("users").select("*").eq("email", email).limit(1);
    const user = users?.[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash)))
      return res.status(401).json({ error: "Invalid email or password" });
      
    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, phone: user.phone, role: user.role, balance: user.balance, referral_code: user.referral_code } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── ME ───────────────────────────────────────────────────────────────────────
app.get("/api/auth/me", auth, async (req, res) => {
  try {
    const { data: user } = await supabase.from("users")
      .select("id,name,email,phone,role,balance,total_earned,referral_code,created_at")
      .eq("id", req.user.id).single();
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── UPDATE PROFILE ───────────────────────────────────────────────────────────
app.patch("/api/auth/profile", auth, async (req, res) => {
  const { name, phone, currentPassword, newPassword } = req.body;
  try {
    const { data: user } = await supabase.from("users").select("*").eq("id", req.user.id).single();
    if (!user) return res.status(404).json({ error: "Not found" });
    
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
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── TASKS ────────────────────────────────────────────────────────────────────
app.get("/api/tasks", auth, async (req, res) => {
  try {
    let query = supabase.from("tasks").select("*").order("created_at", { ascending: false });
    if (req.user.role === "worker") {
      const { data: subs } = await supabase.from("submissions").select("task_id").eq("worker_id", req.user.id);
      const ids = subs?.map(s => s.task_id).filter(Boolean) || [];
      query = query.eq("status", "active");
      if (ids.length > 0) query = query.not("id", "in", `(${ids.map(id => `"${id}"`).join(",")})`);
    }
    if (req.query.category && req.query.category !== "All") query = query.eq("category", req.query.category);
    const { data } = await query;
    res.json(data || []);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/tasks", auth, adminOnly, async (req, res) => {
  const { title, description, link, reward, category, estimatedTime, totalSlots } = req.body;
  if (!title || !description || !link || !reward || !category || !totalSlots)
    return res.status(400).json({ error: "All fields required" });
    
  try {
    const { data, error } = await supabase.from("tasks").insert({
      title, description, link, reward: parseInt(reward), category,
      estimated_time: estimatedTime || "5 min", total_slots: parseInt(totalSlots), created_by: req.user.id,
    }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch("/api/tasks/:id", auth, adminOnly, async (req, res) => {
  const updates = {};
  const map = { title:"title", description:"description", link:"link", reward:"reward", category:"category", status:"status", estimatedTime:"estimated_time", totalSlots:"total_slots" };
  Object.entries(map).forEach(([k, v]) => { if (req.body[k] !== undefined) updates[v] = req.body[k]; });
  
  try {
    const { data, error } = await supabase.from("tasks").update(updates).eq("id", req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete("/api/tasks/:id", auth, adminOnly, async (req, res) => {
  try {
    await supabase.from("tasks").delete().eq("id", req.params.id);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── SUBMISSIONS ──────────────────────────────────────────────────────────────
app.get("/api/submissions", auth, async (req, res) => {
  try {
    let query = supabase.from("submissions")
      .select("*, task:tasks(title,category,reward), worker:users!submissions_worker_id_fkey(id,name,email,phone)")
      .order("submitted_at", { ascending: false });
    if (req.user.role === "worker") query = query.eq("worker_id", req.user.id);
    const { data } = await query;
    res.json(data || []);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/submissions", auth, async (req, res) => {
  if (req.user.role !== "worker") return res.status(403).json({ error: "Workers only" });
  const { taskId, proof } = req.body;
  
  try {
    const { data: task } = await supabase.from("tasks").select("*").eq("id", taskId).single();
    if (!task) return res.status(404).json({ error: "Task not found" });
    if (task.status !== "active") return res.status(400).json({ error: "Task not active" });
    
    const { data: existing } = await supabase.from("submissions").select("id").eq("task_id", taskId).eq("worker_id", req.user.id).limit(1);
    if (existing?.length) return res.status(400).json({ error: "Already submitted this task" });
    
    const { data: sub, error } = await supabase.from("submissions")
      .insert({ task_id: taskId, worker_id: req.user.id, proof, reward: task.reward }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    
    const newFilled = (task.filled_slots || 0) + 1;
    await supabase.from("tasks").update({ filled_slots: newFilled, status: newFilled >= task.total_slots ? "full" : "active" }).eq("id", taskId);
    res.json(sub);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch("/api/submissions/:id", auth, adminOnly, async (req, res) => {
  const { status } = req.body;
  if (!["approved", "rejected"].includes(status)) return res.status(400).json({ error: "Invalid status" });
  
  try {
    const { data: sub } = await supabase.from("submissions").select("*").eq("id", req.params.id).single();
    if (!sub) return res.status(404).json({ error: "Not found" });
    
    await supabase.from("submissions").update({ status, processed_at: new Date().toISOString() }).eq("id", req.params.id);
    
    if (status === "approved" && sub.status === "pending") {
      const { data: w } = await supabase.from("users").select("balance,total_earned").eq("id", sub.worker_id).single();
      if (w) await supabase.from("users").update({ balance: w.balance + sub.reward, total_earned: (w.total_earned||0) + sub.reward }).eq("id", sub.worker_id);
    }
    if (status === "rejected" && sub.status === "approved") {
      const { data: w } = await supabase.from("users").select("balance").eq("id", sub.worker_id).single();
      if (w) await supabase.from("users").update({ balance: Math.max(0, w.balance - sub.reward) }).eq("id", sub.worker_id);
    }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── WITHDRAWALS ──────────────────────────────────────────────────────────────
app.get("/api/withdrawals", auth, async (req, res) => {
  try {
    let query = supabase.from("withdrawals")
      .select("*, worker:users!withdrawals_worker_id_fkey(id,name,email,phone)")
      .order("requested_at", { ascending: false });
    if (req.user.role === "worker") query = query.eq("worker_id", req.user.id);
    const { data } = await query;
    res.json(data || []);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/withdrawals", auth, async (req, res) => {
  if (req.user.role !== "worker") return res.status(403).json({ error: "Workers only" });
  const { amount, method, accountNo, accountName, bankName } = req.body;
  if (!amount || !method || !accountNo || !accountName) return res.status(400).json({ error: "All fields required" });
  
  try {
    const { data: worker } = await supabase.from("users").select("balance").eq("id", req.user.id).single();
    const amt = parseInt(amount);
    if (amt < 200) return res.status(400).json({ error: "Minimum withdrawal is Rs 200" });
    if (amt > worker.balance) return res.status(400).json({ error: "Insufficient balance" });
    
    await supabase.from("users").update({ balance: worker.balance - amt }).eq("id", req.user.id);
    const { data: wd, error } = await supabase.from("withdrawals")
      .insert({ worker_id: req.user.id, amount: amt, method, account_no: accountNo, account_name: accountName, bank_name: bankName || null })
      .select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(wd);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch("/api/withdrawals/:id", auth, adminOnly, async (req, res) => {
  const { status } = req.body;
  if (!["paid", "rejected"].includes(status)) return res.status(400).json({ error: "Invalid status" });
  
  try {
    const { data: wd } = await supabase.from("withdrawals").select("*").eq("id", req.params.id).single();
    if (!wd) return res.status(404).json({ error: "Not found" });
    
    if (status === "rejected" && wd.status === "pending") {
      const { data: w } = await supabase.from("users").select("balance").eq("id", wd.worker_id).single();
      if (w) await supabase.from("users").update({ balance: w.balance + wd.amount }).eq("id", wd.worker_id);
    }
    await supabase.from("withdrawals").update({ status, processed_at: new Date().toISOString() }).eq("id", req.params.id);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── SUPPORT ──────────────────────────────────────────────────────────────────
app.get("/api/support", auth, async (req, res) => {
  try {
    let query = supabase.from("support_tickets")
      .select("*, worker:users!support_tickets_worker_id_fkey(id,name,email)")
      .order("created_at", { ascending: false });
    if (req.user.role === "worker") query = query.eq("worker_id", req.user.id);
    const { data } = await query;
    res.json(data || []);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/support", auth, async (req, res) => {
  const { subject, message } = req.body;
  if (!subject || !message) return res.status(400).json({ error: "Subject and message required" });
  
  try {
    const { data, error } = await supabase.from("support_tickets")
      .insert({ worker_id: req.user.id, subject, message }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch("/api/support/:id", auth, adminOnly, async (req, res) => {
  const { status } = req.body;
  try {
    await supabase.from("support_tickets").update({ status, resolved_at: status === "resolved" ? new Date().toISOString() : null }).eq("id", req.params.id);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── ADMIN STATS ──────────────────────────────────────────────────────────────
app.get("/api/admin/stats", auth, adminOnly, async (req, res) => {
  try {
    const [w, t, s, wd, tk] = await Promise.all([
      supabase.from("users").select("id", { count: "exact" }).eq("role", "worker"),
      supabase.from("tasks").select("id,status"),
      supabase.from("submissions").select("id,status,reward"),
      supabase.from("withdrawals").select("id,status,amount"),
      supabase.from("support_tickets").select("id,status", { count: "exact" }).eq("status", "open"),
    ]);
    res.json({
      totalWorkers: w.count || 0,
      activeTasks: t.data?.filter(x => x.status === "active").length || 0,
      totalTasks: t.data?.length || 0,
      pendingSubmissions: s.data?.filter(x => x.status === "pending").length || 0,
      pendingWithdrawals: wd.data?.filter(x => x.status === "pending").length || 0,
      totalRewarded: s.data?.filter(x => x.status === "approved").reduce((a, x) => a + x.reward, 0) || 0,
      totalPaid: wd.data?.filter(x => x.status === "paid").reduce((a, x) => a + x.amount, 0) || 0,
      openTickets: tk.count || 0,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/admin/workers", auth, adminOnly, async (req, res) => {
  try {
    const { data: workers } = await supabase.from("users")
      .select("id,name,email,phone,balance,total_earned,referral_code,created_at")
      .eq("role", "worker").order("created_at", { ascending: false });
      
    if (!workers || workers.length === 0) return res.json([]);
    
    const workerIds = workers.map(w => w.id);
    const { data: subs } = await supabase.from("submissions").select("worker_id,status").in("worker_id", workerIds);
    
    res.json(workers.map(w => ({
      ...w,
      submissionsCount: subs?.filter(s => s.worker_id === w.id).length || 0,
      approvedCount: subs?.filter(s => s.worker_id === w.id && s.status === "approved").length || 0,
    })));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Review Rewards API v2 listening on port ${PORT}`);
});
