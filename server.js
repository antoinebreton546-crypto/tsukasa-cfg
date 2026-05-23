// ================================================================
//  Tsukasa_strafe — Serveur de licences
//  Stack : Node.js + Express + better-sqlite3
//  Hébergement : Railway.app (gratuit) ou tout VPS
//  Variables d'environnement requises :
//    ADMIN_SECRET   → mot de passe admin (ex: "monMotDePasse42!")
//    PORT           → (optionnel, Railway l'injecte automatiquement)
// ================================================================

const express = require("express");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ── Base de données SQLite ──────────────────────────────────────
const db = new Database("licenses.db");

db.exec(`
  CREATE TABLE IF NOT EXISTS licenses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    key         TEXT    UNIQUE NOT NULL,
    hwid        TEXT    DEFAULT NULL,
    expires_at  INTEGER NOT NULL,
    note        TEXT    DEFAULT '',
    created_at  INTEGER DEFAULT (strftime('%s','now')),
    revoked     INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS check_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    key        TEXT NOT NULL,
    hwid       TEXT,
    ip         TEXT,
    result     TEXT,
    checked_at INTEGER DEFAULT (strftime('%s','now'))
  );
`);

// ── Middleware auth admin ───────────────────────────────────────
const ADMIN_SECRET = process.env.ADMIN_SECRET || "CHANGE_ME_NOW";

function requireAdmin(req, res, next) {
  const token = req.headers["x-admin-secret"] || req.query.secret;
  if (token !== ADMIN_SECRET) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// ── Générateur de clé ──────────────────────────────────────────
function generateKey() {
  const seg = () => crypto.randomBytes(3).toString("hex").toUpperCase();
  return `TSKS-${seg()}-${seg()}-${seg()}`;
}

// ══════════════════════════════════════════════════════════════════
//  ROUTE PUBLIQUE : vérification depuis l'exe
//  POST /verify
//  Body: { "key": "TSKS-XXXXXX-XXXXXX-XXXXXX", "hwid": "abc123" }
//  Réponse: { "valid": true/false, "expires_at": 1234567890, "message": "..." }
// ══════════════════════════════════════════════════════════════════
app.post("/verify", (req, res) => {
  const { key, hwid } = req.body;
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;

  if (!key || !hwid) {
    log(key, hwid, ip, "MISSING_FIELDS");
    return res.json({ valid: false, message: "Missing fields" });
  }

  const row = db.prepare("SELECT * FROM licenses WHERE key = ?").get(key);

  if (!row) {
    log(key, hwid, ip, "INVALID_KEY");
    return res.json({ valid: false, message: "Invalid key" });
  }

  if (row.revoked) {
    log(key, hwid, ip, "REVOKED");
    return res.json({ valid: false, message: "Key revoked" });
  }

  const now = Math.floor(Date.now() / 1000);
  if (row.expires_at !== 0 && row.expires_at < now) {
    log(key, hwid, ip, "EXPIRED");
    return res.json({ valid: false, message: "Key expired", expires_at: row.expires_at });
  }

  // HWID lock : si pas encore lié, on lie
  if (!row.hwid) {
    db.prepare("UPDATE licenses SET hwid = ? WHERE key = ?").run(hwid, key);
    log(key, hwid, ip, "OK_LINKED");
  } else if (row.hwid !== hwid) {
    log(key, hwid, ip, "HWID_MISMATCH");
    return res.json({ valid: false, message: "Hardware mismatch" });
  } else {
    log(key, hwid, ip, "OK");
  }

  return res.json({
    valid: true,
    expires_at: row.expires_at,
    message: row.expires_at === 0 ? "Lifetime" : "Valid",
  });
});

function log(key, hwid, ip, result) {
  try {
    db.prepare(
      "INSERT INTO check_log (key, hwid, ip, result) VALUES (?,?,?,?)"
    ).run(key || "", hwid || "", ip || "", result);
  } catch {}
}

// ══════════════════════════════════════════════════════════════════
//  ROUTES ADMIN
// ══════════════════════════════════════════════════════════════════

// Créer une ou plusieurs clés
// POST /admin/create
// Body: { "count": 1, "days": 30, "note": "client X" }
// days = 0 → lifetime
app.post("/admin/create", requireAdmin, (req, res) => {
  const count = Math.min(parseInt(req.body.count) || 1, 100);
  const days = parseInt(req.body.days) ?? 30;
  const note = (req.body.note || "").slice(0, 200);

  const expires_at =
    days === 0
      ? 0
      : Math.floor(Date.now() / 1000) + days * 86400;

  const stmt = db.prepare(
    "INSERT INTO licenses (key, expires_at, note) VALUES (?,?,?)"
  );
  const keys = [];
  for (let i = 0; i < count; i++) {
    const key = generateKey();
    stmt.run(key, expires_at, note);
    keys.push(key);
  }
  res.json({ created: keys });
});

// Lister toutes les clés
// GET /admin/keys
app.get("/admin/keys", requireAdmin, (req, res) => {
  const rows = db
    .prepare(
      `SELECT id, key, hwid, expires_at, note, created_at, revoked,
       (SELECT COUNT(*) FROM check_log WHERE check_log.key = licenses.key) as checks
       FROM licenses ORDER BY id DESC`
    )
    .all();
  res.json(rows);
});

// Révoquer une clé
// DELETE /admin/revoke/:key
app.delete("/admin/revoke/:key", requireAdmin, (req, res) => {
  db.prepare("UPDATE licenses SET revoked = 1 WHERE key = ?").run(req.params.key);
  res.json({ ok: true });
});

// Réactiver une clé révoquée
// POST /admin/restore/:key
app.post("/admin/restore/:key", requireAdmin, (req, res) => {
  db.prepare("UPDATE licenses SET revoked = 0 WHERE key = ?").run(req.params.key);
  res.json({ ok: true });
});

// Prolonger / modifier l'expiration
// PATCH /admin/extend/:key
// Body: { "days": 30 }  (ajoute 30 jours depuis maintenant)
app.patch("/admin/extend/:key", requireAdmin, (req, res) => {
  const days = parseInt(req.body.days);
  if (isNaN(days)) return res.status(400).json({ error: "Invalid days" });
  const now = Math.floor(Date.now() / 1000);
  // Prolonge depuis la date d'expiration actuelle si dans le futur, sinon depuis maintenant
  const row = db.prepare("SELECT expires_at FROM licenses WHERE key = ?").get(req.params.key);
  if (!row) return res.status(404).json({ error: "Not found" });
  const base = row.expires_at === 0 ? now : Math.max(row.expires_at, now);
  const new_exp = days === 0 ? 0 : base + days * 86400;
  db.prepare("UPDATE licenses SET expires_at = ? WHERE key = ?").run(new_exp, req.params.key);
  res.json({ ok: true, expires_at: new_exp });
});

// Déverrouiller HWID (permet à l'utilisateur de changer de PC)
// POST /admin/reset-hwid/:key
app.post("/admin/reset-hwid/:key", requireAdmin, (req, res) => {
  db.prepare("UPDATE licenses SET hwid = NULL WHERE key = ?").run(req.params.key);
  res.json({ ok: true });
});

// Supprimer définitivement une clé
// DELETE /admin/delete/:key
app.delete("/admin/delete/:key", requireAdmin, (req, res) => {
  db.prepare("DELETE FROM licenses WHERE key = ?").run(req.params.key);
  db.prepare("DELETE FROM check_log WHERE key = ?").run(req.params.key);
  res.json({ ok: true });
});

// Stats globales
// GET /admin/stats
app.get("/admin/stats", requireAdmin, (req, res) => {
  const now = Math.floor(Date.now() / 1000);
  const total    = db.prepare("SELECT COUNT(*) as n FROM licenses").get().n;
  const active   = db.prepare("SELECT COUNT(*) as n FROM licenses WHERE revoked=0 AND (expires_at=0 OR expires_at>?)").get(now).n;
  const expired  = db.prepare("SELECT COUNT(*) as n FROM licenses WHERE expires_at!=0 AND expires_at<=?").get(now).n;
  const revoked  = db.prepare("SELECT COUNT(*) as n FROM licenses WHERE revoked=1").get().n;
  const checksToday = db.prepare(
    "SELECT COUNT(*) as n FROM check_log WHERE checked_at > ?"
  ).get(now - 86400).n;
  res.json({ total, active, expired, revoked, checksToday });
});

// Historique des vérifications d'une clé
// GET /admin/log/:key
app.get("/admin/log/:key", requireAdmin, (req, res) => {
  const rows = db
    .prepare("SELECT * FROM check_log WHERE key = ? ORDER BY checked_at DESC LIMIT 50")
    .all(req.params.key);
  res.json(rows);
});

// ── Démarrage ──────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ License server running on port ${PORT}`);
  if (ADMIN_SECRET === "CHANGE_ME_NOW") {
    console.warn("⚠️  ADMIN_SECRET non configuré ! Définissez la variable d'environnement.");
  }
});
