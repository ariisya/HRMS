const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'hrms.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  full_name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'HR',
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS companies(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS pos(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id INTEGER NOT NULL REFERENCES companies(id),
  name TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  UNIQUE(company_id, name)
);
CREATE TABLE IF NOT EXISTS sublocations(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pos_id INTEGER NOT NULL REFERENCES pos(id),
  name TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  UNIQUE(pos_id, name)
);
CREATE TABLE IF NOT EXISTS guards(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id INTEGER NOT NULL REFERENCES companies(id),
  nama TEXT NOT NULL,
  no_kp TEXT UNIQUE NOT NULL,
  jawatan TEXT,
  tarikh_masuk TEXT,
  tarikh_berhenti TEXT,
  tarikh_lahir TEXT,
  no_telefon TEXT,
  alamat TEXT,
  status_pengawal TEXT NOT NULL DEFAULT 'AKTIF',
  catatan TEXT
);
CREATE TABLE IF NOT EXISTS placements(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  guard_id INTEGER NOT NULL REFERENCES guards(id),
  company_id INTEGER NOT NULL,
  pos_id INTEGER NOT NULL REFERENCES pos(id),
  sub_id INTEGER REFERENCES sublocations(id),
  kategori_syif TEXT NOT NULL,
  tarikh_mula TEXT NOT NULL,
  tarikh_akhir TEXT,
  status_penempatan TEXT NOT NULL DEFAULT 'AKTIF',
  jenis_pergerakan TEXT,
  catatan TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_placement
  ON placements(guard_id) WHERE status_penempatan = 'AKTIF';
`);

// Seed companies and the first admin account
if (db.prepare('SELECT COUNT(*) c FROM companies').get().c === 0) {
  const ins = db.prepare('INSERT INTO companies(name) VALUES(?)');
  ['KRIS KAWALRAPI','FORMGATES','TWOFOUR FORCE','EHSAN','ORIENT','ZB','JANZ','BLUE BERET','AMIGIE']
    .forEach(n => ins.run(n));
}
if (db.prepare('SELECT COUNT(*) c FROM users').get().c === 0) {
  db.prepare('INSERT INTO users(username,password_hash,full_name,role) VALUES(?,?,?,?)')
    .run('admin', bcrypt.hashSync('admin123', 10), 'ADMINISTRATOR', 'ADMIN');
  console.log('Akaun pertama dibuat: admin / admin123 (sila tukar kata laluan)');
}

const app = express();
app.use(express.json({ limit: '25mb' }));
app.use(session({
  secret: 'tukar-teks-rahsia-ini-kepada-ayat-panjang-anda',
  resave: false,
  saveUninitialized: false,
  rolling: true, // setiap aktiviti menyegarkan masa tamat
  cookie: { maxAge: 2 * 60 * 60 * 1000, httpOnly: true, sameSite: 'lax' } // 2 jam tidak aktif
}));
app.use(express.static(path.join(__dirname, 'public')));

const EIGHT_HOURS = 8 * 60 * 60 * 1000;
const up = v => (v === undefined || v === null || v === '') ? null : String(v).trim().toUpperCase();
const today = () => new Date().toISOString().slice(0, 10);
const fail = (res, msg, code = 400) => res.status(code).json({ error: msg });

function auth(req, res, next) {
  const s = req.session;
  if (!s.user) return fail(res, 'Sila log masuk', 401);
  if (Date.now() - s.start > EIGHT_HOURS) {
    return req.session.destroy(() => fail(res, 'Sesi tamat', 401));
  }
  next();
}
const adminOnly = (req, res, next) =>
  req.session.user.role === 'ADMIN' ? next() : fail(res, 'Hanya ADMIN dibenarkan', 403);

// ---------- Login ----------
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(String(username || '').trim().toLowerCase());
  if (!u || !u.active || !bcrypt.compareSync(String(password || ''), u.password_hash)) {
    return fail(res, 'Nama pengguna atau kata laluan salah', 401);
  }
  req.session.user = { id: u.id, username: u.username, full_name: u.full_name, role: u.role };
  req.session.start = Date.now();
  res.json(req.session.user);
});
app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/me', auth, (req, res) => res.json(req.session.user));

// ---------- Users (ADMIN) ----------
app.get('/api/users', auth, adminOnly, (req, res) =>
  res.json(db.prepare('SELECT id,username,full_name,role,active FROM users ORDER BY username').all()));
app.post('/api/users', auth, adminOnly, (req, res) => {
  const { username, password, full_name, role } = req.body;
  if (!username || !password || !full_name) return fail(res, 'Lengkapkan semua maklumat');
  if (String(password).length < 6) return fail(res, 'Kata laluan minimum 6 aksara');
  try {
    db.prepare('INSERT INTO users(username,password_hash,full_name,role) VALUES(?,?,?,?)')
      .run(String(username).trim().toLowerCase(), bcrypt.hashSync(password, 10), up(full_name), role === 'ADMIN' ? 'ADMIN' : 'HR');
    res.json({ ok: true });
  } catch (e) { fail(res, 'Nama pengguna sudah wujud'); }
});
app.put('/api/users/:id', auth, adminOnly, (req, res) => {
  const { active, password } = req.body;
  if (active !== undefined) {
    if (Number(req.params.id) === req.session.user.id) return fail(res, 'Anda tidak boleh nyahaktif akaun sendiri');
    db.prepare('UPDATE users SET active=? WHERE id=?').run(active ? 1 : 0, req.params.id);
  }
  if (password) {
    if (String(password).length < 6) return fail(res, 'Kata laluan minimum 6 aksara');
    db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(bcrypt.hashSync(password, 10), req.params.id);
  }
  res.json({ ok: true });
});

// ---------- Companies, POS, Sub ----------
app.get('/api/companies', auth, (req, res) =>
  res.json(db.prepare('SELECT * FROM companies WHERE active=1 ORDER BY name').all()));

app.get('/api/pos', auth, (req, res) => {
  const { company_id, all } = req.query;
  let sql = `SELECT p.*, c.name AS company_name FROM pos p JOIN companies c ON c.id=p.company_id WHERE 1=1`;
  const args = [];
  if (company_id) { sql += ' AND p.company_id=?'; args.push(company_id); }
  if (!all) sql += ' AND p.active=1';
  res.json(db.prepare(sql + ' ORDER BY c.name, p.name').all(...args));
});
app.post('/api/pos', auth, adminOnly, (req, res) => {
  const { company_id, name } = req.body;
  if (!company_id || !name) return fail(res, 'Lengkapkan maklumat POS');
  try {
    db.prepare('INSERT INTO pos(company_id,name) VALUES(?,?)').run(company_id, up(name));
    res.json({ ok: true });
  } catch (e) { fail(res, 'POS ini sudah wujud untuk syarikat tersebut'); }
});
app.put('/api/pos/:id', auth, adminOnly, (req, res) => {
  db.prepare('UPDATE pos SET active=? WHERE id=?').run(req.body.active ? 1 : 0, req.params.id);
  res.json({ ok: true });
});
app.get('/api/subs', auth, (req, res) => {
  const { pos_id, all } = req.query;
  let sql = 'SELECT * FROM sublocations WHERE pos_id=?';
  if (!all) sql += ' AND active=1';
  res.json(db.prepare(sql + ' ORDER BY name').all(pos_id));
});
app.post('/api/subs', auth, adminOnly, (req, res) => {
  const { pos_id, name } = req.body;
  if (!pos_id || !name) return fail(res, 'Lengkapkan maklumat sub lokasi');
  try {
    db.prepare('INSERT INTO sublocations(pos_id,name) VALUES(?,?)').run(pos_id, up(name));
    res.json({ ok: true });
  } catch (e) { fail(res, 'Sub lokasi ini sudah wujud'); }
});
app.put('/api/subs/:id', auth, adminOnly, (req, res) => {
  db.prepare('UPDATE sublocations SET active=? WHERE id=?').run(req.body.active ? 1 : 0, req.params.id);
  res.json({ ok: true });
});

// ---------- Dashboard ----------
app.get('/api/dashboard', auth, (req, res) => {
  const count = sql => db.prepare(sql).get().c;
  res.json({
    total: count('SELECT COUNT(*) c FROM guards'),
    aktif: count("SELECT COUNT(*) c FROM guards WHERE status_pengawal='AKTIF'"),
    berhenti: count("SELECT COUNT(*) c FROM guards WHERE status_pengawal='BERHENTI'"),
    gantung: count("SELECT COUNT(*) c FROM guards WHERE status_pengawal='GANTUNG'"),
    syarikat: count('SELECT COUNT(*) c FROM companies WHERE active=1'),
    tanpaPenempatan: count(`SELECT COUNT(*) c FROM guards g WHERE g.status_pengawal='AKTIF'
      AND NOT EXISTS (SELECT 1 FROM placements p WHERE p.guard_id=g.id AND p.status_penempatan='AKTIF')`),
    mengikutSyarikat: db.prepare(`SELECT c.name, COUNT(g.id) total,
      SUM(g.status_pengawal='AKTIF') aktif FROM companies c
      LEFT JOIN guards g ON g.company_id=c.id GROUP BY c.id ORDER BY c.name`).all(),
    mengikutPOS: db.prepare(`SELECT c.name company, p.name pos, COUNT(pl.id) total
      FROM pos p JOIN companies c ON c.id=p.company_id
      LEFT JOIN placements pl ON pl.pos_id=p.id AND pl.status_penempatan='AKTIF'
      GROUP BY p.id ORDER BY total DESC, c.name LIMIT 15`).all()
  });
});

// ---------- Guards ----------
const ageOf = dob => {
  if (!dob) return null;
  const d = new Date(dob), n = new Date();
  let a = n.getFullYear() - d.getFullYear();
  if (n < new Date(n.getFullYear(), d.getMonth(), d.getDate())) a--;
  return a;
};

app.get('/api/guards', auth, (req, res) => {
  const { q, company_id, status } = req.query;
  let sql = `SELECT g.id,g.nama,g.no_kp,g.jawatan,g.status_pengawal,c.name company_name,
    p.name pos_name, s.name sub_name, pl.kategori_syif
    FROM guards g JOIN companies c ON c.id=g.company_id
    LEFT JOIN placements pl ON pl.guard_id=g.id AND pl.status_penempatan='AKTIF'
    LEFT JOIN pos p ON p.id=pl.pos_id
    LEFT JOIN sublocations s ON s.id=pl.sub_id WHERE 1=1`;
  const args = [];
  if (q) { sql += ' AND (g.nama LIKE ? OR g.no_kp LIKE ?)'; args.push(`%${q}%`, `%${q}%`); }
  if (company_id) { sql += ' AND g.company_id=?'; args.push(company_id); }
  if (status) { sql += ' AND g.status_pengawal=?'; args.push(status); }
  res.json(db.prepare(sql + ' ORDER BY g.nama LIMIT 500').all(...args));
});

app.get('/api/guards/:id', auth, (req, res) => {
  const g = db.prepare(`SELECT g.*, c.name company_name FROM guards g
    JOIN companies c ON c.id=g.company_id WHERE g.id=?`).get(req.params.id);
  if (!g) return fail(res, 'Pengawal tidak dijumpai', 404);
  g.umur = ageOf(g.tarikh_lahir);
  const history = db.prepare(`SELECT pl.*, c.name company_name, p.name pos_name, s.name sub_name
    FROM placements pl JOIN companies c ON c.id=pl.company_id
    JOIN pos p ON p.id=pl.pos_id LEFT JOIN sublocations s ON s.id=pl.sub_id
    WHERE pl.guard_id=? ORDER BY pl.tarikh_mula DESC, pl.id DESC`).all(g.id);
  res.json({ guard: g, history });
});

function guardFields(b) {
  return {
    nama: up(b.nama), jawatan: up(b.jawatan), tarikh_masuk: b.tarikh_masuk || null,
    tarikh_berhenti: b.tarikh_berhenti || null, tarikh_lahir: b.tarikh_lahir || null,
    no_telefon: b.no_telefon ? String(b.no_telefon).trim() : null,
    alamat: up(b.alamat), catatan: up(b.catatan)
  };
}
const cleanIC = v => String(v || '').replace(/\D/g, '');

app.post('/api/guards', auth, (req, res) => {
  const f = guardFields(req.body);
  const ic = cleanIC(req.body.no_kp);
  if (!f.nama) return fail(res, 'Nama diperlukan');
  if (ic.length !== 12) return fail(res, 'No KP mesti 12 digit');
  if (!req.body.company_id) return fail(res, 'Pilih syarikat');
  try {
    const r = db.prepare(`INSERT INTO guards(company_id,nama,no_kp,jawatan,tarikh_masuk,tarikh_lahir,no_telefon,alamat,catatan)
      VALUES(?,?,?,?,?,?,?,?,?)`).run(req.body.company_id, f.nama, ic, f.jawatan, f.tarikh_masuk, f.tarikh_lahir, f.no_telefon, f.alamat, f.catatan);
    res.json({ id: r.lastInsertRowid });
  } catch (e) { fail(res, 'No KP ini sudah wujud dalam sistem'); }
});

app.put('/api/guards/:id', auth, (req, res) => {
  const f = guardFields(req.body);
  const ic = cleanIC(req.body.no_kp);
  const status = ['AKTIF', 'BERHENTI', 'GANTUNG'].includes(req.body.status_pengawal) ? req.body.status_pengawal : 'AKTIF';
  if (!f.nama) return fail(res, 'Nama diperlukan');
  if (ic.length !== 12) return fail(res, 'No KP mesti 12 digit');
  try {
    db.transaction(() => {
      db.prepare(`UPDATE guards SET nama=?,no_kp=?,jawatan=?,tarikh_masuk=?,tarikh_berhenti=?,tarikh_lahir=?,
        no_telefon=?,alamat=?,catatan=?,status_pengawal=? WHERE id=?`)
        .run(f.nama, ic, f.jawatan, f.tarikh_masuk, f.tarikh_berhenti, f.tarikh_lahir, f.no_telefon, f.alamat, f.catatan, status, req.params.id);
      if (status === 'BERHENTI') { // pengawal berhenti: tamatkan penempatan, rekod kekal
        db.prepare(`UPDATE placements SET tarikh_akhir=?, status_penempatan='TAMAT', jenis_pergerakan='TAMAT PENEMPATAN'
          WHERE guard_id=? AND status_penempatan='AKTIF'`).run(f.tarikh_berhenti || today(), req.params.id);
      }
    })();
    res.json({ ok: true });
  } catch (e) { fail(res, 'No KP ini sudah digunakan oleh pengawal lain'); }
});

// ---------- Placement ----------
app.post('/api/guards/:id/place', auth, (req, res) => {
  const g = db.prepare('SELECT * FROM guards WHERE id=?').get(req.params.id);
  if (!g) return fail(res, 'Pengawal tidak dijumpai', 404);
  if (g.status_pengawal === 'BERHENTI') return fail(res, 'Pengawal telah berhenti');
  const { pos_id, sub_id, kategori_syif, tarikh, catatan } = req.body;
  if (!['SYIF PAGI', 'SYIF MALAM'].includes(kategori_syif)) return fail(res, 'Pilih kategori syif');
  const pos = db.prepare('SELECT * FROM pos WHERE id=? AND active=1 AND company_id=?').get(pos_id, g.company_id);
  if (!pos) return fail(res, 'POS tidak sah untuk syarikat pengawal ini');
  const subs = db.prepare('SELECT id FROM sublocations WHERE pos_id=? AND active=1').all(pos.id);
  let sid = null;
  if (subs.length) {
    if (!sub_id || !subs.some(s => s.id === Number(sub_id))) return fail(res, 'Pilih sub lokasi');
    sid = Number(sub_id);
  }
  const date = tarikh || today();
  db.transaction(() => {
    const cur = db.prepare("SELECT id FROM placements WHERE guard_id=? AND status_penempatan='AKTIF'").get(g.id);
    if (cur) {
      db.prepare("UPDATE placements SET tarikh_akhir=?, status_penempatan='TAMAT', jenis_pergerakan='PINDAH' WHERE id=?").run(date, cur.id);
    }
    db.prepare(`INSERT INTO placements(guard_id,company_id,pos_id,sub_id,kategori_syif,tarikh_mula,catatan)
      VALUES(?,?,?,?,?,?,?)`).run(g.id, g.company_id, pos.id, sid, kategori_syif, date, up(catatan));
  })();
  res.json({ ok: true });
});

app.post('/api/guards/:id/end-placement', auth, (req, res) => {
  const r = db.prepare(`UPDATE placements SET tarikh_akhir=?, status_penempatan='TAMAT', jenis_pergerakan='TAMAT PENEMPATAN'
    WHERE guard_id=? AND status_penempatan='AKTIF'`).run(req.body.tarikh || today(), req.params.id);
  if (!r.changes) return fail(res, 'Tiada penempatan aktif');
  res.json({ ok: true });
});
// ---------- Import / Export (Excel) ----------
const ExcelJS = require('exceljs');

const IMPORT_FIELDS = [
  { key: 'nama', label: 'NAMA', required: true },
  { key: 'no_kp', label: 'NO_KP', required: true },
  { key: 'jawatan', label: 'JAWATAN' },
  { key: 'tarikh_masuk', label: 'TARIKH_MASUK' },
  { key: 'tarikh_lahir', label: 'TARIKH_LAHIR' },
  { key: 'no_telefon', label: 'NO_TELEFON' },
  { key: 'alamat', label: 'ALAMAT' },
  { key: 'catatan', label: 'CATATAN' }
];
app.get('/api/import/fields', auth, (req, res) => res.json(IMPORT_FIELDS));

function cellText(v) {
  if (v === null || v === undefined) return '';
  if (v instanceof Date) return v.toISOString().slice(0, 10);
  if (typeof v === 'object') {
    if (v.result !== undefined) return cellText(v.result);
    if (v.text !== undefined) return String(v.text).trim();
    if (v.richText) return v.richText.map(r => r.text).join('').trim();
    return '';
  }
  return String(v).trim();
}
function toISODate(s) {
  if (!s) return null;
  if (/^\d{4}-\d{2}-\d{2}/.test(s)) return s.slice(0, 10);
  const m = String(s).match(/^(\d{1,2})[\/\-.](\d{1,2})[\/\-.](\d{2,4})$/);
  if (m) {
    let y = m[3];
    if (y.length === 2) y = (Number(y) > 30 ? '19' : '20') + y;
    return `${y}-${m[2].padStart(2, '0')}-${m[1].padStart(2, '0')}`;
  }
  return null;
}

// 1) Read the uploaded Excel file and send back headers and rows
app.post('/api/import/parse', auth, async (req, res) => {
  try {
    const buf = Buffer.from(String(req.body.data || ''), 'base64');
    const wb = new ExcelJS.Workbook();
    await wb.xlsx.load(buf);
    const ws = wb.worksheets[0];
    if (!ws) return fail(res, 'Fail kosong');
    const cols = ws.columnCount;
    const rows = [];
    ws.eachRow({ includeEmpty: false }, row => {
      const vals = [];
      for (let c = 1; c <= cols; c++) vals.push(cellText(row.getCell(c).value));
      if (vals.some(v => v !== '')) rows.push(vals);
    });
    if (rows.length < 2) return fail(res, 'Tiada data dijumpai dalam fail');
    if (rows.length > 10001) return fail(res, 'Terlalu banyak baris (maksimum 10000)');
    res.json({ headers: rows[0], rows: rows.slice(1) });
  } catch (e) {
    fail(res, 'Fail tidak dapat dibaca. Sila guna fail .xlsx');
  }
});

// 2) Check every record before saving (never overwrites existing guards)
function checkRecords(records) {
  const seen = new Set();
  const exists = db.prepare('SELECT id FROM guards WHERE no_kp=?');
  return records.map((r, i) => {
    let ic = String(r.no_kp || '').replace(/\D/g, '');
    if (ic.length === 11) ic = '0' + ic; // Excel sering buang sifar di depan
    const rec = {
      row: i + 1, nama: up(r.nama), no_kp: ic, jawatan: up(r.jawatan),
      tarikh_masuk: toISODate(r.tarikh_masuk), tarikh_lahir: toISODate(r.tarikh_lahir),
      no_telefon: r.no_telefon ? String(r.no_telefon).trim() : null,
      alamat: up(r.alamat), catatan: up(r.catatan)
    };
    let status = 'OK', msg = '';
    if (!rec.nama) { status = 'RALAT'; msg = 'Nama kosong'; }
    else if (ic.length !== 12) { status = 'RALAT'; msg = 'No KP mesti 12 digit'; }
    else if (exists.get(ic)) { status = 'DUPLIKAT'; msg = 'Sudah wujud dalam sistem'; }
    else if (seen.has(ic)) { status = 'DUPLIKAT'; msg = 'Berulang dalam fail'; }
    if (status === 'OK') {
      seen.add(ic);
      if ((r.tarikh_masuk && !rec.tarikh_masuk) || (r.tarikh_lahir && !rec.tarikh_lahir)) msg = 'Format tarikh tidak dikenali (diabaikan)';
    }
    return { ...rec, status, msg };
  });
}
app.post('/api/import/check', auth, (req, res) => {
  const { records } = req.body;
  if (!Array.isArray(records) || !records.length) return fail(res, 'Tiada rekod');
  res.json(checkRecords(records));
});

// 3) Save only the OK records
app.post('/api/import/commit', auth, (req, res) => {
  const { company_id, records } = req.body;
  if (!Array.isArray(records) || !records.length) return fail(res, 'Tiada rekod');
  const company = db.prepare('SELECT id FROM companies WHERE id=? AND active=1').get(company_id);
  if (!company) return fail(res, 'Syarikat tidak sah');
  const checked = checkRecords(records);
  const ins = db.prepare(`INSERT INTO guards(company_id,nama,no_kp,jawatan,tarikh_masuk,tarikh_lahir,no_telefon,alamat,catatan)
    VALUES(?,?,?,?,?,?,?,?,?)`);
  let added = 0;
  db.transaction(() => {
    checked.filter(r => r.status === 'OK').forEach(r => {
      ins.run(company.id, r.nama, r.no_kp, r.jawatan, r.tarikh_masuk, r.tarikh_lahir, r.no_telefon, r.alamat, r.catatan);
      added++;
    });
  })();
  res.json({
    added,
    duplicates: checked.filter(r => r.status === 'DUPLIKAT').length,
    errors: checked.filter(r => r.status === 'RALAT').length
  });
});

// ---------- Export ----------
async function sendWorkbook(res, filename, sheetName, columns, rows) {
  const wb = new ExcelJS.Workbook();
  const ws = wb.addWorksheet(sheetName);
  ws.columns = columns;
  rows.forEach(r => ws.addRow(r));
  const head = ws.getRow(1);
  head.font = { bold: true, color: { argb: 'FFFFFFFF' } };
  head.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF0B1F3A' } };
  ws.views = [{ state: 'frozen', ySplit: 1 }];
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  await wb.xlsx.write(res);
  res.end();
}

app.get('/api/export/guards', auth, async (req, res) => {
  try {
    const { company_id, status } = req.query;
    let sql = `SELECT g.*, c.name company_name, p.name pos_name, s.name sub_name, pl.kategori_syif, pl.tarikh_mula
      FROM guards g JOIN companies c ON c.id=g.company_id
      LEFT JOIN placements pl ON pl.guard_id=g.id AND pl.status_penempatan='AKTIF'
      LEFT JOIN pos p ON p.id=pl.pos_id LEFT JOIN sublocations s ON s.id=pl.sub_id WHERE 1=1`;
    const args = [];
    if (company_id) { sql += ' AND g.company_id=?'; args.push(company_id); }
    if (status) { sql += ' AND g.status_pengawal=?'; args.push(status); }
    const rows = db.prepare(sql + ' ORDER BY c.name, g.nama').all(...args).map(g => ({ ...g, umur: ageOf(g.tarikh_lahir) }));
    const columns = [
      ['SYARIKAT','company_name',22], ['NAMA','nama',30], ['NO_KP','no_kp',16], ['JAWATAN','jawatan',18],
      ['TARIKH_MASUK','tarikh_masuk',14], ['TARIKH_BERHENTI','tarikh_berhenti',16], ['TARIKH_LAHIR','tarikh_lahir',14],
      ['UMUR','umur',8], ['NO_TELEFON','no_telefon',16], ['ALAMAT','alamat',40], ['STATUS_PENGAWAL','status_pengawal',16],
      ['POS','pos_name',22], ['SUB_LOKASI','sub_name',18], ['KATEGORI_SYIF','kategori_syif',14],
      ['TARIKH_MULA_PENEMPATAN','tarikh_mula',20], ['CATATAN','catatan',30]
    ].map(c => ({ header: c[0], key: c[1], width: c[2] }));
    await sendWorkbook(res, `senarai_pengawal_${today()}.xlsx`, 'Pengawal', columns, rows);
  } catch (e) { fail(res, 'Gagal eksport', 500); }
});

app.get('/api/export/history', auth, async (req, res) => {
  try {
    const rows = db.prepare(`SELECT c.name company_name, g.nama, g.no_kp, p.name pos_name, s.name sub_name,
      pl.kategori_syif, pl.tarikh_mula, pl.tarikh_akhir, pl.status_penempatan, pl.jenis_pergerakan, pl.catatan
      FROM placements pl JOIN guards g ON g.id=pl.guard_id JOIN companies c ON c.id=pl.company_id
      JOIN pos p ON p.id=pl.pos_id LEFT JOIN sublocations s ON s.id=pl.sub_id
      ORDER BY g.nama, pl.tarikh_mula, pl.id`).all();
    const columns = [
      ['SYARIKAT','company_name',22], ['NAMA','nama',30], ['NO_KP','no_kp',16], ['POS','pos_name',22],
      ['SUB_LOKASI','sub_name',18], ['KATEGORI_SYIF','kategori_syif',14], ['TARIKH_MULA','tarikh_mula',14],
      ['TARIKH_AKHIR','tarikh_akhir',14], ['STATUS_PENEMPATAN','status_penempatan',18],
      ['JENIS_PERGERAKAN','jenis_pergerakan',20], ['CATATAN','catatan',30]
    ].map(c => ({ header: c[0], key: c[1], width: c[2] }));
    await sendWorkbook(res, `sejarah_penempatan_${today()}.xlsx`, 'Sejarah', columns, rows);
  } catch (e) { fail(res, 'Gagal eksport', 500); }
});

app.get('/api/export/template', auth, async (req, res) => {
  const columns = IMPORT_FIELDS.map(f => ({ header: f.label, key: f.key, width: 20 }));
  const sample = { nama: 'AHMAD BIN ALI', no_kp: '900101015555', jawatan: 'PENGAWAL KESELAMATAN',
    tarikh_masuk: '2024-01-15', tarikh_lahir: '1990-01-01', no_telefon: '0123456789',
    alamat: 'NO 1 JALAN CONTOH', catatan: '' };
  await sendWorkbook(res, 'templat_import_pengawal.xlsx', 'Templat', columns, [sample]);
});

const PORT = 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`HRMS berjalan di http://localhost:${PORT}`));