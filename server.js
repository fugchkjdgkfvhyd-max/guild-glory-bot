require("dotenv").config();
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const QRCode = require("qrcode");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA = path.join(ROOT, "data");
const UPLOADS = path.join(ROOT, "uploads");

fs.mkdirSync(DATA, {recursive:true});
fs.mkdirSync(UPLOADS, {recursive:true});

app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:"1mb"}));
app.use(express.urlencoded({extended:true}));

app.use(session({
  name:"rocks.sid",
  secret:process.env.SESSION_SECRET || "CHANGE_THIS_LOCAL_ONLY",
  resave:false,
  saveUninitialized:false,
  cookie:{
    httpOnly:true,
    sameSite:"lax",
    secure:process.env.NODE_ENV==="production",
    maxAge:1000*60*60*8
  }
}));

app.use("/api", rateLimit({
  windowMs:60*1000,
  limit:100,
  standardHeaders:true,
  legacyHeaders:false
}));

app.use(express.static(ROOT));
app.use("/uploads",(req,res)=>res.status(404).end());

const db = new Database(path.join(DATA,"rocks.sqlite"));
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 credits INTEGER NOT NULL DEFAULT 0,
 telegram_chat_id TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS payments(
 id TEXT PRIMARY KEY,
 user_id INTEGER NOT NULL,
 credits INTEGER NOT NULL,
 amount INTEGER NOT NULL,
 utr TEXT UNIQUE,
 receipt_path TEXT,
 status TEXT NOT NULL DEFAULT 'PENDING',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 reviewed_at TEXT,
 rejection_reason TEXT,
 FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS transactions(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 payment_id TEXT,
 amount INTEGER NOT NULL,
 type TEXT NOT NULL,
 note TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS telegram_codes(
 user_id INTEGER PRIMARY KEY,
 code TEXT NOT NULL UNIQUE,
 expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings(
 key TEXT PRIMARY KEY,
 value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS announcements(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 title TEXT NOT NULL,
 body TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

function setting(k, fallback=""){
  const r=db.prepare("SELECT value FROM settings WHERE key=?").get(k);
  return r?r.value:fallback;
}

function setSetting(k,v){
  db.prepare(`
    INSERT INTO settings(key,value) VALUES(?,?)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value
  `).run(k,String(v));
}

if(!setting("credit_price")) setSetting("credit_price",process.env.CREDIT_PRICE_INR||"150");
if(!setting("max_credits")) setSetting("max_credits",process.env.MAX_CREDITS_PER_ORDER||"10");
if(!setting("upi_id")) setSetting("upi_id",process.env.UPI_ID||"");
if(!setting("upi_name")) setSetting("upi_name",process.env.UPI_PAYEE_NAME||"");
if(!setting("maintenance")) setSetting("maintenance","false");

const upload = multer({
  storage:multer.diskStorage({
    destination:UPLOADS,
    filename:(req,file,cb)=>cb(
      null,
      crypto.randomUUID()+path.extname(file.originalname).toLowerCase()
    )
  }),
  limits:{fileSize:4*1024*1024},
  fileFilter:(req,file,cb)=>cb(
    null,
    ["image/png","image/jpeg","image/webp"].includes(file.mimetype)
  )
});

const safeUser = u=>({
  id:u.id,
  name:u.name,
  email:u.email,
  credits:u.credits,
  created_at:u.created_at
});

function constantTimeEqual(a,b){
  const x=Buffer.from(String(a));
  const y=Buffer.from(String(b));
  return x.length===y.length && crypto.timingSafeEqual(x,y);
}

function requireUser(req,res,next){
  if(!req.session.userId){
    return res.status(401).json({error:"Please log in"});
  }
  next();
}function requireAdmin(req,res,next){
  if(!req.session.isAdmin){
    return res.status(403).json({error:"Owner admin access required"});
  }
  next();
}

async function telegramSend(chatId,text){
  const token=process.env.TELEGRAM_BOT_TOKEN;
  if(!token||!chatId)return;

  try{
    await fetch(`https://api.telegram.org/bot${token}/sendMessage`,{
      method:"POST",
      headers:{"content-type":"application/json"},
      body:JSON.stringify({chat_id:chatId,text})
    });
  }catch(e){
    console.error("Telegram send failed");
  }
}

function notifyUser(userId,text){
  const u=db.prepare(
    "SELECT telegram_chat_id FROM users WHERE id=?"
  ).get(userId);

  if(u?.telegram_chat_id){
    telegramSend(u.telegram_chat_id,text);
  }
}

app.use((req,res,next)=>{
  if(
    setting("maintenance")==="true" &&
    !req.path.startsWith("/admin") &&
    !req.path.startsWith("/api/admin") &&
    req.path!=="/api/me"
  ){
    return res.status(503).send(
      "ROCKS GUILD GLORY BOT is temporarily under maintenance."
    );
  }
  next();
});

// AUTH

app.post("/api/register",async(req,res)=>{
  const {name,email,password}=req.body||{};

  if(!name||!email||!password||String(password).length<8){
    return res.status(400).json({
      error:"Enter name, valid email and password (at least 8 characters)."
    });
  }

  try{
    const hash=await bcrypt.hash(password,12);

    const info=db.prepare(`
      INSERT INTO users(name,email,password_hash)
      VALUES(?,?,?)
    `).run(
      String(name).slice(0,60),
      String(email).toLowerCase().trim(),
      hash
    );

    req.session.userId=info.lastInsertRowid;

    res.json({
      user:safeUser(
        db.prepare("SELECT * FROM users WHERE id=?")
          .get(info.lastInsertRowid)
      )
    });
  }catch(e){
    res.status(409).json({
      error:"That email may already be registered."
    });
  }
});

app.post("/api/login",async(req,res)=>{
  const u=db.prepare(
    "SELECT * FROM users WHERE email=?"
  ).get(String(req.body?.email||"").toLowerCase().trim());

  if(
    !u ||
    !await bcrypt.compare(
      String(req.body?.password||""),
      u.password_hash
    )
  ){
    return res.status(401).json({
      error:"Incorrect email or password"
    });
  }

  req.session.userId=u.id;
  res.json({user:safeUser(u)});
});

app.post("/api/logout",(req,res)=>{
  req.session.destroy(()=>res.json({ok:true}));
});

app.get("/api/me",requireUser,(req,res)=>{
  const u=db.prepare(
    "SELECT * FROM users WHERE id=?"
  ).get(req.session.userId);

  if(!u){
    return res.status(401).json({error:"Account not found"});
  }

  res.json({user:safeUser(u)});
});

// ADMIN LOGIN

app.post("/api/admin/login",async(req,res)=>{
  const {email,password,pin}=req.body||{};

  const ok=
    process.env.ADMIN_EMAIL &&
    process.env.ADMIN_PASSWORD &&
    process.env.ADMIN_PIN &&
    String(email)===process.env.ADMIN_EMAIL &&
    String(password||"")===process.env.ADMIN_PASSWORD &&
    constantTimeEqual(pin||"",process.env.ADMIN_PIN);

  if(!ok){
    return res.status(401).json({
      error:"Invalid owner credentials"
    });
  }

  req.session.isAdmin=true;
  res.json({ok:true});
});

app.post("/api/admin/logout",requireAdmin,(req,res)=>{
  req.session.isAdmin=false;
  res.json({ok:true});
});

app.get("/api/admin/me",requireAdmin,(req,res)=>{
  res.json({admin:true});
});

// PUBLIC SETTINGS

app.get("/api/public/settings",(req,res)=>{
  res.json({
    creditPrice:Number(setting("credit_price","150")),
    maxCredits:Number(setting("max_credits","10")),
    upiConfigured:Boolean(setting("upi_id")),
    maintenance:setting("maintenance")==="true"
  });
});

// CREATE PAYMENT ORDER AND QR

app.post("/api/payments/create",requireUser,async(req,res)=>{
  const credits=Number(req.body?.credits);
  const max=Number(setting("max_credits","10"));
  const price=Number(setting("credit_price","150"));

  if(!Number.isInteger(credits)||credits<1||credits>max){
    return res.status(400).json({
      error:`Choose between 1 and ${max} credits`
    });
  }

  const upi=setting("upi_id");
  const name=setting("upi_name");

  if(!upi||!name){
    return res.status(503).json({
      error:"UPI details have not been configured by the owner."
    });
  }

  const amount=credits*price;
  const id="RGG-"+crypto.randomBytes(6).toString("hex").toUpperCase();

  const uri=
    `upi://pay?pa=${encodeURIComponent(upi)}`+
    `&pn=${encodeURIComponent(name)}`+
    `&am=${amount}&cu=INR`+
    `&tn=${encodeURIComponent("ROCKS "+id)}`;

  const qr=await QRCode.toDataURL(uri);

  db.prepare(`
    INSERT INTO payments(id,user_id,credits,amount)
    VALUES(?,?,?,?)
  `).run(id,req.session.userId,credits,amount);

  res.json({orderId:id,credits,amount,qr});
});

// SUBMIT PAYMENT RECEIPT

app.post(
  "/api/payments/:id/submit",
  requireUser,
  upload.single("receipt"),
  (req,res)=>{
    const p=db.prepare(`
      SELECT * FROM payments
      WHERE id=? AND user_id=?
    `).get(req.params.id,req.session.userId);

    if(!p||p.status!=="PENDING"){
      return res.status(404).json({
        error:"Payment order not found or already submitted"
      });
    }

    const utr=String(req.body?.utr||"").trim();

    if(utr.length<6||utr.length>80||!req.file){
      return res.status(400).json({
        error:"Enter a valid UTR and upload a screenshot"
      });
    }

    try{
      db.prepare(`
        UPDATE payments
        SET utr=?,receipt_path=?
        WHERE id=?
      `).run(utr,req.file.filename,p.id);

      telegramSend(
        process.env.TELEGRAM_ADMIN_CHAT_ID,
        `New payment submission\nOrder: ${p.id}\nCredits: ${p.credits}\nAmount: ₹${p.amount}\nUTR: ${utr}`
      );

      res.json({ok:true,status:"PENDING"});
    }catch(e){
      res.status(409).json({
        error:"This UTR may already have been submitted"
      });
    }
  }
);

app.get("/api/payments/mine",requireUser,(req,res)=>{
  res.json({
    payments:db.prepare(`
      SELECT id,credits,amount,utr,status,created_at,rejection_reason
      FROM payments
      WHERE user_id=?
      ORDER BY created_at DESC
    `).all(req.session.userId)
  });
});

// ADMIN PAYMENT MANAGEMENT

app.get("/api/admin/payments",requireAdmin,(req,res)=>{
  res.json({
    payments:db.prepare(`
      SELECT p.*,u.name,u.email
      FROM payments p
      JOIN users u ON u.id=p.user_id
      ORDER BY p.created_at DESC
    `).all()
  });
});

app.get("/api/admin/receipt/:id",requireAdmin,(req,res)=>{
  const p=db.prepare(
    "SELECT receipt_path FROM payments WHERE id=?"
  ).get(req.params.id);

  if(!p?.receipt_path)return res.status(404).end();

  res.sendFile(
    path.join(UPLOADS,path.basename(p.receipt_path))
  );
});app.post("/api/admin/payments/:id/review",requireAdmin,(req,res)=>{
  const {decision,reason}=req.body||{};

  const p=db.prepare(
    "SELECT * FROM payments WHERE id=?"
  ).get(req.params.id);

  if(!p||p.status!=="PENDING"||!p.utr||!p.receipt_path){
    return res.status(400).json({
      error:"Payment is not ready for review"
    });
  }

  if(!["ACCEPTED","REJECTED"].includes(decision)){
    return res.status(400).json({
      error:"Invalid decision"
    });
  }

  const tx=db.transaction(()=>{
    const fresh=db.prepare(
      "SELECT * FROM payments WHERE id=?"
    ).get(p.id);

    if(fresh.status!=="PENDING"){
      throw new Error("Already reviewed");
    }

    db.prepare(`
      UPDATE payments
      SET status=?,
          reviewed_at=CURRENT_TIMESTAMP,
          rejection_reason=?
      WHERE id=?
    `).run(
      decision,
      decision==="REJECTED"
        ? String(reason||"Payment not verified").slice(0,250)
        : null,
      p.id
    );

    if(decision==="ACCEPTED"){
      db.prepare(
        "UPDATE users SET credits=credits+? WHERE id=?"
      ).run(p.credits,p.user_id);

      db.prepare(`
        INSERT INTO transactions(user_id,payment_id,amount,type,note)
        VALUES(?,?,?,?,?)
      `).run(
        p.user_id,
        p.id,
        p.credits,
        "CREDIT",
        "Manual payment accepted"
      );
    }
  });

  try{
    tx();

    notifyUser(
      p.user_id,
      decision==="ACCEPTED"
        ? `Payment ${p.id} accepted. ${p.credits} credits added.`
        : `Payment ${p.id} was rejected. No credits were added.`
    );

    res.json({ok:true});
  }catch(e){
    res.status(409).json({error:e.message});
  }
});

app.get("/api/transactions/mine",requireUser,(req,res)=>{
  res.json({
    transactions:db.prepare(`
      SELECT amount,type,note,created_at
      FROM transactions
      WHERE user_id=?
      ORDER BY id DESC
    `).all(req.session.userId)
  });
});

// ADMIN SETTINGS AND USERS

app.get("/api/admin/settings",requireAdmin,(req,res)=>{
  res.json({
    creditPrice:Number(setting("credit_price","150")),
    maxCredits:Number(setting("max_credits","10")),
    upiId:setting("upi_id"),
    upiName:setting("upi_name"),
    maintenance:setting("maintenance")==="true"
  });
});

app.put("/api/admin/settings",requireAdmin,(req,res)=>{
  const {
    creditPrice,
    maxCredits,
    upiId,
    upiName,
    maintenance
  }=req.body||{};

  if(
    !Number.isInteger(Number(creditPrice))||
    Number(creditPrice)<1||
    !Number.isInteger(Number(maxCredits))||
    Number(maxCredits)<1||
    Number(maxCredits)>10
  ){
    return res.status(400).json({
      error:"Invalid price or credit limit"
    });
  }

  setSetting("credit_price",Number(creditPrice));
  setSetting("max_credits",Number(maxCredits));
  setSetting("upi_id",String(upiId||"").trim());
  setSetting("upi_name",String(upiName||"").trim());
  setSetting("maintenance",maintenance?"true":"false");

  res.json({ok:true});
});

app.get("/api/admin/users",requireAdmin,(req,res)=>{
  res.json({
    users:db.prepare(`
      SELECT id,name,email,credits,created_at
      FROM users
      ORDER BY id DESC
    `).all()
  });
});

app.post("/api/admin/users/:id/credits",requireAdmin,(req,res)=>{
  const amount=Number(req.body?.amount);

  if(
    !Number.isInteger(amount)||
    amount===0||
    Math.abs(amount)>100000
  ){
    return res.status(400).json({
      error:"Invalid credit adjustment"
    });
  }

  const tx=db.transaction(()=>{
    db.prepare(
      "UPDATE users SET credits=credits+? WHERE id=?"
    ).run(amount,req.params.id);

    db.prepare(`
      INSERT INTO transactions(user_id,amount,type,note)
      VALUES(?,?,?,?)
    `).run(
      req.params.id,
      Math.abs(amount),
      amount>0?"ADMIN_ADD":"ADMIN_REMOVE",
      "Owner adjustment"
    );
  });

  try{
    tx();
    res.json({ok:true});
  }catch(e){
    res.status(400).json({
      error:"Could not update credits"
    });
  }
});

app.get("/api/admin/summary",requireAdmin,(req,res)=>{
  res.json({
    users:db.prepare(
      "SELECT COUNT(*) n FROM users"
    ).get().n,

    pending:db.prepare(
      "SELECT COUNT(*) n FROM payments WHERE status='PENDING'"
    ).get().n,

    approved:db.prepare(
      "SELECT COUNT(*) n FROM payments WHERE status='ACCEPTED'"
    ).get().n
  });
});

// ANNOUNCEMENTS

app.get("/api/announcements",(req,res)=>{
  res.json({
    items:db.prepare(`
      SELECT id,title,body,created_at
      FROM announcements
      ORDER BY id DESC
      LIMIT 30
    `).all()
  });
});

app.post("/api/admin/announcements",requireAdmin,(req,res)=>{
  const {title,body}=req.body||{};

  if(!title||!body){
    return res.status(400).json({
      error:"Title and message required"
    });
  }

  db.prepare(
    "INSERT INTO announcements(title,body) VALUES(?,?)"
  ).run(
    String(title).slice(0,100),
    String(body).slice(0,1000)
  );

  res.json({ok:true});
});

// TELEGRAM ACCOUNT LINKING

app.post("/api/telegram/link-code",requireUser,(req,res)=>{
  const code=crypto.randomBytes(4).toString("hex").toUpperCase();
  const expires=Date.now()+10*60*1000;

  db.prepare(`
    INSERT INTO telegram_codes(user_id,code,expires_at)
    VALUES(?,?,?)
    ON CONFLICT(user_id)
    DO UPDATE SET code=excluded.code,expires_at=excluded.expires_at
  `).run(req.session.userId,code,expires);

  res.json({
    code,
    expiresInMinutes:10,
    botUsername:"Configure your bot username"
  });
});

app.post("/api/telegram/webhook",async(req,res)=>{
  const secret=req.get("x-telegram-bot-api-secret-token");

  if(
    !process.env.TELEGRAM_WEBHOOK_SECRET||
    secret!==process.env.TELEGRAM_WEBHOOK_SECRET
  ){
    return res.sendStatus(403);
  }

  const msg=req.body?.message;
  const chat=msg?.chat?.id;
  const text=String(msg?.text||"");

  if(chat&&text.startsWith("/link ")){
    const code=text.split(/\s+/)[1];

    const row=db.prepare(`
      SELECT * FROM telegram_codes
      WHERE code=? AND expires_at>?
    `).get(code,Date.now());

    if(row){
      db.prepare(
        "UPDATE users SET telegram_chat_id=? WHERE id=?"
      ).run(String(chat),row.user_id);

      db.prepare(
        "DELETE FROM telegram_codes WHERE user_id=?"
      ).run(row.user_id);

      await telegramSend(
        chat,
        "Your Telegram account is now linked to ROCKS GUILD GLORY BOT."
      );
    }else{
      await telegramSend(
        chat,
        "That link code is invalid or expired. Generate a new code from your website profile."
      );
    }
  }else if(chat&&text==="/start"){
    await telegramSend(
      chat,
      "Welcome to ROCKS GUILD GLORY BOT. Link your website account using /link YOUR_CODE."
    );
  }else if(chat&&text==="/help"){
    await telegramSend(
      chat,
      "Commands: /start, /help. Link your website account from the website profile."
    );
  }

  res.json({ok:true});
});

// EXTERNAL API - READ ONLY GET REQUESTS

const allowedPaths=[
  "/api/auth/me",
  "/api/pricing",
  "/api/client/my-groups",
  "/api/client/group-history",
  "/api/client/activity-log",
  "/api/client/notifications"
];

app.get("/api/external/:endpoint",requireUser,async(req,res)=>{
  const map={
    me:allowedPaths[0],
    pricing:allowedPaths[1],
    groups:allowedPaths[2],
    history:allowedPaths[3],
    activity:allowedPaths[4],
    notifications:allowedPaths[5]
  };

  const endpoint=map[req.params.endpoint];

  if(!endpoint){
    return res.status(404).json({
      error:"Unsupported endpoint"
    });
  }

  const base=(
    process.env.FFGLORY_API_BASE||"https://ffglory.pro"
  ).replace(/\/+$/,"");

  const key=process.env.FFGLORY_API_KEY;

  if(!key){
    return res.status(503).json({
      error:"External API key is not configured"
    });
  }

  try{
    const r=await fetch(base+endpoint,{
      headers:{
        "x-api-key":key,
        Accept:"application/json"
      },
      signal:AbortSignal.timeout(10000)
    });

    const body=await r.text();
    res.status(r.status).type("application/json").send(body);
  }catch(e){
    res.status(502).json({
      error:"External API unavailable"
    });
  }
});

// WEBSITE ROUTES

app.get("/admin",(req,res)=>{
  res.sendFile(path.join(ROOT,"admin.html"));
});

app.use((req,res)=>{
  if(req.path.startsWith("/api/")){
    return res.status(404).json({error:"API route not found"});
  }

  res.sendFile(path.join(ROOT,"index.html"));
});

// START SERVER

app.listen(PORT,()=>{
  console.log(
    `ROCKS GUILD GLORY BOT running on port ${PORT}`
  );
});