const express = require("express");
const path = require("path");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { Storage } = require("@google-cloud/storage");

const app = express();
const PORT = Number(process.env.PORT || 8080);

// ---- ENV VARS (set in Cloud Run) ----
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "adminpytch";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "123456"; // set in Cloud Run
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const MEDIA_BUCKET = process.env.MEDIA_BUCKET || "samplemedia1";

// Optional: set to custom domain later
const GCS_PUBLIC_BASE = process.env.GCS_PUBLIC_BASE || "https://storage.googleapis.com";

// ---- middleware ----
app.disable("x-powered-by");
app.use((req, res, next) => {
  res.removeHeader("Accept-CH");
  res.removeHeader("Critical-CH");
  next();
});

app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// ---- static apps ----
const root = __dirname;
app.use(express.static(root));

function serveIndex(appName) {
  return (req, res) => res.sendFile(path.join(root, "apps", appName, "index.html"));
}

app.get("/", serveIndex("storefront"));
app.get(["/storefront", "/storefront/"], serveIndex("storefront"));
app.get(["/admin", "/admin/"], serveIndex("admin"));
app.get(["/dealer", "/dealer/"], serveIndex("dealer"));

app.get("/health", (req, res) => res.status(200).json({ ok: true }));

// ---- auth helpers ----
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "8h" });
}

function requireAuth(req, res, next) {
  const token = String(req.headers.authorization || "").replace("Bearer ", "").trim();
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// ---- TEMP in-memory DB (V2 demo) ----
// NOTE: Cloud Run instances can restart; this is demo-only.
// Next step: Firestore.
const db = {
  dealers: {
    dealerpytch: {
      dealerId: "dealerpytch",
      pin: "123456",
      name: "Demo Dealer",
      vehicles: {}
    }
  }
};

// ---- Admin APIs ----
app.post("/api/admin/login", (req, res) => {
  const { username, password } = req.body || {};
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    const token = signToken({ scope: "admin" });
    return res.json({ token, user: { username, scope: "admin" } });
  }
  return res.status(401).json({ error: "Invalid credentials" });
});

app.get("/api/admin/dealers", requireAuth, (req, res) => {
  if (req.user?.scope !== "admin") return res.status(403).json({ error: "Forbidden" });
  const dealers = Object.values(db.dealers).map(d => ({ dealerId: d.dealerId, name: d.name }));
  return res.json({ dealers });
});

app.post("/api/admin/dealers", requireAuth, (req, res) => {
  if (req.user?.scope !== "admin") return res.status(403).json({ error: "Forbidden" });

  const { dealerId, pin, name } = req.body || {};
  if (!dealerId || !pin) return res.status(400).json({ error: "dealerId and pin required" });
  if (db.dealers[dealerId]) return res.status(409).json({ error: "Dealer already exists" });

  db.dealers[dealerId] = { dealerId, pin: String(pin), name: name || dealerId, vehicles: {} };
  return res.json({ dealer: { dealerId, name: db.dealers[dealerId].name } });
});

app.post("/api/admin/reset-passcode", requireAuth, (req, res) => {
  if (req.user?.scope !== "admin") return res.status(403).json({ error: "Forbidden" });

  const { dealerId, newPin } = req.body || {};
  if (!dealerId || !newPin) return res.status(400).json({ error: "dealerId and newPin required" });

  const dealer = db.dealers[dealerId];
  if (!dealer) return res.status(404).json({ error: "Dealer not found" });

  dealer.pin = String(newPin);
  return res.json({ ok: true });
});

// ---- Dealer APIs ----
app.post("/api/dealer/login", (req, res) => {
  const { dealerId, pin } = req.body || {};
  const dealer = db.dealers[String(dealerId || "")];
  if (!dealer || dealer.pin !== String(pin)) return res.status(401).json({ error: "Invalid credentials" });

  const token = signToken({ scope: "dealer", dealerId: dealer.dealerId });
  return res.json({ token, dealer: { dealerId: dealer.dealerId, name: dealer.name } });
});

function requireDealerScope(req, res, next) {
  if (req.user?.scope !== "dealer") return res.status(403).json({ error: "Forbidden" });
  if (req.user?.dealerId !== req.params.dealerId) return res.status(403).json({ error: "Wrong dealer" });
  next();
}

function makeVehicleId() {
  return "veh_" + crypto.randomBytes(6).toString("hex");
}

app.get("/api/dealers/:dealerId/vehicles", requireAuth, requireDealerScope, (req, res) => {
  const dealer = db.dealers[req.params.dealerId];
  return res.json({ vehicles: Object.values(dealer.vehicles || {}) });
});

app.post("/api/dealers/:dealerId/vehicles", requireAuth, requireDealerScope, (req, res) => {
  const dealer = db.dealers[req.params.dealerId];
  const vehicleId = makeVehicleId();

  const v = {
    vehicleId,
    dealerId: dealer.dealerId,
    title: req.body?.title || "",
    make: req.body?.make || "",
    model: req.body?.model || "",
    year: Number(req.body?.year || "") || null,
    price: Number(req.body?.price || "") || 0,
    status: req.body?.status || "Draft",
    notes: req.body?.notes || "",
    media: { images: [], videos: [] },
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  dealer.vehicles[vehicleId] = v;
  return res.json({ vehicle: v });
});

// ---- Upload signing to GCS bucket (samplemedia1) ----
const storage = new Storage();
const bucket = storage.bucket(MEDIA_BUCKET);

app.post(
  "/api/dealers/:dealerId/vehicles/:vehicleId/uploads/sign",
  requireAuth,
  requireDealerScope,
  async (req, res) => {
    const { type, filename, contentType } = req.body || {};
    if (!type || !filename || !contentType) {
      return res.status(400).json({ error: "type, filename, contentType required" });
    }
    if (!["image", "video"].includes(type)) {
      return res.status(400).json({ error: "type must be image or video" });
    }

    const { dealerId, vehicleId } = req.params;
    const safeName = String(filename).replace(/[^\w.\-]+/g, "_");
    const folder = type === "image" ? "images/original" : "videos/original";
    const objectKey = `dealers/${dealerId}/vehicles/${vehicleId}/${folder}/${Date.now()}_${safeName}`;

    try {
      const file = bucket.file(objectKey);
      const [url] = await file.getSignedUrl({
        version: "v4",
        action: "write",
        expires: Date.now() + 10 * 60 * 1000,
        contentType
      });

      const publicUrl = `${GCS_PUBLIC_BASE}/${MEDIA_BUCKET}/${objectKey}`;
      return res.json({ url, objectKey, publicUrl });
    } catch (e) {
      return res.status(500).json({ error: "Failed to sign upload", details: e?.message || String(e) });
    }
  }
);

// ---- Public inventory ----
app.get("/api/public/vehicles", (req, res) => {
  const dealerId = req.query.dealerId ? String(req.query.dealerId) : "";
  let vehicles = [];

  if (dealerId) {
    const dealer = db.dealers[dealerId];
    vehicles = Object.values(dealer?.vehicles || {});
  } else {
    for (const d of Object.values(db.dealers)) vehicles.push(...Object.values(d.vehicles || {}));
  }

  vehicles = vehicles.filter(v => String(v.status || "").toLowerCase() === "published");
  return res.json({ vehicles });
});

// 404
app.use((req, res) => res.status(404).send("Not Found"));

app.listen(PORT, "0.0.0.0", () => console.log(`carsalessaas v2 listening on ${PORT}`));

process.on("unhandledRejection", (r) => console.error("unhandledRejection", r));
process.on("uncaughtException", (e) => console.error("uncaughtException", e));
