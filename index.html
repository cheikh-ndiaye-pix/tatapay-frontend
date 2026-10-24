const express   = require('express');
const cors      = require('cors');
const admin     = require('firebase-admin');
const crypto    = require('crypto');
const rateLimit = require('express-rate-limit');
const app       = express();

// ── VERCEL : derrière un proxy (nécessaire pour le rate limiting par IP) ──
app.set('trust proxy', 1);

// ── CORS SÉCURISÉ ──
const ALLOWED_ORIGINS = [
  'https://tatapay-a4972.web.app',
  'https://tatapay-a4972.firebaseapp.com',
  'https://tatapay-frontend.vercel.app',
  'http://localhost:8081',
  'http://localhost:19006',
  'exp://192.168.1.91:8081'
];
// Autorise aussi tous les déploiements de preview Vercel du même projet
const VERCEL_PREVIEW_REGEX = /^https:\/\/tatapay-frontend(-[a-z0-9-]+)?\.vercel\.app$/;

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin) || VERCEL_PREVIEW_REGEX.test(origin)) {
      return callback(null, true);
    }
    console.error('❌ CORS refusé pour origine:', origin);
    return callback(new Error('Non autorisé par CORS'));
  }
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// URL publique du backend (Vercel)
const BACKEND_URL = 'https://tatapay-frontend.vercel.app';

// ── VARIABLES D'ENVIRONNEMENT ──
const clean = (v) => (v || '').toString().trim().replace(/^["']+|["']+$/g, '').trim();

const PAYTECH_API_KEY    = clean(process.env.PAYTECH_API_KEY);
const PAYTECH_API_SECRET = clean(process.env.PAYTECH_API_SECRET);
const rawEnv      = clean(process.env.PAYTECH_ENV).toLowerCase();
const PAYTECH_ENV = ['prod', 'production', 'live'].includes(rawEnv) ? 'prod' : 'test';

console.log(
  '🔑 PayTech — clé:',
  PAYTECH_API_KEY ? PAYTECH_API_KEY.slice(0, 4) + '… (' + PAYTECH_API_KEY.length + ' car.)' : 'MANQUANTE ⚠️',
  '| secret:',
  PAYTECH_API_SECRET ? '(' + PAYTECH_API_SECRET.length + ' car.)' : 'MANQUANT ⚠️',
  '| env:', PAYTECH_ENV
);

// ── INTERRUPTEUR RETRAITS : tant que WITHDRAWALS_ENABLED n'est pas 'true', aucun virement réel ──
const WITHDRAWALS_ENABLED = clean(process.env.WITHDRAWALS_ENABLED).toLowerCase() === 'true';
const ADMIN_UID          = clean(process.env.ADMIN_UID);
const COMMISSION_RATE    = 0.02;

// ── FIREBASE (initialisation unique : Vercel réutilise les instances) ──
if (!admin.apps.length) {
  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}
const db = admin.firestore();

// ── RATE LIMITING ──
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Trop de requêtes, réessayez dans 15 minutes.' }
});
const ipnLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 50,
  message: { error: 'Trop de requêtes IPN' }
});

// ── MIDDLEWARE : VÉRIFICATION TOKEN FIREBASE ──
const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Non autorisé — token manquant' });
  }
  const token = authHeader.replace('Bearer ', '').trim();
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.uid = decoded.uid;
    next();
  } catch (e) {
    console.error('❌ Token invalide:', e.message);
    return res.status(401).json({ error: 'Token invalide ou expiré' });
  }
};

// ── MIDDLEWARE : VÉRIFICATION ADMIN ──
const verifyAdmin = async (req, res, next) => {
  if (!req.uid) return res.status(401).json({ error: 'Non autorisé' });
  if (req.uid !== ADMIN_UID) {
    return res.status(403).json({ error: 'Accès réservé à l\'administrateur' });
  }
  next();
};

// ── MIDDLEWARE : VÉRIFICATION PROPRIÉTAIRE ──
const verifyOwner = async (req, res, next) => {
  if (!req.uid) return res.status(401).json({ error: 'Non autorisé' });
  try {
    const userSnap = await db.collection('users').doc(req.uid).get();
    if (!userSnap.exists || userSnap.data().role !== 'owner') {
      return res.status(403).json({ error: 'Accès réservé aux propriétaires de bus' });
    }
    if (userSnap.data().status !== 'active') {
      return res.status(403).json({ error: 'Compte propriétaire non activé' });
    }
    req.ownerData = userSnap.data();
    next();
  } catch (e) {
    console.error('❌ verifyOwner:', e);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
};

// ── VALIDATION MONTANT ──
const validateAmount = (amount) => {
  const amt = parseInt(amount);
  if (!amt || !Number.isInteger(amt)) return false;
  if (amt < 100) return false;
  if (amt > 500000) return false;
  return amt;
};


const cut = (v, max = 80) => String(v == null ? '' : v).slice(0, max);

// Le `meta` d'un ticket vient du client : on ne garde que des champs connus, typés, sans undefined.
const cleanTicketMeta = (m) => {
  m = (m && typeof m === 'object') ? m : {};
  return {
    busUid: cut(m.busUid, 128), busId: cut(m.busId, 40),
    passengerId: cut(m.passengerId, 40), passengerName: cut(m.passengerName, 80),
    from: cut(m.from, 60), to: cut(m.to, 60), section: Number(m.section) || 0,
    gie: cut(m.gie), vehicle: cut(m.vehicle), ligne: cut(m.ligne), zone: cut(m.zone)
  };
};

const requirePaytechKeys = (req, res, next) => {
  if (!PAYTECH_API_KEY || !PAYTECH_API_SECRET) {
    console.error('🚨 Clés PayTech manquantes (PAYTECH_API_KEY / PAYTECH_API_SECRET).');
    return res.status(503).json({ error: 'Clé API PayTech manquante sur le serveur (configuration à vérifier)' });
  }
  next();
};

// ════════════════════════════════════════════════════════════
// ── ROUTES ──
// ════════════════════════════════════════════════════════════

app.get('/api', (req, res) => {
  res.json({
    message: 'TataPay Backend is running!',
    paytech_env: PAYTECH_ENV,
    paytech_keys: (PAYTECH_API_KEY && PAYTECH_API_SECRET) ? 'configurées' : 'MANQUANTES'
  });
});

app.get('/ping', (req, res) => res.json({ status: 'alive', time: new Date() }));

// ── INIT PAIEMENT PAYTECH ──
app.post('/api/payment/init', verifyToken, limiter, requirePaytechKeys, async (req, res) => {
  const { amount, phone, method, type, meta } = req.body;
  const uid = req.uid;

  const amt = validateAmount(amount);
  if (!amt) {
    return res.status(400).json({ error: 'Montant invalide (min 100, max 500 000 FCFA)' });
  }

  const allowedTypes = ['recharge', 'ticket'];
  if (!allowedTypes.includes(type)) {
    return res.status(400).json({ error: 'Type de paiement invalide' });
  }

  if (type === 'ticket') {
    if (!meta || typeof meta.busUid !== 'string' || !meta.busUid || meta.busUid === uid) {
      return res.status(400).json({ error: 'Receveur du ticket invalide' });
    }
    const busSnap = await db.collection('users').doc(meta.busUid).get();
    if (!busSnap.exists || busSnap.data().role !== 'receiver') {
      return res.status(400).json({ error: 'Receveur du ticket introuvable' });
    }
  }

  const refCommand = 'TTP-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8);

  await db.collection('paytech_transactions').doc(refCommand).set({
    uid,
    amount: amt,
    type:      type,
    method:    method || null,
    meta:      type === 'ticket' ? cleanTicketMeta(meta) : null,
    status:    'pending',
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  });

  const itemNames = {
    recharge: 'Recharge TataPay',
    ticket:   'Ticket TataPay',
    retrait:  'Retrait TataPay'
  };

  const payload = {
    item_name:       itemNames[type] || 'TataPay',
    item_price:      amt,
    currency:        'XOF',
    ref_command:     refCommand,
    command_name:    'TataPay Paiement',
    env:             PAYTECH_ENV,
    ipn_url:         BACKEND_URL + '/api/ipn',
    success_url:     'https://tatapay-a4972.web.app/success.html',
    cancel_url:      'https://tatapay-a4972.web.app/cancel.html',
    sender_phone:    phone || '',
    sender_country:  'SN',
    custom_field:    JSON.stringify({ uid, type, ref: refCommand })
  };

  if (method) {
    payload.channel = method;
  }

  try {
    const response = await fetch('https://paytech.sn/api/payment/request-payment', {
      method: 'POST',
      headers: {
        'API_KEY':      PAYTECH_API_KEY,
        'API_SECRET':   PAYTECH_API_SECRET,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    const rawText = await response.text();
    console.log('🔍 Statut PayTech:', response.status, '| env:', PAYTECH_ENV);
    console.log('🔍 Réponse PayTech:', rawText.slice(0, 500));

    let data;
    try {
      data = JSON.parse(rawText);
    } catch (e) {
      await db.collection('paytech_transactions').doc(refCommand).delete();
      return res.status(502).json({ error: 'Réponse invalide de PayTech' });
    }

    if (data.payment_url || data.redirect_url) {
      const url = data.payment_url || data.redirect_url;
      res.json({ payment_url: url, redirect_url: url, ref_command: refCommand });
    } else {
      await db.collection('paytech_transactions').doc(refCommand).delete();
      console.error('❌ PayTech a refusé la demande:', data);
      res.status(500).json({ error: 'Paiement refusé par PayTech' });
    }

  } catch (error) {
    console.error('❌ Erreur init paiement:', error);
    await db.collection('paytech_transactions').doc(refCommand).delete().catch(() => {});
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── MAPPING OPÉRATEUR → SERVICE PAYTECH ──
const SERVICE_MAP = {
  'wave':   'Wave Senegal',
  'orange': 'Orange Money Senegal',
  'free':   'Free Money'
};

// ── RETRAIT RÉEL VIA PAYTECH TRANSFER API ──
// Ordre sûr : 1) on RÉSERVE (débite) le montant dans une transaction,
// 2) on appelle PayTech, 3) si PayTech refuse, on REMBOURSE.
// Deux retraits simultanés ne peuvent donc jamais dépasser le solde.
app.post('/api/withdraw', verifyToken, limiter, requirePaytechKeys, async (req, res) => {
  if (!WITHDRAWALS_ENABLED) {
    return res.status(503).json({ error: 'Retraits temporairement désactivés' });
  }
  const { amount, phone, method, requestId } = req.body || {};
  const uid = req.uid;

  const amt = validateAmount(amount);
  if (!amt) return res.status(400).json({ error: 'Montant invalide (min 100, max 500 000 FCFA)' });
  const cleanPhone = String(phone || '').replace(/\s+/g, '');
  if (!/^\+?\d{8,15}$/.test(cleanPhone)) return res.status(400).json({ error: 'Numéro de téléphone invalide' });
  if (!SERVICE_MAP[method]) return res.status(400).json({ error: 'Opérateur invalide' });

  const service = SERVICE_MAP[method];
  // Idempotence : un même (uid, requestId) donne toujours le même retrait → un rejeu ne re-débite jamais.
  const reqId = (typeof requestId === 'string' && /^[A-Za-z0-9_-]{8,64}$/.test(requestId)) ? requestId : null;
  const externalId = reqId
    ? 'TTW-' + crypto.createHash('sha256').update(uid + ':' + reqId).digest('hex').slice(0, 24)
    : 'TTW-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex');
  const userRef = db.collection('users').doc(uid);
  const wdRef   = db.collection('withdrawals').doc(externalId);
  const histRef = userRef.collection('history').doc(externalId);

  // 1) Réservation atomique
  let replay = null;
  try {
    await db.runTransaction(async (t) => {
      replay = null;
      const [snap, wdSnap] = await Promise.all([t.get(userRef), t.get(wdRef)]);
      if (wdSnap.exists) { replay = wdSnap.data(); return; }
      if (!snap.exists) throw Object.assign(new Error('Utilisateur introuvable'), { http: 404 });
      const u = snap.data();
      if (!['approved', 'active'].includes(u.status)) throw Object.assign(new Error('Compte non validé'), { http: 403 });
      if ((u.balance || 0) < amt) throw Object.assign(new Error('Solde insuffisant'), { http: 400 });
      t.update(userRef, { balance: admin.firestore.FieldValue.increment(-amt) });
      t.set(wdRef, {
        ownerUid: uid, ownerName: u.name || '', amount: amt, phone: cleanPhone,
        operator: method, service, ref: externalId, status: 'reserved',
        ts: admin.firestore.FieldValue.serverTimestamp()
      });
      t.set(histRef, {
        type: 'withdraw', label: `Retrait ${service} — ${cleanPhone}`, amount: -amt,
        ref: externalId, status: 'pending', ts: admin.firestore.FieldValue.serverTimestamp()
      });
    });
  } catch (e) {
    if (!e.http) console.error('❌ Erreur réservation retrait:', e);
    return res.status(e.http || 500).json({ error: e.http ? e.message : 'Erreur serveur' });
  }

  // Rejeu d'une requête déjà traitée : on renvoie l'état existant, sans rien re-débiter.
  if (replay) {
    if (replay.status === 'refunded') return res.status(400).json({ error: 'Retrait refusé et remboursé', ref: externalId });
    if (replay.status === 'unknown')  return res.status(502).json({ error: 'Retrait en vérification', ref: externalId });
    return res.json({ message: 'Retrait en cours de traitement', ref: externalId, status: 'pending', success: true, replay: true });
  }

  // 2) Virement PayTech
  let data = null, httpStatus = 0;
  try {
    const response = await fetch('https://paytech.sn/api/transfer/transferFund', {
      method: 'POST',
      headers: { 'API_KEY': PAYTECH_API_KEY, 'API_SECRET': PAYTECH_API_SECRET, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        amount: amt, destination_number: cleanPhone, service,
        callback_url: BACKEND_URL + '/api/transfer-callback', external_id: externalId
      })
    });
    httpStatus = response.status;
    const rawText = await response.text();
    console.log('💸 Transfer PayTech:', httpStatus, rawText.slice(0, 400));
    try { data = JSON.parse(rawText); } catch (e) { data = null; }
  } catch (err) {
    console.error('❌ Erreur réseau PayTech:', err.message);
    // Statut inconnu : on NE rembourse PAS automatiquement (le virement est peut-être parti).
    await setWithdrawalStatus(externalId, 'unknown', { error: 'network' }, ['reserved']).catch(() => {});
    return res.status(502).json({ error: 'PayTech injoignable — retrait en vérification', ref: externalId });
  }

  if (data && data.success === 1) {
    await setWithdrawalStatus(externalId, 'sent', { transferId: data.transfer?.id_transfer || '' }, ['reserved', 'unknown']).catch(() => {});
    return res.json({ message: 'Retrait en cours de traitement', ref: externalId, status: 'pending', success: true });
  }

  // 3) Remboursement UNIQUEMENT sur refus explicite (JSON avec success 0/false, HTTP < 500).
  //    Réponse illisible ou erreur 5xx : le virement est peut-être parti → statut "unknown", à régler par l'admin.
  const clearRefusal = !!data && (data.success === 0 || data.success === false) && httpStatus < 500;
  if (clearRefusal) {
    await refundWithdrawal(externalId, cut(data.message, 120) || 'Refus PayTech');
    return res.status(400).json({ error: 'Retrait refusé par PayTech', ref: externalId });
  }
  await setWithdrawalStatus(externalId, 'unknown', { error: 'ambiguous_response', httpStatus }, ['reserved']).catch(() => {});
  return res.status(502).json({ error: 'Retrait en vérification', ref: externalId });
});

// Change le statut d'un retrait seulement s'il est encore dans un statut de départ autorisé
// (évite qu'un « sent » tardif n'écrase un « success » arrivé par callback).
async function setWithdrawalStatus(externalId, next, extra, allowedFrom) {
  const wdRef = db.collection('withdrawals').doc(externalId);
  await db.runTransaction(async (t) => {
    const s = await t.get(wdRef);
    if (!s.exists || !allowedFrom.includes(s.data().status)) return;
    t.update(wdRef, { status: next, ...(extra || {}) });
  });
}

// Marque un retrait comme réussi (callback PayTech ou admin). Si déjà remboursé : à vérifier à la main.
async function markWithdrawalSuccess(externalId) {
  const wdRef = db.collection('withdrawals').doc(externalId);
  await db.runTransaction(async (t) => {
    const s = await t.get(wdRef);
    if (!s.exists) return;
    const w = s.data();
    if (w.status === 'success') return;
    if (w.status === 'refunded') {
      t.update(wdRef, { needsReview: true, reviewReason: 'transfer_success reçu après remboursement' });
      console.error('🚨 Retrait', externalId, ': transfert réussi APRÈS remboursement — à vérifier');
      return;
    }
    t.update(wdRef, { status: 'success' });
    t.set(db.collection('users').doc(w.ownerUid).collection('history').doc(externalId), { status: 'success' }, { merge: true });
  });
}

// Rembourse un retrait une seule fois (idempotent)
async function refundWithdrawal(externalId, reason) {
  const wdRef = db.collection('withdrawals').doc(externalId);
  await db.runTransaction(async (t) => {
    const snap = await t.get(wdRef);
    if (!snap.exists) return;
    const w = snap.data();
    if (['refunded', 'success'].includes(w.status)) return;
    const userRef = db.collection('users').doc(w.ownerUid);
    t.update(userRef, { balance: admin.firestore.FieldValue.increment(w.amount) });
    t.set(userRef.collection('history').doc(externalId + '-R'), {
      type: 'refund', label: 'Remboursement retrait échoué', amount: w.amount,
      ref: externalId, ts: admin.firestore.FieldValue.serverTimestamp()
    });
    t.set(userRef.collection('history').doc(externalId), { status: 'refunded' }, { merge: true });
    t.update(wdRef, { status: 'refunded', reason, refundedAt: admin.firestore.FieldValue.serverTimestamp() });
  });
}

const safeEq = (a, b) => {
  const x = Buffer.from(String(a || '')), y = Buffer.from(String(b || ''));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

// ── CALLBACK TRANSFER PAYTECH ──
app.post('/api/transfer-callback', async (req, res) => {
  console.log('📩 Transfer callback reçu:', JSON.stringify(req.body));

  try {
    const {
      type_event,
      external_id,
      id_transfer,
      amount,
      service_name,
      state,
      destination_number,
      api_key_sha256,
      api_secret_sha256
    } = req.body;

    const expectedKeyHash    = crypto.createHash('sha256').update(PAYTECH_API_KEY).digest('hex');
    const expectedSecretHash = crypto.createHash('sha256').update(PAYTECH_API_SECRET).digest('hex');

    if (!safeEq(api_key_sha256, expectedKeyHash) || !safeEq(api_secret_sha256, expectedSecretHash)) {
      console.error('❌ Callback non authentifié');
      return res.status(403).send('Forbidden');
    }

    if (type_event === 'transfer_success') {
      console.log(`✅ Transfer confirmé : ${id_transfer} — ${amount} FCFA → ${destination_number}`);
      if (external_id) await markWithdrawalSuccess(String(external_id));
    } else if (type_event === 'transfer_failed') {
      console.error(`❌ Transfer échoué : ${id_transfer}`);
      if (external_id) await refundWithdrawal(String(external_id), 'transfer_failed');
    }

    res.status(200).send('OK');
  } catch (err) {
    console.error('❌ Erreur callback transfer:', err);
    res.status(500).send('Erreur');
  }
});

// ── IPN PAYTECH (sécurisé) ──
app.post('/api/ipn', ipnLimiter, async (req, res) => {
  console.log('📩 IPN reçu:', JSON.stringify({
    type_event:  req.body.type_event,
    ref_command: req.body.ref_command,
    item_price:  req.body.item_price
  }));

  try {
    const {
      type_event,
      ref_command,
      method,
      api_key_sha256,
      api_secret_sha256
    } = req.body;

    const expectedKeyHash    = crypto.createHash('sha256').update(PAYTECH_API_KEY).digest('hex');
    const expectedSecretHash = crypto.createHash('sha256').update(PAYTECH_API_SECRET).digest('hex');

    if (!safeEq(api_key_sha256, expectedKeyHash) || !safeEq(api_secret_sha256, expectedSecretHash)) {
      console.error('❌ IPN non authentifié — signature invalide');
      return res.status(403).send('Forbidden');
    }

    if (type_event !== 'sale_complete') {
      console.log('⏭️ Événement ignoré:', type_event);
      return res.status(200).send('OK');
    }

    const txRef = db.collection('paytech_transactions').doc(ref_command);

    await db.runTransaction(async (t) => {
      const txSnap = await t.get(txRef);

      if (!txSnap.exists) {
        console.error('❌ Transaction inconnue:', ref_command);
        return;
      }
      if (txSnap.data().status === 'credited') {
        console.log('⚠️ Déjà crédité:', ref_command);
        return;
      }

      const txData = txSnap.data();
      const { uid, amount, type, meta } = txData;

      if (!uid || !amount) {
        console.error('❌ uid ou amount manquant');
        return;
      }

      const userRef     = db.collection('users').doc(uid);
      const histRef     = db.collection('users').doc(uid).collection('history').doc();
      const finalMethod = method || txData.method || 'Mobile Money';

      if (type === 'recharge') {
        t.update(userRef, { balance: admin.firestore.FieldValue.increment(amount) });
        t.set(histRef, {
          type: 'recharge',
          label: `Recharge via ${finalMethod} — ${ref_command}`,
          amount, ref: ref_command,
          ts: admin.firestore.FieldValue.serverTimestamp()
        });
        console.log(`✅ Recharge : ${uid} +${amount} FCFA`);
      }

      else if (type === 'ticket' && meta) {
        const m = cleanTicketMeta(meta);
        const receiverRef = db.collection('users').doc(m.busUid || '_none_');
        const rSnap = m.busUid ? await t.get(receiverRef) : null;
        if (!rSnap || !rSnap.exists || rSnap.data().role !== 'receiver') {
          // Argent encaissé par PayTech mais receveur introuvable : on ne perd pas la trace, on ne boucle pas.
          t.update(txRef, { status: 'needs_review', reason: 'receveur introuvable' });
          console.error('🚨 IPN ticket', ref_command, ': receveur introuvable — à traiter manuellement');
          return;
        }
        const hasAdmin     = !!ADMIN_UID && ADMIN_UID !== m.busUid;
        const commission   = hasAdmin ? Math.round(amount * COMMISSION_RATE) : 0;
        const receiverAmt  = amount - commission;

        const pendingRef   = db.collection('pending').doc();
        const recvHistRef  = receiverRef.collection('history').doc();
        const commHistRef  = db.collection('commissions').doc();

        t.set(pendingRef, {
          busUid: m.busUid, busId: m.busId,
          passengerUid: uid, passengerId: m.passengerId,
          passengerName: m.passengerName,
          from: m.from, to: m.to,
          section: m.section, price: amount,
          commission, receiverAmt,
          method: finalMethod, gie: m.gie,
          vehicle: m.vehicle, ligne: m.ligne,
          zone: m.zone, ref: ref_command,
          paidAt: admin.firestore.FieldValue.serverTimestamp(),
          status: 'pending'
        });

        // Payé par Mobile Money : on ne débite PAS le portefeuille du passager.
        t.set(histRef, {
          type: 'ticket',
          label: `Ticket ${m.gie}/${m.vehicle} → ${m.to} (Mobile Money)`.slice(0, 120),
          amount: 0, paidExternal: amount, ref: ref_command,
          ts: admin.firestore.FieldValue.serverTimestamp()
        });

        t.update(receiverRef, { balance: admin.firestore.FieldValue.increment(receiverAmt) });
        t.set(recvHistRef, {
          type: 'collect',
          label: `Collecte ticket ${m.gie}/${m.vehicle} — ${ref_command}`.slice(0, 120),
          amount: receiverAmt, ref: ref_command,
          ts: admin.firestore.FieldValue.serverTimestamp()
        });

        if (hasAdmin && commission > 0) {
          const adminRef     = db.collection('users').doc(ADMIN_UID);
          const adminHistRef = adminRef.collection('history').doc();
          t.set(adminRef, { balance: admin.firestore.FieldValue.increment(commission) }, { merge: true });
          t.set(adminHistRef, {
            type: 'commission',
            label: `Commission — ${m.gie}/${m.vehicle} — ${ref_command}`.slice(0, 120),
            amount: commission, ref: ref_command,
            ts: admin.firestore.FieldValue.serverTimestamp()
          });
        }

        t.set(commHistRef, {
          ref: ref_command, amount, commission, receiverAmt,
          rate: COMMISSION_RATE, receiverUid: m.busUid,
          passengerUid: uid, gie: m.gie, vehicle: m.vehicle,
          ts: admin.firestore.FieldValue.serverTimestamp()
        });

        console.log(`✅ Ticket : ${uid} -${amount} FCFA | receveur +${receiverAmt} | TataPay +${commission}`);
      }

      t.update(txRef, {
        status: 'credited', method: finalMethod,
        creditedAt: admin.firestore.FieldValue.serverTimestamp()
      });
    });

    res.status(200).send('OK');

  } catch (err) {
    console.error('❌ Erreur IPN:', err);
    res.status(500).send('Erreur');
  }
});

// ════════════════════════════════════════════════════════════
// ── GESTION DES COMPTES ──
// ════════════════════════════════════════════════════════════

// ── PROPRIÉTAIRES ──

app.post('/api/owners/request', verifyToken, limiter, async (req, res) => {
  const uid = req.uid;
  const { name, phone, email, companyName, busCount } = req.body;
  if (!name || !phone || !email) {
    return res.status(400).json({ error: 'Nom, téléphone et email sont obligatoires' });
  }
  try {
    // create() échoue si le compte existe déjà : un solde ou un rôle existant n'est jamais écrasé.
    await db.collection('users').doc(uid).create({
      uid, name: cut(name, 80), phone: cut(phone, 20), email: cut(email, 120),
      companyName: cut(companyName, 100),
      busCount:    Math.min(Math.max(parseInt(busCount, 10) || 1, 1), 1000),
      role:        'owner',
      status:      'pending',
      balance:     0,
      createdAt:   admin.firestore.FieldValue.serverTimestamp()
    });
    console.log(`📋 Demande propriétaire : ${uid} (${name})`);
    res.json({ message: 'Demande envoyée. En attente de validation par l\'administrateur.' });
  } catch (err) {
    if (err.code === 6) return res.status(409).json({ error: 'Un compte existe déjà pour cet utilisateur' });
    console.error('❌ Erreur demande propriétaire:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/owners/status', verifyToken, async (req, res) => {
  try {
    const snap = await db.collection('users').doc(req.uid).get();
    if (!snap.exists || snap.data().role !== 'owner') {
      return res.status(404).json({ error: 'Aucune demande propriétaire trouvée' });
    }
    const d = snap.data();
    res.json({ status: d.status, name: d.name, email: d.email });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/owners/receivers', verifyToken, verifyOwner, async (req, res) => {
  try {
    const snap = await db.collection('users')
      .where('role', '==', 'receiver')
      .where('ownerUid', '==', req.uid)
      .where('status', '==', 'active')
      .get();
    const receivers = snap.docs.map(d => ({
      uid: d.id, name: d.data().name, phone: d.data().phone,
      email: d.data().email, balance: d.data().balance || 0, createdAt: d.data().createdAt
    }));
    res.json({ receivers });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/owners/receivers/pending', verifyToken, verifyOwner, async (req, res) => {
  try {
    const snap = await db.collection('users')
      .where('role', '==', 'receiver')
      .where('ownerUid', '==', req.uid)
      .where('status', '==', 'pending')
      .get();
    const pending = snap.docs.map(d => ({
      uid: d.id, name: d.data().name, phone: d.data().phone,
      email: d.data().email, createdAt: d.data().createdAt
    }));
    res.json({ pending });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/owners/receivers/:receiverUid/approve', verifyToken, verifyOwner, async (req, res) => {
  const { receiverUid } = req.params;
  try {
    const receiverSnap = await db.collection('users').doc(receiverUid).get();
    if (!receiverSnap.exists || receiverSnap.data().role !== 'receiver') {
      return res.status(404).json({ error: 'Receveur introuvable' });
    }
    if (receiverSnap.data().ownerUid !== req.uid) {
      return res.status(403).json({ error: 'Ce receveur ne vous appartient pas' });
    }
    await db.collection('users').doc(receiverUid).update({
      status: 'active', approvedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    console.log(`✅ Receveur approuvé : ${receiverUid} par ${req.uid}`);
    res.json({ message: 'Receveur approuvé avec succès' });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/owners/receivers/:receiverUid/reject', verifyToken, verifyOwner, async (req, res) => {
  const { receiverUid } = req.params;
  const { reason } = req.body;
  try {
    const receiverSnap = await db.collection('users').doc(receiverUid).get();
    if (!receiverSnap.exists || receiverSnap.data().role !== 'receiver') {
      return res.status(404).json({ error: 'Receveur introuvable' });
    }
    if (receiverSnap.data().ownerUid !== req.uid) {
      return res.status(403).json({ error: 'Ce receveur ne vous appartient pas' });
    }
    await db.collection('users').doc(receiverUid).update({
      status: 'rejected', rejectReason: reason || '',
      rejectedAt: admin.firestore.FieldValue.serverTimestamp(), rejectedBy: req.uid
    });
    console.log(`❌ Receveur refusé : ${receiverUid} par ${req.uid}`);
    res.json({ message: 'Demande du receveur refusée' });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/owners/revenues', verifyToken, verifyOwner, async (req, res) => {
  try {
    const receiversSnap = await db.collection('users')
      .where('role', '==', 'receiver')
      .where('ownerUid', '==', req.uid)
      .where('status', '==', 'active')
      .get();
    const revenues = [];
    for (const receiverDoc of receiversSnap.docs) {
      const receiverUid  = receiverDoc.id;
      const receiverData = receiverDoc.data();
      const histSnap = await db.collection('users').doc(receiverUid)
        .collection('history')
        .where('type', 'in', ['collect', 'collect_offline'])
        .get();
      let total = 0, count = 0;
      histSnap.docs.forEach(h => {
        const amt = h.data().amount || 0;
        if (amt > 0) { total += amt; count++; }
      });
      revenues.push({
        uid: receiverUid, name: receiverData.name, phone: receiverData.phone,
        balance: receiverData.balance || 0, totalEarned: total, tripCount: count
      });
    }
    res.json({ revenues });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── RECEVEURS ──

app.get('/api/receivers/owners', verifyToken, async (req, res) => {
  try {
    const snap = await db.collection('users')
      .where('role', '==', 'owner')
      .where('status', '==', 'active')
      .get();
    const owners = snap.docs.map(d => ({
      uid: d.id, name: d.data().name,
      companyName: d.data().companyName || '',
      busCount: d.data().busCount || 0, phone: d.data().phone
    }));
    res.json({ owners });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/receivers/request', verifyToken, limiter, async (req, res) => {
  const uid = req.uid;
  const { name, phone, email, ownerUid } = req.body;
  if (!name || !phone || !email || !ownerUid) {
    return res.status(400).json({ error: 'Nom, téléphone, email et propriétaire sont obligatoires' });
  }
  try {
    const ownerSnap = await db.collection('users').doc(ownerUid).get();
    if (!ownerSnap.exists || ownerSnap.data().role !== 'owner' || ownerSnap.data().status !== 'active') {
      return res.status(404).json({ error: 'Propriétaire introuvable ou inactif' });
    }
    await db.collection('users').doc(uid).create({
      uid, name: cut(name, 80), phone: cut(phone, 20), email: cut(email, 120), ownerUid,
      ownerName: ownerSnap.data().name,
      role:      'receiver',
      status:    'pending',
      balance:   0,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    console.log(`📋 Demande receveur : ${uid} (${name}) → propriétaire ${ownerUid}`);
    res.json({ message: 'Demande envoyée. En attente de validation par le propriétaire.' });
  } catch (err) {
    if (err.code === 6) return res.status(409).json({ error: 'Un compte existe déjà pour cet utilisateur' });
    console.error('❌ Erreur demande receveur:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/receivers/status', verifyToken, async (req, res) => {
  try {
    const snap = await db.collection('users').doc(req.uid).get();
    if (!snap.exists || snap.data().role !== 'receiver') {
      return res.status(404).json({ error: 'Aucune demande receveur trouvée' });
    }
    const d = snap.data();
    res.json({
      status: d.status, name: d.name, ownerName: d.ownerName,
      ownerUid: d.ownerUid, rejectReason: d.rejectReason || null
    });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── ADMINISTRATEUR ──

app.get('/api/admin/owners', verifyToken, verifyAdmin, async (req, res) => {
  const { status } = req.query;
  try {
    let query = db.collection('users').where('role', '==', 'owner');
    if (status) query = query.where('status', '==', status);
    const snap = await query.get();
    const owners = snap.docs.map(d => ({
      uid: d.id, name: d.data().name, phone: d.data().phone, email: d.data().email,
      companyName: d.data().companyName || '', busCount: d.data().busCount || 0,
      status: d.data().status, createdAt: d.data().createdAt
    }));
    res.json({ owners, total: owners.length });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/admin/owners/:ownerUid/approve', verifyToken, verifyAdmin, async (req, res) => {
  const { ownerUid } = req.params;
  try {
    const ownerSnap = await db.collection('users').doc(ownerUid).get();
    if (!ownerSnap.exists || ownerSnap.data().role !== 'owner') {
      return res.status(404).json({ error: 'Propriétaire introuvable' });
    }
    await db.collection('users').doc(ownerUid).update({
      status: 'active', approvedAt: admin.firestore.FieldValue.serverTimestamp(), approvedBy: req.uid
    });
    console.log(`✅ Propriétaire approuvé par admin : ${ownerUid}`);
    res.json({ message: 'Propriétaire approuvé avec succès' });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/admin/owners/:ownerUid/reject', verifyToken, verifyAdmin, async (req, res) => {
  const { ownerUid } = req.params;
  const { reason } = req.body;
  try {
    const ownerSnap = await db.collection('users').doc(ownerUid).get();
    if (!ownerSnap.exists || ownerSnap.data().role !== 'owner') {
      return res.status(404).json({ error: 'Propriétaire introuvable' });
    }
    await db.collection('users').doc(ownerUid).update({
      status: 'rejected', rejectReason: reason || '',
      rejectedAt: admin.firestore.FieldValue.serverTimestamp(), rejectedBy: req.uid
    });
    console.log(`❌ Propriétaire refusé par admin : ${ownerUid}`);
    res.json({ message: 'Propriétaire refusé' });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/admin/stats', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const [ownersSnap, receiversSnap, passengersSnap, txSnap] = await Promise.all([
      db.collection('users').where('role', '==', 'owner').get(),
      db.collection('users').where('role', '==', 'receiver').get(),
      db.collection('users').where('role', '==', 'passenger').get(),
      db.collection('paytech_transactions').where('status', '==', 'credited').get()
    ]);
    const ownersByStatus = { pending: 0, active: 0, rejected: 0 };
    ownersSnap.docs.forEach(d => {
      const s = d.data().status || 'pending';
      ownersByStatus[s] = (ownersByStatus[s] || 0) + 1;
    });
    const receiversByStatus = { pending: 0, active: 0, rejected: 0 };
    receiversSnap.docs.forEach(d => {
      const s = d.data().status || 'pending';
      receiversByStatus[s] = (receiversByStatus[s] || 0) + 1;
    });
    let totalVolume = 0;
    txSnap.docs.forEach(d => { totalVolume += d.data().amount || 0; });
    res.json({
      owners:       { total: ownersSnap.size,    ...ownersByStatus },
      receivers:    { total: receiversSnap.size, ...receiversByStatus },
      passengers:   { total: passengersSnap.size },
      transactions: { total: txSnap.size, totalVolume }
    });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.delete('/api/admin/owners/:ownerUid', verifyToken, verifyAdmin, async (req, res) => {
  const { ownerUid } = req.params;
  try {
    const batch = db.batch();
    const receiversSnap = await db.collection('users')
      .where('role', '==', 'receiver')
      .where('ownerUid', '==', ownerUid)
      .get();
    receiversSnap.docs.forEach(d => {
      batch.update(d.ref, { status: 'suspended', suspendedAt: admin.firestore.FieldValue.serverTimestamp() });
    });
    batch.delete(db.collection('users').doc(ownerUid));
    await batch.commit();
    console.log(`🗑️ Propriétaire supprimé par admin : ${ownerUid} | ${receiversSnap.size} receveur(s) suspendus`);
    res.json({ message: 'Propriétaire supprimé', receiversSuspended: receiversSnap.size });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── PROFIL UTILISATEUR ──

app.get('/api/profile', verifyToken, async (req, res) => {
  try {
    const snap = await db.collection('users').doc(req.uid).get();
    if (!snap.exists) return res.status(404).json({ error: 'Profil introuvable' });
    res.json(snap.data());
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/profile/history', verifyToken, async (req, res) => {
  const limit = parseInt(req.query.limit) || 20;
  try {
    const snap = await db.collection('users').doc(req.uid)
      .collection('history')
      .orderBy('ts', 'desc')
      .limit(limit)
      .get();
    const history = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    res.json({ history });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ════════════════════════════════════════════════════════════
// ── ASSISTANT IA GRATUIT (Google Gemini) ──
// Nécessite la variable d'environnement GEMINI_API_KEY sur Vercel.
// ════════════════════════════════════════════════════════════
const { GoogleGenAI } = require('@google/genai');

const GEMINI_API_KEY = clean(process.env.GEMINI_API_KEY);
let genAI = null;
if (!GEMINI_API_KEY) {
  console.error('🚨 GEMINI_API_KEY n\'est pas définie — la route /api/assistant est désactivée.');
} else {
  genAI = new GoogleGenAI({ apiKey: GEMINI_API_KEY });
}

const assistantLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 15,
  message: { error: 'Trop de requêtes, réessayez dans une minute.' }
});

const requireGeminiKey = (req, res, next) => {
  if (!genAI) {
    return res.status(503).json({ error: 'Assistant indisponible (configuration serveur manquante)' });
  }
  next();
};

app.post('/api/assistant', assistantLimiter, requireGeminiKey, async (req, res) => {
  const { question, lang } = req.body;
  if (!question || typeof question !== 'string' || !question.trim()) {
    return res.status(400).json({ error: 'Question manquante' });
  }
  if (question.length > 500) {
    return res.status(400).json({ error: 'Question trop longue (max 500 caractères)' });
  }

  const langLabel = lang === 'wo' ? 'wolof' : 'français';
  const systemPrompt =
    `Tu es l'assistant vocal de l'application TataPay (paiement de tickets de bus au Sénégal). ` +
    `Réponds UNIQUEMENT en ${langLabel}, en 2 à 4 phrases courtes et simples, adaptées à une lecture ` +
    `à voix haute. Explique clairement comment utiliser l'application (inscription, paiement, tickets, ` +
    `retraits, rôles passager/receveur/propriétaire/directeur). Si tu n'es pas sûr d'une information, ` +
    `dis-le simplement plutôt que d'inventer.`;

  try {
    const response = await genAI.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: question.trim(),
      config: { systemInstruction: systemPrompt }
    });

    const answer = (response.text || '…').trim();
    console.log(`🎙️ Assistant (${langLabel}) : "${question.slice(0,60)}" → ${answer.slice(0,80)}`);
    res.json({ answer, lang: lang === 'wo' ? 'wo' : 'fr' });

  } catch (err) {
    console.error('❌ Erreur assistant Gemini:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

/* ════════════════════════════════════════════════════════════════════
   PAIEMENT DE TICKET CÔTÉ SERVEUR (QR signé du passager)
   Variables Vercel : QR_PRIVATE_KEY (obligatoire), WALLET_COMMISSION_RATE (opt., défaut 0),
                      PAX_DAILY_CAP (opt., défaut 2250)
   ════════════════════════════════════════════════════════════════════ */
const MAX_TICKET_PRICE   = 450;          // FCFA — prix max d'un ticket payé par portefeuille
const MAX_PER_QR         = 900;          // FCFA — total max débitable avec UN même QR
const PAX_DAILY_CAP      = (() => {      // FCFA — total max débitable par PASSAGER et par jour via QR
  const n = parseInt(clean(process.env.PAX_DAILY_CAP), 10);
  return n > 0 ? n : 2250;
})();
const QR_VALIDITY_SEC    = 24 * 3600;    // durée de vie d'un QR
const QR_SYNC_GRACE_SEC  = 24 * 3600;    // délai max, après expiration, pour synchroniser une vente hors-ligne
const PENDING_MAX_AGE_MS = 60 * 60 * 1000; // une demande `pending` payée par portefeuille expire après 1 h
const WALLET_COMMISSION_RATE = (() => {
  const r = Number(clean(process.env.WALLET_COMMISSION_RATE) || 0);
  return (r >= 0 && r <= 0.2) ? r : 0;
})();

const QR_PRIVATE_PEM = clean(process.env.QR_PRIVATE_KEY).replace(/\\n/g, '\n');
let qrPrivateKey = null, qrPublicKey = null;
if (QR_PRIVATE_PEM) {
  try {
    qrPrivateKey = crypto.createPrivateKey(QR_PRIVATE_PEM);
    qrPublicKey  = crypto.createPublicKey(qrPrivateKey);
  } catch (e) { console.error('🚨 QR_PRIVATE_KEY invalide:', e.message); }
} else {
  console.error('🚨 QR_PRIVATE_KEY manquante — QR signé et encaissement par QR désactivés.');
}

const RE_UID = /^[A-Za-z0-9]{10,128}$/;
const RE_WALLET = /^[A-Za-z0-9-]{3,40}$/;
const qrMessage = (uid, walletId, bal, iat, exp) => `TP1|${uid}|${walletId}|${bal}|${iat}|${exp}`;
const signQr = (msg) =>
  crypto.sign('sha256', Buffer.from(msg), { key: qrPrivateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
const verifyQr = (msg, sig) => {
  try {
    const b = Buffer.from(String(sig), 'base64url');
    return b.length === 64 &&
      crypto.verify('sha256', Buffer.from(msg), { key: qrPublicKey, dsaEncoding: 'ieee-p1363' }, b);
  } catch (e) { return false; }
};

const byUid = (req) => req.uid || 'anon';
const qrIssueLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 40, keyGenerator: byUid, validate: false,
  message: { error: 'Trop de demandes de QR, réessayez plus tard.' }
});
const collectLimiter = rateLimit({
  windowMs: 60 * 1000, max: 60, keyGenerator: byUid, validate: false,
  message: { error: 'Trop de requêtes, réessayez dans une minute.' }
});

// ── ÉMETTRE UN QR SIGNÉ (appelé par le PASSAGER, avec réseau) ──
app.post('/api/qr/issue', verifyToken, qrIssueLimiter, async (req, res) => {
  if (!qrPrivateKey) return res.status(503).json({ error: 'QR signé indisponible (configuration serveur manquante)' });
  try {
    const snap = await db.collection('users').doc(req.uid).get();
    if (!snap.exists) return res.status(404).json({ error: 'Utilisateur introuvable' });
    const u = snap.data();
    if (!['approved', 'active'].includes(u.status)) return res.status(403).json({ error: 'Compte non validé' });
    if (typeof u.walletId !== 'string' || !RE_WALLET.test(u.walletId)) {
      return res.status(409).json({ error: 'Wallet introuvable pour ce compte' });
    }
    const bal = Math.max(0, Math.round(u.balance || 0));
    const iat = Math.floor(Date.now() / 1000);
    const exp = iat + QR_VALIDITY_SEC;
    const sig = signQr(qrMessage(req.uid, u.walletId, bal, iat, exp));
    const qr = `tatapay://wallet/${u.walletId}?uid=${req.uid}&bal=${bal}&t=${iat}&exp=${exp}&sig=${sig}`;
    res.json({ qr, bal, iat, exp });
  } catch (err) {
    console.error('❌ Erreur /api/qr/issue:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── ENCAISSER UN TICKET (appelé par le RECEVEUR) ──
//   mode 'qr'      : preuve = QR signé du passager (marche pour les ventes faites hors-ligne)
//   mode 'pending' : preuve = demande créée par le passager lui-même (collection `pending`)
//                    • payée par portefeuille  → débit/crédit faits ici
//                    • payée par Mobile Money  → déjà encaissée par l'IPN : on vérifie la transaction
//                      PayTech et on crée seulement le ticket (aucun mouvement de solde)
// Idempotent : même (receveur, syncRef) → jamais traité deux fois.
app.post('/api/ticket/collect', verifyToken, collectLimiter, async (req, res) => {
  const receiverUid = req.uid;
  const { mode, syncRef, qr, pendingId, price, ticket: tk } = req.body || {};
  const meta = (tk && typeof tk === 'object') ? tk : {};
  const reject = (reason) => res.json({ status: 'rejected', reason });

  if (typeof syncRef !== 'string' || !/^[A-Za-z0-9_-]{16,64}$/.test(syncRef)) {
    return res.status(400).json({ error: 'syncRef invalide' });
  }
  if (mode !== 'qr' && mode !== 'pending') return res.status(400).json({ error: 'Mode invalide' });

  let qrData = null, qrPrice = 0;
  if (mode === 'qr') {
    if (!qrPublicKey) return res.status(503).json({ error: 'Service indisponible (configuration serveur manquante)' });
    if (!qr || typeof qr !== 'object') return res.status(400).json({ error: 'QR manquant' });
    const { uid, walletId, bal, iat, exp, sig } = qr;
    if (typeof uid !== 'string' || !RE_UID.test(uid) || typeof walletId !== 'string' || !RE_WALLET.test(walletId)
        || typeof sig !== 'string' || sig.length > 200
        || !Number.isInteger(bal) || bal < 0 || !Number.isInteger(iat) || !Number.isInteger(exp)) {
      return res.status(400).json({ error: 'QR mal formé' });
    }
    if (!verifyQr(qrMessage(uid, walletId, bal, iat, exp), sig)) return reject('QR invalide (signature)');
    if (Math.floor(Date.now() / 1000) > exp + QR_SYNC_GRACE_SEC) return reject('QR expiré');
    if (!Number.isInteger(price) || price < 1 || price > MAX_TICKET_PRICE) {
      return reject(`Prix invalide (1 à ${MAX_TICKET_PRICE} FCFA)`);
    }
    qrData = { uid, walletId, iat };
    qrPrice = price;
  } else if (typeof pendingId !== 'string' || !/^[A-Za-z0-9]{10,40}$/.test(pendingId)) {
    return res.status(400).json({ error: 'pendingId invalide' });
  }

  const receiverRef = db.collection('users').doc(receiverUid);
  const ticketRef   = db.collection('tickets').doc(
    'T' + crypto.createHash('sha256').update(receiverUid + ':' + syncRef).digest('hex').slice(0, 30)
  );
  const FV = admin.firestore.FieldValue;
  const day = new Date().toISOString().slice(0, 10).replace(/-/g, '');

  let out = null;
  try {
    await db.runTransaction(async (t) => {
      out = null;                                   // Firestore peut rejouer cette fonction
      const no = (reason) => { out = { status: 'rejected', reason }; };

      // ── LECTURES (toutes avant la moindre écriture) ──
      const [rSnap, tSnap] = await Promise.all([t.get(receiverRef), t.get(ticketRef)]);
      if (tSnap.exists) { out = { status: 'already_synced', ticketId: ticketRef.id }; return; }
      if (!rSnap.exists || rSnap.data().role !== 'receiver' || !['approved', 'active'].includes(rSnap.data().status)) {
        return no('Compte receveur non actif');
      }
      const r = rSnap.data();

      let passengerUid, amount, from, to, section;
      let pendingRef = null, sessionRef = null, dailyRef = null, extTxRef = null, extTx = null, pend = null;
      if (mode === 'pending') {
        pendingRef = db.collection('pending').doc(pendingId);
        const pSnap = await t.get(pendingRef);
        if (!pSnap.exists) return no('Demande introuvable (déjà traitée ou annulée)');
        pend = pSnap.data();
        if (pend.busUid !== receiverUid) return no('Cette demande ne vous est pas destinée');
        amount = Number(pend.price);
        if (!Number.isInteger(amount) || amount < 1) return no('Prix invalide');
        passengerUid = String(pend.passengerUid || '');
        from = cut(pend.from, 60); to = cut(pend.to, 60); section = Number(pend.section) || 0;

        if (pend.paidAt || pend.ref) {
          // Payée par Mobile Money : la preuve est la transaction PayTech créditée par l'IPN.
          if (typeof pend.ref !== 'string' || !pend.ref) return no('Demande payée invalide');
          extTxRef = db.collection('paytech_transactions').doc(pend.ref);
          const xs = await t.get(extTxRef);
          extTx = xs.exists ? xs.data() : null;
          if (!extTx || extTx.status !== 'credited' || extTx.type !== 'ticket'
              || extTx.uid !== passengerUid || extTx.amount !== amount
              || !extTx.meta || extTx.meta.busUid !== receiverUid) return no('Paiement Mobile Money non vérifié');
          if (extTx.ticketId) return no('Ticket déjà émis pour ce paiement');
        } else {
          if (amount > MAX_TICKET_PRICE) return no(`Prix invalide (1 à ${MAX_TICKET_PRICE} FCFA)`);
          const ts0 = pend.ts && typeof pend.ts.toMillis === 'function' ? pend.ts.toMillis() : 0;
          if (!ts0 || Date.now() - ts0 > PENDING_MAX_AGE_MS) return no('Demande expirée : le passager doit la renvoyer');
        }
      } else {
        amount = qrPrice;
        passengerUid = qrData.uid;
        from = cut(meta.from, 60) || '—'; to = cut(meta.to, 60) || '—'; section = Number(meta.section) || 0;
        sessionRef = db.collection('offline_qr_sessions').doc(`${qrData.uid}_${qrData.iat}`);
        dailyRef   = db.collection('offline_qr_sessions').doc(`day_${qrData.uid}_${day}`);
      }

      if (!passengerUid || passengerUid === receiverUid) return no('Passager invalide');
      const passengerRef = db.collection('users').doc(passengerUid);
      const [paxSnap, sessionSnap, dailySnap] = await Promise.all([
        t.get(passengerRef),
        sessionRef ? t.get(sessionRef) : Promise.resolve(null),
        dailyRef ? t.get(dailyRef) : Promise.resolve(null)
      ]);

      if (!paxSnap.exists) return no('Passager introuvable');
      const pax = paxSnap.data();
      if (mode === 'qr' && pax.walletId !== qrData.walletId) return no('QR incohérent');
      const external = !!extTxRef;
      if (!external) {
        if (!['approved', 'active'].includes(pax.status)) return no('Compte passager non actif');
        if ((pax.balance || 0) < amount) return no('Solde insuffisant');
      }

      let spent = 0, daySpent = 0;
      if (sessionRef) {
        spent = sessionSnap.exists ? (sessionSnap.data().totalSpent || 0) : 0;
        if (spent + amount > MAX_PER_QR) {
          return no(`Plafond par QR dépassé (max ${MAX_PER_QR} F, ${spent} F déjà utilisés)`);
        }
        daySpent = dailySnap && dailySnap.exists ? (dailySnap.data().totalSpent || 0) : 0;
        if (daySpent + amount > PAX_DAILY_CAP) {
          return no(`Plafond journalier du passager atteint (${PAX_DAILY_CAP} F)`);
        }
      }

      // ── CALCULS ──
      const commission  = external ? (Number(pend.commission) || 0)
        : ((ADMIN_UID && ADMIN_UID !== receiverUid) ? Math.round(amount * WALLET_COMMISSION_RATE) : 0);
      const receiverAmt = amount - commission;
      const ts          = FV.serverTimestamp();

      const ticketDoc = {
        payMode: external ? 'mobile' : 'wallet',
        method: external ? (cut(pend.method, 30) || 'Mobile Money') : 'cash',
        busId: cut(r.walletId, 40), busUid: receiverUid,
        gie: cut(r.gie), vehicle: cut(r.vehicle), ligne: cut(r.ligne), zone: cut(r.zone),
        from, to, section, price: amount, commission,
        passengerId: cut(pax.walletId, 40), passengerUid, passenger: cut(pax.name, 80) || 'Passager',
        date: cut(meta.date, 20), time: cut(meta.time, 20), sn: cut(meta.sn, 40),
        offline: !!meta.offline, syncRef, ts
      };

      // ── ÉCRITURES (une seule transaction : tout ou rien) ──
      if (external) {
        // L'IPN a déjà crédité le receveur et écrit les historiques : seuls compteurs + ticket.
        t.update(receiverRef, { today: FV.increment(amount), count: FV.increment(1) });
        t.update(extTxRef, { ticketId: ticketRef.id, ticketIssuedAt: ts });
      } else {
        t.update(passengerRef, { balance: FV.increment(-amount) });
        t.set(passengerRef.collection('history').doc(), {
          type: 'ticket', label: `Ticket ${ticketDoc.gie}/${ticketDoc.vehicle} → ${to}`.slice(0, 120),
          amount: -amount, ref: syncRef, ts
        });
        t.update(receiverRef, {
          balance: FV.increment(receiverAmt), today: FV.increment(amount), count: FV.increment(1)
        });
        t.set(receiverRef.collection('history').doc(), {
          type: 'collect', label: `Collecte ticket ${ticketDoc.gie}/${ticketDoc.vehicle} — ${pax.name || ''}`.slice(0, 120),
          amount: receiverAmt, ref: syncRef, ts
        });
        if (commission > 0) {
          const adminRef = db.collection('users').doc(ADMIN_UID);
          t.set(adminRef, { balance: FV.increment(commission) }, { merge: true });
          t.set(adminRef.collection('history').doc(), {
            type: 'commission', label: `Commission — ${ticketDoc.gie}/${ticketDoc.vehicle} — ${ticketRef.id}`.slice(0, 120),
            amount: commission, ref: ticketRef.id, ts
          });
          t.set(db.collection('commissions').doc(ticketRef.id), {
            ref: ticketRef.id, amount, commission, receiverAmt, rate: WALLET_COMMISSION_RATE,
            receiverUid, passengerUid, gie: ticketDoc.gie, vehicle: ticketDoc.vehicle, source: 'wallet', ts
          });
        }
      }
      t.set(ticketRef, ticketDoc);
      t.set(passengerRef.collection('tickets').doc(ticketRef.id), { ...ticketDoc, ticketId: ticketRef.id });
      t.set(db.collection('notifications').doc(), {
        toUid: passengerUid, type: 'ticket_validated', passenger: cut(pax.name, 80), read: false, ts
      });
      if (sessionRef) {
        t.set(sessionRef, { uid: qrData.uid, issuedAt: qrData.iat, totalSpent: spent + amount, updatedAt: ts }, { merge: true });
        t.set(dailyRef,   { uid: qrData.uid, day, totalSpent: daySpent + amount, updatedAt: ts }, { merge: true });
      }
      if (pendingRef) t.delete(pendingRef);

      out = { status: 'synced', ticketId: ticketRef.id };
    });

    if (out.status === 'synced') console.log(`✅ Ticket ${mode}: ${receiverUid} ← ${syncRef.slice(0, 8)}…`);
    res.json(out);
  } catch (err) {
    console.error('❌ Erreur /api/ticket/collect:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});


// ── ADMIN : retraits bloqués (statut « unknown » ou « reserved » trop longtemps) ──
const RE_WD = /^TTW-[A-Za-z0-9-]{6,60}$/;
app.get('/api/admin/withdrawals/stuck', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const snap = await db.collection('withdrawals').where('status', 'in', ['unknown', 'reserved']).limit(100).get();
    res.json({ withdrawals: snap.docs.map(d => {
      const w = d.data();
      return { ref: d.id, ownerUid: w.ownerUid, amount: w.amount, phone: w.phone, operator: w.operator, status: w.status, error: w.error || '' };
    }) });
  } catch (err) {
    console.error('❌ withdrawals/stuck:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});
// À utiliser SEULEMENT après avoir vérifié chez PayTech que le virement n'est PAS parti.
app.post('/api/admin/withdrawals/:ref/refund', verifyToken, verifyAdmin, async (req, res) => {
  const ref = String(req.params.ref);
  if (!RE_WD.test(ref)) return res.status(400).json({ error: 'Référence invalide' });
  try {
    const s = await db.collection('withdrawals').doc(ref).get();
    if (!s.exists) return res.status(404).json({ error: 'Retrait introuvable' });
    if (!['unknown', 'reserved'].includes(s.data().status)) {
      return res.status(409).json({ error: 'Statut actuel : ' + s.data().status });
    }
    await refundWithdrawal(ref, 'admin_refund');
    res.json({ message: 'Retrait remboursé', ref });
  } catch (err) {
    console.error('❌ admin refund:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});
// À utiliser quand PayTech confirme que le virement est bien parti.
app.post('/api/admin/withdrawals/:ref/mark-success', verifyToken, verifyAdmin, async (req, res) => {
  const ref = String(req.params.ref);
  if (!RE_WD.test(ref)) return res.status(400).json({ error: 'Référence invalide' });
  try {
    const s = await db.collection('withdrawals').doc(ref).get();
    if (!s.exists) return res.status(404).json({ error: 'Retrait introuvable' });
    if (!['unknown', 'reserved', 'sent'].includes(s.data().status)) {
      return res.status(409).json({ error: 'Statut actuel : ' + s.data().status });
    }
    await markWithdrawalSuccess(ref);
    res.json({ message: 'Retrait marqué comme réussi', ref });
  } catch (err) {
    console.error('❌ admin mark-success:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── VERCEL : on exporte l'app (pas de app.listen, pas de keep-alive) ──
module.exports = app;
