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
const OFFLINE_SECRET     = clean(process.env.OFFLINE_SECRET);
if (!OFFLINE_SECRET) {
  console.error('🚨 OFFLINE_SECRET n\'est pas définie — les routes /api/offline/* sont désactivées.');
}
const ADMIN_UID          = clean(process.env.ADMIN_UID);
const COMMISSION_RATE    = 0.02;
const MAX_OFFLINE_PER_QR = 1000;

const requireOfflineSecret = (req, res, next) => {
  if (!OFFLINE_SECRET) {
    return res.status(503).json({ error: 'Paiement hors-ligne indisponible (configuration serveur manquante)' });
  }
  next();
};

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
    return res.status(500).json({ error: e.message });
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
    meta:      meta || null,
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
      return res.status(502).json({ error: 'Réponse non-JSON de PayTech', raw: rawText.slice(0, 500) });
    }

    if (data.payment_url || data.redirect_url) {
      const url = data.payment_url || data.redirect_url;
      res.json({ payment_url: url, redirect_url: url, ref_command: refCommand });
    } else {
      await db.collection('paytech_transactions').doc(refCommand).delete();
      console.error('❌ PayTech a refusé la demande:', data);
      res.status(500).json({ error: data.message || 'Erreur PayTech', details: data });
    }

  } catch (error) {
    console.error('❌ Erreur init paiement:', error);
    await db.collection('paytech_transactions').doc(refCommand).delete().catch(() => {});
    res.status(500).json({ error: error.message });
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
  const { amount, phone, method } = req.body;
  const uid = req.uid;

  const amt = validateAmount(amount);
  if (!amt) return res.status(400).json({ error: 'Montant invalide (min 100, max 500 000 FCFA)' });
  const cleanPhone = String(phone || '').replace(/\s+/g, '');
  if (!/^\+?\d{8,15}$/.test(cleanPhone)) return res.status(400).json({ error: 'Numéro de téléphone invalide' });
  if (!SERVICE_MAP[method]) return res.status(400).json({ error: 'Opérateur invalide' });

  const service    = SERVICE_MAP[method];
  const externalId = 'TTW-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex');
  const userRef    = db.collection('users').doc(uid);
  const wdRef      = db.collection('withdrawals').doc(externalId);
  const histRef    = userRef.collection('history').doc(externalId);

  // 1) Réservation atomique
  try {
    await db.runTransaction(async (t) => {
      const snap = await t.get(userRef);
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
    return res.status(e.http || 500).json({ error: e.message });
  }

  // 2) Virement PayTech
  let data = null;
  try {
    const response = await fetch('https://paytech.sn/api/transfer/transferFund', {
      method: 'POST',
      headers: { 'API_KEY': PAYTECH_API_KEY, 'API_SECRET': PAYTECH_API_SECRET, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        amount: amt, destination_number: cleanPhone, service,
        callback_url: BACKEND_URL + '/api/transfer-callback', external_id: externalId
      })
    });
    const rawText = await response.text();
    console.log('💸 Transfer PayTech:', response.status, rawText.slice(0, 400));
    try { data = JSON.parse(rawText); } catch (e) { data = null; }
  } catch (err) {
    console.error('❌ Erreur réseau PayTech:', err.message);
    // Statut inconnu : on NE rembourse PAS automatiquement (le virement est peut-être parti).
    await wdRef.update({ status: 'unknown', error: err.message }).catch(() => {});
    return res.status(502).json({ error: 'PayTech injoignable — retrait en vérification', ref: externalId });
  }

  if (data && data.success === 1) {
    await wdRef.update({ status: 'sent', transferId: data.transfer?.id_transfer || '' });
    return res.json({ message: 'Retrait en cours de traitement', ref: externalId, status: 'pending', success: true });
  }

  // 3) Refus clair de PayTech → remboursement
  await refundWithdrawal(externalId, (data && data.message) || 'Refus PayTech');
  return res.status(400).json({ error: (data && data.message) || 'Échec PayTech' });
});

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
      if (external_id) await db.collection('withdrawals').doc(String(external_id)).update({ status: 'success' }).catch(() => {});
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
        const commission    = Math.round(amount * COMMISSION_RATE);
        const receiverAmt   = amount - commission;

        const pendingRef    = db.collection('pending').doc();
        const receiverRef   = db.collection('users').doc(meta.busUid);
        const recvHistRef   = db.collection('users').doc(meta.busUid).collection('history').doc();
        const adminRef      = db.collection('users').doc(ADMIN_UID);
        const adminHistRef  = db.collection('users').doc(ADMIN_UID).collection('history').doc();
        const commHistRef   = db.collection('commissions').doc();

        t.set(pendingRef, {
          busUid: meta.busUid, busId: meta.busId,
          passengerUid: uid, passengerId: meta.passengerId,
          passengerName: meta.passengerName,
          from: meta.from, to: meta.to,
          section: meta.section, price: amount,
          commission, receiverAmt,
          method: finalMethod, gie: meta.gie,
          vehicle: meta.vehicle, ligne: meta.ligne,
          zone: meta.zone, ref: ref_command,
          paidAt: admin.firestore.FieldValue.serverTimestamp(),
          status: 'pending'
        });

        // Payé par Mobile Money : on ne débite PAS le portefeuille du passager.
        t.set(histRef, {
          type: 'ticket',
          label: `Ticket ${meta.gie}/${meta.vehicle} → ${meta.to} (Mobile Money)`,
          amount: 0, paidExternal: amount, ref: ref_command,
          ts: admin.firestore.FieldValue.serverTimestamp()
        });

        t.update(receiverRef, { balance: admin.firestore.FieldValue.increment(receiverAmt) });
        t.set(recvHistRef, {
          type: 'collect',
          label: `Collecte ticket ${meta.gie}/${meta.vehicle} — ${ref_command}`,
          amount: receiverAmt, ref: ref_command,
          ts: admin.firestore.FieldValue.serverTimestamp()
        });

        if (ADMIN_UID) {
          t.update(adminRef, { balance: admin.firestore.FieldValue.increment(commission) });
          t.set(adminHistRef, {
            type: 'commission',
            label: `Commission 2% — ${meta.gie}/${meta.vehicle} — ${ref_command}`,
            amount: commission, ref: ref_command,
            ts: admin.firestore.FieldValue.serverTimestamp()
          });
        }

        t.set(commHistRef, {
          ref: ref_command, amount, commission, receiverAmt,
          rate: COMMISSION_RATE, receiverUid: meta.busUid,
          passengerUid: uid, gie: meta.gie, vehicle: meta.vehicle,
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

// ── GÉNÉRER QR SIGNÉ HORS-LIGNE ──
app.post('/api/offline/qr', verifyToken, requireOfflineSecret, limiter, async (req, res) => {
  const uid = req.uid;
  try {
    const userSnap = await db.collection('users').doc(uid).get();
    if (!userSnap.exists) return res.status(404).json({ error: 'Utilisateur introuvable' });

    const userData = userSnap.data();
    const payload = {
      uid,
      walletId:  userData.walletId,
      name:      userData.name,
      balance:   userData.balance || 0,
      issuedAt:  Date.now(),
      expiresAt: Date.now() + 24 * 60 * 60 * 1000
    };

    const signature = crypto
      .createHmac('sha256', OFFLINE_SECRET)
      .update(JSON.stringify(payload))
      .digest('hex');

    console.log(`✅ QR offline : ${uid} | solde: ${payload.balance} FCFA`);
    res.json({ payload, signature, maxOffline: MAX_OFFLINE_PER_QR });

  } catch (err) {
    console.error('❌ Erreur QR offline:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── VÉRIFIER QR HORS-LIGNE ──
app.post('/api/offline/verify', requireOfflineSecret, async (req, res) => {
  const { payload, signature } = req.body;
  if (!payload || !signature) return res.status(400).json({ error: 'Données manquantes' });

  try {
    const expectedSig = crypto
      .createHmac('sha256', OFFLINE_SECRET)
      .update(JSON.stringify(payload))
      .digest('hex');

    const valid      = expectedSig === signature;
    const expired    = Date.now() > payload.expiresAt;

    res.json({ valid, expired, maxOffline: MAX_OFFLINE_PER_QR });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── SYNC TRANSACTIONS HORS-LIGNE ──
// Plafond cumulé par QR émis (uid+issuedAt), suivi dans offline_qr_sessions/{sessionKey}.
app.post('/api/offline/sync', verifyToken, requireOfflineSecret, limiter, async (req, res) => {
  const { transactions } = req.body;
  if (!transactions || !Array.isArray(transactions)) {
    return res.status(400).json({ error: 'Tableau de transactions manquant' });
  }

  const results = [];

  for (const tx of transactions) {
    const { payload, signature, price, syncRef } = tx;
    const receiverUid = req.uid; // jamais pris du client

    try {
      const expectedSig = crypto
        .createHmac('sha256', OFFLINE_SECRET)
        .update(JSON.stringify(payload))
        .digest('hex');

      if (expectedSig !== signature) {
        results.push({ syncRef, status: 'rejected', reason: 'Signature invalide' });
        continue;
      }

      if (Date.now() > payload.expiresAt + 24 * 60 * 60 * 1000) {
        results.push({ syncRef, status: 'rejected', reason: 'QR expiré' });
        continue;
      }

      if (!syncRef || typeof syncRef !== 'string' || !Number.isInteger(price) || price <= 0 || price > 1000) {
        results.push({ syncRef, status: 'rejected', reason: 'Dépasse limite 1000 FCFA par transaction' });
        continue;
      }

      const existingSnap = await db.collection('offline_transactions').doc(syncRef).get();
      if (existingSnap.exists) {
        results.push({ syncRef, status: 'already_synced' });
        continue;
      }

      const sessionKey = `${payload.uid}_${payload.issuedAt}`;
      const sessionRef = db.collection('offline_qr_sessions').doc(sessionKey);

      const passengerRef  = db.collection('users').doc(payload.uid);
      const receiverRef   = db.collection('users').doc(receiverUid);
      const passHistRef   = db.collection('users').doc(payload.uid).collection('history').doc();
      const recvHistRef   = db.collection('users').doc(receiverUid).collection('history').doc();
      const offlineTxRef  = db.collection('offline_transactions').doc(syncRef);

      let rejection = null;

      await db.runTransaction(async (t) => {
        const [passengerSnap, sessionSnap, receiverSnap] = await Promise.all([
          t.get(passengerRef),
          t.get(sessionRef),
          t.get(receiverRef)
        ]);
        if (!receiverSnap.exists || receiverSnap.data().role !== 'receiver' || payload.uid === receiverUid) {
          rejection = 'Seul un receveur peut encaisser';
          return;
        }

        if (!passengerSnap.exists || (passengerSnap.data().balance || 0) < price) {
          rejection = 'Solde insuffisant';
          return;
        }

        const alreadySpent = sessionSnap.exists ? (sessionSnap.data().totalSpent || 0) : 0;
        if (alreadySpent + price > MAX_OFFLINE_PER_QR) {
          rejection = `Plafond hors-ligne dépassé (max ${MAX_OFFLINE_PER_QR} F par QR, ${alreadySpent} F déjà utilisés)`;
          return;
        }

        t.update(passengerRef, { balance: admin.firestore.FieldValue.increment(-price) });
        t.set(passHistRef, {
          type: 'ticket_offline', label: `Ticket hors-ligne — ${syncRef}`,
          amount: -price, ref: syncRef,
          ts: admin.firestore.FieldValue.serverTimestamp()
        });
        t.update(receiverRef, { balance: admin.firestore.FieldValue.increment(price) });
        t.set(recvHistRef, {
          type: 'collect_offline', label: `Collecte hors-ligne — ${syncRef}`,
          amount: price, ref: syncRef,
          ts: admin.firestore.FieldValue.serverTimestamp()
        });
        t.set(offlineTxRef, {
          passengerUid: payload.uid, receiverUid, price, syncRef,
          syncedAt: admin.firestore.FieldValue.serverTimestamp(), status: 'synced'
        });
        t.set(sessionRef, {
          uid: payload.uid, issuedAt: payload.issuedAt,
          totalSpent: alreadySpent + price,
          updatedAt: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });
      });

      if (rejection) {
        results.push({ syncRef, status: 'rejected', reason: rejection });
        continue;
      }

      results.push({ syncRef, status: 'synced' });
      console.log(`✅ Sync offline : ${payload.uid} -${price} FCFA → ${receiverUid}`);

    } catch (err) {
      console.error(`❌ Erreur sync ${syncRef}:`, err.message);
      results.push({ syncRef, status: 'error', reason: err.message });
    }
  }

  const synced   = results.filter(r => r.status === 'synced').length;
  const rejected = results.filter(r => r.status === 'rejected').length;
  console.log(`📊 Sync : ${synced} acceptées, ${rejected} rejetées`);
  res.json({ results, synced, rejected });
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
    const existing = await db.collection('users').doc(uid).get();
    if (existing.exists && existing.data().role === 'owner') {
      return res.status(409).json({ error: 'Une demande propriétaire existe déjà pour ce compte' });
    }
    await db.collection('users').doc(uid).set({
      uid, name, phone, email,
      companyName: companyName || '',
      busCount:    busCount || 1,
      role:        'owner',
      status:      'pending',
      balance:     0,
      createdAt:   admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });
    console.log(`📋 Demande propriétaire : ${uid} (${name})`);
    res.json({ message: 'Demande envoyée. En attente de validation par l\'administrateur.' });
  } catch (err) {
    console.error('❌ Erreur demande propriétaire:', err);
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
        .where('type', 'in', ['collect_offline', 'ticket'])
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    const existing = await db.collection('users').doc(uid).get();
    if (existing.exists && existing.data().role === 'receiver') {
      return res.status(409).json({ error: 'Vous avez déjà une demande en cours' });
    }
    await db.collection('users').doc(uid).set({
      uid, name, phone, email, ownerUid,
      ownerName: ownerSnap.data().name,
      role:      'receiver',
      status:    'pending',
      balance:   0,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });
    console.log(`📋 Demande receveur : ${uid} (${name}) → propriétaire ${ownerUid}`);
    res.json({ message: 'Demande envoyée. En attente de validation par le propriétaire.' });
  } catch (err) {
    console.error('❌ Erreur demande receveur:', err);
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
  }
});

// ── PROFIL UTILISATEUR ──

app.get('/api/profile', verifyToken, async (req, res) => {
  try {
    const snap = await db.collection('users').doc(req.uid).get();
    if (!snap.exists) return res.status(404).json({ error: 'Profil introuvable' });
    res.json(snap.data());
  } catch (err) {
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
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
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════
// ── GROQ (IA gratuite, modèle Llama 3.3) ──
// Nécessite la variable d'environnement GROQ_API_KEY sur Vercel.
// ════════════════════════════════════════════════════════════
const GROQ_API_KEY = clean(process.env.GROQ_API_KEY);

const requireGroqKey = (req, res, next) => {
  if (!GROQ_API_KEY) {
    return res.status(503).json({ error: 'IA indisponible (GROQ_API_KEY manquante)' });
  }
  next();
};

async function askGroq(system, user) {
  const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + GROQ_API_KEY,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      model: 'llama-3.3-70b-versatile',
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: user }
      ],
      temperature: 0.4,
      max_tokens: 300
    })
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error((data.error && data.error.message) || ('Groq HTTP ' + r.status));
  return ((data.choices && data.choices[0] && data.choices[0].message.content) || '').trim();
}

// ════════════════════════════════════════════════════════════
// ── SENTINEL : explication d'une alerte en langage simple (Groq) ──
// Les chiffres viennent de Sentinel (envoyés par l'application) ; le modèle ne fait que les expliquer.
// ════════════════════════════════════════════════════════════
app.post('/api/ai-explain', verifyToken, assistantLimiter, requireGroqKey, async (req, res) => {
  const { type, bus, day, msg, lang } = req.body || {};
  const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
  const alertMsg = str(msg, 400);
  if (!alertMsg) return res.status(400).json({ error: 'Alerte manquante' });

  const kinds = {
    drop: 'une chute de recettes inhabituelle',
    skim: 'des espèces dues non versées au propriétaire',
    trend: 'une baisse progressive des recettes'
  };
  const kind = kinds[type] || 'une anomalie';
  const langLabel = lang === 'wo' ? 'wolof' : 'français';

  const systemPrompt =
    `Tu es Sentinel, le conseiller de TataPay (paiement de tickets de bus au Sénégal). ` +
    `Tu expliques une alerte à un propriétaire ou un chauffeur. Réponds UNIQUEMENT en ${langLabel}, ` +
    `en 3 à 4 phrases courtes et simples. Reprends les chiffres de l'alerte tels quels, sans en inventer. ` +
    `Ne dis jamais qu'il y a fraude ou vol : c'est une indication à vérifier sur le terrain. ` +
    `Donne 2 ou 3 causes possibles et innocentes (panne, jour férié, bus à l'arrêt, versement en retard, ` +
    `erreur de saisie) puis une action concrète pour vérifier (appeler le receveur, contrôler le bus, ` +
    `comparer avec le carnet).`;

  const prompt =
    `Alerte Sentinel : ${kind}.\n` +
    `Bus : ${str(bus, 40) || 'inconnu'}\n` +
    `Jour : ${str(day, 60) || 'inconnu'}\n` +
    `Détail : ${alertMsg}`;

  try {
    const answer = await askGroq(systemPrompt, prompt);
    if (!answer) return res.status(502).json({ error: 'Réponse vide' });
    res.json({ answer, lang: lang === 'wo' ? 'wo' : 'fr' });
  } catch (err) {
    console.error('❌ Erreur ai-explain Groq:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── VERCEL : on exporte l'app (pas de app.listen, pas de keep-alive) ──
module.exports = app;
