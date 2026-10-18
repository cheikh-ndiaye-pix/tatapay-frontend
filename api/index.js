// TataPay — backend converti pour Vercel (une seule fonction Express).
// Toutes les routes /api/* sont redirigées ici par vercel.json.
const express   = require('express');
const cors      = require('cors');
const admin     = require('firebase-admin');
const crypto    = require('crypto');
const rateLimit = require('express-rate-limit');

const app = express();
app.set('trust proxy', 1); // Vercel est derrière un proxy (nécessaire pour le rate limit par IP)

// ── CORS ──
const ALLOWED_ORIGINS = [
  'https://tatapay-a4972.web.app',
  'https://tatapay-a4972.firebaseapp.com',
  'https://tatapay-frontend.vercel.app',
  'http://localhost:8081',
  'http://localhost:19006',
  'exp://192.168.1.91:8081'
];
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

// ── VARIABLES D'ENVIRONNEMENT ──
const clean = (v) => (v || '').toString().trim().replace(/^["']+|["']+$/g, '').trim();

const PAYTECH_API_KEY    = clean(process.env.PAYTECH_API_KEY);
const PAYTECH_API_SECRET = clean(process.env.PAYTECH_API_SECRET);
const rawEnv      = clean(process.env.PAYTECH_ENV).toLowerCase();
const PAYTECH_ENV = ['prod', 'production', 'live'].includes(rawEnv) ? 'prod' : 'test';

const OFFLINE_SECRET     = clean(process.env.OFFLINE_SECRET);
const ADMIN_UID          = clean(process.env.ADMIN_UID);
const COMMISSION_RATE    = 0.02;
const MAX_OFFLINE_PER_QR = 1000;

// URL publique de CE backend (pour les callbacks PayTech). Surchargeable via BACKEND_URL.
const BACKEND_URL = clean(process.env.BACKEND_URL) || 'https://tatapay-frontend.vercel.app';

const requireOfflineSecret = (req, res, next) => {
  if (!OFFLINE_SECRET) {
    return res.status(503).json({ error: 'Paiement hors-ligne indisponible (configuration serveur manquante)' });
  }
  next();
};

// ── FIREBASE (initialisé une seule fois, même si l'instance est réutilisée) ──
if (!admin.apps.length) {
  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}
const db = admin.firestore();

// ── RATE LIMITING (en mémoire : par instance serverless, donc approximatif) ──
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

// ── MIDDLEWARES ──
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

const verifyAdmin = async (req, res, next) => {
  if (!req.uid) return res.status(401).json({ error: 'Non autorisé' });
  if (!ADMIN_UID || req.uid !== ADMIN_UID) {
    return res.status(403).json({ error: 'Accès réservé à l\'administrateur' });
  }
  next();
};

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

const validateAmount = (amount) => {
  const amt = parseInt(amount);
  if (!amt || !Number.isInteger(amt)) return false;
  if (amt < 100) return false;
  if (amt > 500000) return false;
  return amt;
};

const requirePaytechKeys = (req, res, next) => {
  if (!PAYTECH_API_KEY || !PAYTECH_API_SECRET) {
    console.error('🚨 Clés PayTech manquantes.');
    return res.status(503).json({ error: 'Clé API PayTech manquante sur le serveur (configuration à vérifier)' });
  }
  next();
};

// ════════════════════════════════════════════════════════════
// ── ROUTES ──
// ════════════════════════════════════════════════════════════

app.get(['/api', '/api/ping'], (req, res) => {
  res.json({
    status: 'alive',
    message: 'TataPay Backend (Vercel) is running!',
    paytech_env: PAYTECH_ENV,
    paytech_keys: (PAYTECH_API_KEY && PAYTECH_API_SECRET) ? 'configurées' : 'MANQUANTES',
    admin_uid: ADMIN_UID ? 'configuré' : 'MANQUANT',
    offline_secret: OFFLINE_SECRET ? 'configuré' : 'MANQUANT',
    time: new Date()
  });
});

// ── INIT PAIEMENT PAYTECH ──
app.post('/api/payment/init', verifyToken, limiter, requirePaytechKeys, async (req, res) => {
  const { amount, phone, method, type, meta } = req.body;
  const uid = req.uid;

  const amt = validateAmount(amount);
  if (!amt) {
    return res.status(400).json({ error: 'Montant invalide (min 100, max 500 000 FCFA)' });
  }

  const allowedTypes = ['recharge', 'ticket', 'retrait'];
  if (!allowedTypes.includes(type)) {
    return res.status(400).json({ error: 'Type de paiement invalide' });
  }

  const refCommand = 'TTP-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8);

  try {
    await db.collection('paytech_transactions').doc(refCommand).set({
      uid,
      amount: amt,
      type,
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
      ipn_url:         `${BACKEND_URL}/api/ipn`,
      success_url:     'https://tatapay-a4972.web.app/success.html',
      cancel_url:      'https://tatapay-a4972.web.app/cancel.html',
      sender_phone:    phone || '',
      sender_country:  'SN',
      custom_field:    JSON.stringify({ uid, type, ref: refCommand })
    };

    if (method) payload.channel = method;

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

const SERVICE_MAP = {
  'wave':   'Wave Senegal',
  'orange': 'Orange Money Senegal',
  'free':   'Free Money'
};

// ── RETRAIT RÉEL VIA PAYTECH TRANSFER API ──
app.post('/api/withdraw', verifyToken, limiter, requirePaytechKeys, async (req, res) => {
  const { amount, phone, method } = req.body;
  const uid = req.uid;

  const amt = validateAmount(amount);
  if (!amt) return res.status(400).json({ error: 'Montant invalide (min 100, max 500 000 FCFA)' });
  if (!phone) return res.status(400).json({ error: 'Numéro de téléphone requis' });

  const service = SERVICE_MAP[method] || SERVICE_MAP['wave'];
  const externalId = 'TTW-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8);

  try {
    const userSnap = await db.collection('users').doc(uid).get();
    if (!userSnap.exists) return res.status(404).json({ error: 'Utilisateur introuvable' });

    const balance = userSnap.data().balance || 0;
    if (balance < amt) return res.status(400).json({ error: 'Solde insuffisant' });

    const payload = {
      amount:             amt,
      destination_number: phone,
      service,
      callback_url:       `${BACKEND_URL}/api/transfer-callback`,
      external_id:        externalId
    };

    const response = await fetch('https://paytech.sn/api/transfer/transferFund', {
      method: 'POST',
      headers: {
        'API_KEY':      PAYTECH_API_KEY,
        'API_SECRET':   PAYTECH_API_SECRET,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    const rawText = await response.text();
    console.log('💸 Transfer PayTech:', response.status, rawText.slice(0, 400));

    let data;
    try {
      data = JSON.parse(rawText);
    } catch (e) {
      return res.status(502).json({ error: 'Réponse non-JSON PayTech', raw: rawText.slice(0, 400) });
    }

    if (data.success === 1) {
      const histRef = db.collection('users').doc(uid).collection('history').doc();
      await db.runTransaction(async (t) => {
        t.update(db.collection('users').doc(uid), {
          balance: admin.firestore.FieldValue.increment(-amt)
        });
        t.set(histRef, {
          type:       'withdraw',
          label:      `Retrait ${service} — ${phone} — ${externalId}`,
          amount:     -amt,
          ref:        externalId,
          transferId: data.transfer?.id_transfer || '',
          status:     'pending',
          ts:         admin.firestore.FieldValue.serverTimestamp()
        });
      });

      console.log(`✅ Retrait initié : ${uid} -${amt} FCFA → ${phone} (${service})`);
      res.json({
        message:    'Retrait en cours de traitement',
        ref:        externalId,
        transferId: data.transfer?.id_transfer || '',
        status:     'pending'
      });

    } else {
      console.error('❌ Échec transfer PayTech:', data);
      res.status(400).json({ error: data.message || 'Échec PayTech', details: data });
    }

  } catch (err) {
    console.error('❌ Erreur retrait:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── CALLBACK TRANSFER PAYTECH ──
app.post('/api/transfer-callback', async (req, res) => {
  console.log('📩 Transfer callback reçu:', JSON.stringify(req.body));
  try {
    const {
      type_event, id_transfer, amount, destination_number,
      api_key_sha256, api_secret_sha256
    } = req.body;

    const expectedKeyHash    = crypto.createHash('sha256').update(PAYTECH_API_KEY).digest('hex');
    const expectedSecretHash = crypto.createHash('sha256').update(PAYTECH_API_SECRET).digest('hex');

    if (api_key_sha256 !== expectedKeyHash || api_secret_sha256 !== expectedSecretHash) {
      console.error('❌ Callback non authentifié');
      return res.status(403).send('Forbidden');
    }

    if (type_event === 'transfer_success') {
      console.log(`✅ Transfer confirmé : ${id_transfer} — ${amount} FCFA → ${destination_number}`);
    } else if (type_event === 'transfer_failed') {
      console.error(`❌ Transfer échoué : ${id_transfer}`);
    }

    res.status(200).send('OK');
  } catch (err) {
    console.error('❌ Erreur callback transfer:', err);
    res.status(500).send('Erreur');
  }
});

// ── IPN PAYTECH ──
app.post('/api/ipn', ipnLimiter, async (req, res) => {
  console.log('📩 IPN reçu:', JSON.stringify({
    type_event:  req.body.type_event,
    ref_command: req.body.ref_command,
    item_price:  req.body.item_price
  }));

  try {
    const { type_event, ref_command, method, api_key_sha256, api_secret_sha256 } = req.body;

    const expectedKeyHash    = crypto.createHash('sha256').update(PAYTECH_API_KEY).digest('hex');
    const expectedSecretHash = crypto.createHash('sha256').update(PAYTECH_API_SECRET).digest('hex');

    if (api_key_sha256 !== expectedKeyHash || api_secret_sha256 !== expectedSecretHash) {
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

      if (!txSnap.exists) { console.error('❌ Transaction inconnue:', ref_command); return; }
      if (txSnap.data().status === 'credited') { console.log('⚠️ Déjà crédité:', ref_command); return; }

      const txData = txSnap.data();
      const { uid, amount, type, meta } = txData;

      if (!uid || !amount) { console.error('❌ uid ou amount manquant'); return; }

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
        const commission  = Math.round(amount * COMMISSION_RATE);
        const receiverAmt = amount - commission;

        const pendingRef   = db.collection('pending').doc();
        const receiverRef  = db.collection('users').doc(meta.busUid);
        const recvHistRef  = db.collection('users').doc(meta.busUid).collection('history').doc();
        const adminRef     = db.collection('users').doc(ADMIN_UID || 'none');
        const adminHistRef = db.collection('users').doc(ADMIN_UID || 'none').collection('history').doc();
        const commHistRef  = db.collection('commissions').doc();

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

        t.update(userRef, { balance: admin.firestore.FieldValue.increment(-amount) });
        t.set(histRef, {
          type: 'ticket',
          label: `Ticket ${meta.gie}/${meta.vehicle} → ${meta.to}`,
          amount: -amount, ref: ref_command,
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

      else if (type === 'retrait') {
        t.update(userRef, { balance: admin.firestore.FieldValue.increment(-amount) });
        t.set(histRef, {
          type: 'withdraw',
          label: `Retrait via ${finalMethod} — ${ref_command}`,
          amount: -amount, ref: ref_command,
          ts: admin.firestore.FieldValue.serverTimestamp()
        });
        console.log(`✅ Retrait : ${uid} -${amount} FCFA`);
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

// ── QR HORS-LIGNE ──
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

app.post('/api/offline/verify', requireOfflineSecret, async (req, res) => {
  const { payload, signature } = req.body;
  if (!payload || !signature) return res.status(400).json({ error: 'Données manquantes' });

  try {
    const expectedSig = crypto
      .createHmac('sha256', OFFLINE_SECRET)
      .update(JSON.stringify(payload))
      .digest('hex');

    const valid   = expectedSig === signature;
    const expired = Date.now() > payload.expiresAt;

    res.json({ valid, expired, maxOffline: MAX_OFFLINE_PER_QR });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── SYNC HORS-LIGNE (plafond cumulé par QR) ──
app.post('/api/offline/sync', verifyToken, requireOfflineSecret, limiter, async (req, res) => {
  const { transactions } = req.body;
  if (!transactions || !Array.isArray(transactions)) {
    return res.status(400).json({ error: 'Tableau de transactions manquant' });
  }

  const results = [];

  for (const tx of transactions) {
    const { payload, signature, price, receiverUid, syncRef } = tx;

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

      if (!price || price > 1000) {
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

      const passengerRef = db.collection('users').doc(payload.uid);
      const receiverRef  = db.collection('users').doc(receiverUid);
      const passHistRef  = db.collection('users').doc(payload.uid).collection('history').doc();
      const recvHistRef  = db.collection('users').doc(receiverUid).collection('history').doc();
      const offlineTxRef = db.collection('offline_transactions').doc(syncRef);

      let rejection = null;

      await db.runTransaction(async (t) => {
        const [passengerSnap, sessionSnap] = await Promise.all([
          t.get(passengerRef),
          t.get(sessionRef)
        ]);

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

// ── PROFIL ──
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
  const limit = Math.min(parseInt(req.query.limit) || 20, 200);
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

// ── ASSISTANT IA (Google Gemini) — nécessite GEMINI_API_KEY ──
const GEMINI_API_KEY = clean(process.env.GEMINI_API_KEY);
let genAI = null;
if (GEMINI_API_KEY) {
  try {
    const { GoogleGenAI } = require('@google/genai');
    genAI = new GoogleGenAI({ apiKey: GEMINI_API_KEY });
  } catch (e) {
    console.error('🚨 @google/genai introuvable — /api/assistant désactivée:', e.message);
  }
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
    res.json({ answer, lang: lang === 'wo' ? 'wo' : 'fr' });
  } catch (err) {
    console.error('❌ Erreur assistant Gemini:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── 404 + erreurs (CORS refusé, JSON invalide…) ──
app.use('/api', (req, res) => res.status(404).json({ error: 'Route introuvable' }));
app.use((err, req, res, next) => {
  console.error('❌ Erreur:', err.message);
  res.status(err.status || 500).json({ error: err.message });
});

module.exports = app;
