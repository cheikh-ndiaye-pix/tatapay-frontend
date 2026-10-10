const express   = require('express');
const cors      = require('cors');
const admin     = require('firebase-admin');
const crypto    = require('crypto');
const https     = require('https');
const rateLimit = require('express-rate-limit');
const app       = express();

// ── CORS SÉCURISÉ ──
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
const PAYTECH_API_KEY    = (process.env.PAYTECH_API_KEY    || '').trim();
const PAYTECH_API_SECRET = (process.env.PAYTECH_API_SECRET || '').trim();
const PAYTECH_ENV        = (process.env.PAYTECH_ENV || 'test').trim();
const OFFLINE_SECRET     = (process.env.OFFLINE_SECRET || '').trim();
if (!OFFLINE_SECRET) {
  console.error('🚨 OFFLINE_SECRET n\'est pas définie — les routes /api/offline/* sont désactivées.');
}
const ADMIN_UID          = (process.env.ADMIN_UID || '').trim();
// PAYOUT_MODE : 'paytech' (envoi automatique via PayTech) ou 'manual'
// (le montant est réservé, l'admin envoie lui-même sur Wave puis valide).
const PAYOUT_MODE        = (process.env.PAYOUT_MODE || 'manual').trim().toLowerCase() === 'paytech' ? 'paytech' : 'manual';
const COMMISSION_RATE    = 0.02;
const MAX_OFFLINE_PER_QR = 1000;

const requireOfflineSecret = (req, res, next) => {
  if (!OFFLINE_SECRET) {
    return res.status(503).json({ error: 'Paiement hors-ligne indisponible (configuration serveur manquante)' });
  }
  next();
};

// ── FIREBASE ──
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();
const FV = admin.firestore.FieldValue;

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

// ── COMPARAISON À TEMPS CONSTANT (signatures PayTech) ──
const safeEqual = (a, b) => {
  const x = Buffer.from(String(a || ''));
  const y = Buffer.from(String(b || ''));
  if (x.length !== y.length) return false;
  return crypto.timingSafeEqual(x, y);
};
const paytechSignatureOk = (body) => {
  const k = crypto.createHash('sha256').update(PAYTECH_API_KEY).digest('hex');
  const s = crypto.createHash('sha256').update(PAYTECH_API_SECRET).digest('hex');
  return safeEqual(body.api_key_sha256, k) && safeEqual(body.api_secret_sha256, s);
};

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

// ── VALIDATION MONTANT ──
const validateAmount = (amount) => {
  const amt = parseInt(amount);
  if (!amt || !Number.isInteger(amt)) return false;
  if (amt < 100) return false;
  if (amt > 500000) return false;
  return amt;
};

// ════════════════════════════════════════════════════════════
// ── ROUTES ──
// ════════════════════════════════════════════════════════════

app.get('/', (req, res) => {
  res.json({ message: 'TataPay Backend is running!', paytech_env: PAYTECH_ENV, payout_mode: PAYOUT_MODE, version: 'payout-manual-v2' });
});

app.get('/ping', (req, res) => res.json({ status: 'alive', time: new Date() }));

// ── INIT PAIEMENT PAYTECH (entrant : recharge / ticket) ──
// Le type "retrait" a été retiré : un retrait passe UNIQUEMENT par /api/withdraw.
app.post('/api/payment/init', verifyToken, limiter, async (req, res) => {
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

  // Un paiement "ticket" doit viser un vrai receveur
  let safeMeta = null;
  if (type === 'ticket') {
    if (!meta || typeof meta.busUid !== 'string' || !meta.busUid || meta.busUid === uid) {
      return res.status(400).json({ error: 'Ticket invalide (receveur manquant)' });
    }
    try {
      const busSnap = await db.collection('users').doc(meta.busUid).get();
      if (!busSnap.exists || busSnap.data().role !== 'receiver') {
        return res.status(400).json({ error: 'Receveur introuvable' });
      }
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
    safeMeta = meta;
  }

  const refCommand = 'TTP-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8);

  await db.collection('paytech_transactions').doc(refCommand).set({
    uid,
    amount: amt,
    type:      type,
    method:    method || null,
    meta:      safeMeta,
    status:    'pending',
    createdAt: FV.serverTimestamp()
  });

  const itemNames = { recharge: 'Recharge TataPay', ticket: 'Ticket TataPay' };

  const payload = {
    item_name:       itemNames[type] || 'TataPay',
    item_price:      amt,
    currency:        'XOF',
    ref_command:     refCommand,
    command_name:    'TataPay Paiement',
    env:             PAYTECH_ENV,
    ipn_url:         'https://tatapay-backend-1.onrender.com/api/ipn',
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
    const fetch = await import('node-fetch');
    const response = await fetch.default('https://paytech.sn/api/payment/request-payment', {
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

    let data;
    try {
      data = JSON.parse(rawText);
    } catch (e) {
      return res.status(502).json({ error: 'Réponse non-JSON de PayTech' });
    }

    if (data.payment_url || data.redirect_url) {
      const url = data.payment_url || data.redirect_url;
      res.json({ payment_url: url, redirect_url: url, ref_command: refCommand });
    } else {
      await db.collection('paytech_transactions').doc(refCommand).delete();
      res.status(500).json({ error: data.message || 'Erreur PayTech' });
    }

  } catch (error) {
    console.error('❌ Erreur init paiement:', error);
    res.status(500).json({ error: 'Erreur serveur de paiement' });
  }
});

// ── MAPPING OPÉRATEUR → SERVICE PAYTECH ──
const SERVICE_MAP = {
  'wave':   'Wave Senegal',
  'orange': 'Orange Money Senegal',
  'free':   'Free Money'
};

// ── REMBOURSEMENT D'UN RETRAIT (idempotent) ──
// Ne rembourse qu'une seule fois, et jamais un retrait confirmé par PayTech.
async function refundPayout(payoutId, reason) {
  const payoutRef = db.collection('payouts').doc(payoutId);
  return db.runTransaction(async (t) => {
    const snap = await t.get(payoutRef);
    if (!snap.exists) return { refunded: false, why: 'inconnu' };
    const p = snap.data();
    if (p.status === 'refunded' || p.status === 'success') {
      return { refunded: false, why: p.status };
    }
    t.update(payoutRef, { status: 'refunded', refundReason: reason, refundedAt: FV.serverTimestamp() });
    t.update(db.collection('users').doc(p.uid), { balance: FV.increment(p.amount) });
    t.set(db.collection('users').doc(p.uid).collection('history').doc(), {
      type: 'withdraw_refund',
      label: `Retrait échoué — remboursé (${payoutId})`,
      amount: p.amount, ref: payoutId, ts: FV.serverTimestamp()
    });
    return { refunded: true };
  });
}

// ── RETRAIT VERS MOBILE MONEY (Wave par défaut) ──
// Ordre sûr : 1) on RÉSERVE le montant (débit atomique, solde vérifié dans la
// transaction) 2) on appelle PayTech 3) en cas d'échec confirmé, on rembourse.
// Le client envoie un requestId unique : rejouer la même requête ne paie jamais deux fois.
app.post('/api/withdraw', verifyToken, limiter, async (req, res) => {
  const { amount, phone, method, requestId } = req.body;
  const uid = req.uid;

  const amt = validateAmount(amount);
  if (!amt) return res.status(400).json({ error: 'Montant invalide (min 100, max 500 000 FCFA)' });

  const cleanPhone = String(phone || '').replace(/\s+/g, '');
  if (!/^\+?\d{8,15}$/.test(cleanPhone)) return res.status(400).json({ error: 'Numéro de téléphone invalide' });

  if (!/^[A-Za-z0-9]{8,40}$/.test(String(requestId || ''))) {
    return res.status(400).json({ error: 'Identifiant de requête invalide' });
  }

  const service = SERVICE_MAP[method] || SERVICE_MAP['wave'];
  const payoutId = `TTW-${uid.slice(0, 8)}-${requestId}`;
  const payoutRef = db.collection('payouts').doc(payoutId);
  const userRef = db.collection('users').doc(uid);

  try {
    // 1) Réservation atomique
    const reservation = await db.runTransaction(async (t) => {
      const existing = await t.get(payoutRef);
      if (existing.exists) return { created: false, payout: existing.data() };

      const userSnap = await t.get(userRef);
      if (!userSnap.exists) throw Object.assign(new Error('Utilisateur introuvable'), { http: 404 });
      const u = userSnap.data();
      if (!['approved', 'active'].includes(u.status)) {
        throw Object.assign(new Error('Compte non actif'), { http: 403 });
      }
      if ((u.balance || 0) < amt) {
        throw Object.assign(new Error('Solde insuffisant'), { http: 400 });
      }

      t.update(userRef, { balance: FV.increment(-amt) });
      t.set(payoutRef, {
        uid, amount: amt, phone: cleanPhone, service,
        name: u.name || '', walletId: u.walletId || '',
        status: PAYOUT_MODE === 'manual' ? 'pending_manual' : 'processing',
        createdAt: FV.serverTimestamp()
      });
      t.set(userRef.collection('history').doc(), {
        type: 'withdraw',
        label: `Retrait ${service} — ${cleanPhone} — ${payoutId}`,
        amount: -amt, ref: payoutId, status: 'pending', ts: FV.serverTimestamp()
      });
      return { created: true };
    });

    // Requête déjà traitée : on renvoie simplement l'état actuel
    if (!reservation.created) {
      return res.json({ message: 'Demande déjà enregistrée', ref: payoutId, status: reservation.payout.status });
    }

    // Mode manuel : pas d'appel PayTech, l'admin envoie l'argent depuis Wave
    if (PAYOUT_MODE === 'manual') {
      console.log(`📝 Retrait manuel en attente : ${uid} -${amt} FCFA → ${cleanPhone}`);
      return res.json({ message: 'Demande enregistrée, envoi en cours de traitement', ref: payoutId, status: 'pending' });
    }

    // 2) Appel PayTech
    let data = null, networkError = null;
    try {
      const fetch = await import('node-fetch');
      const response = await fetch.default('https://paytech.sn/api/transfer/transferFund', {
        method: 'POST',
        headers: {
          'API_KEY':      PAYTECH_API_KEY,
          'API_SECRET':   PAYTECH_API_SECRET,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          amount:             amt,
          destination_number: cleanPhone,
          service,
          callback_url:       'https://tatapay-backend-1.onrender.com/api/transfer-callback',
          external_id:        payoutId
        })
      });
      const rawText = await response.text();
      console.log('💸 Transfer PayTech:', response.status, rawText.slice(0, 300));
      try { data = JSON.parse(rawText); } catch (e) { data = { success: 0, message: 'Réponse invalide de PayTech' }; }
    } catch (e) {
      networkError = e;
    }

    // Réseau coupé : on ne sait pas si PayTech a reçu l'ordre. On NE rembourse PAS
    // (risque de double paiement). Le callback PayTech réglera l'état, sinon contrôle manuel.
    if (networkError) {
      console.error('⚠️ Retrait incertain', payoutId, networkError.message);
      await payoutRef.update({ status: 'unknown', note: networkError.message });
      return res.status(202).json({ message: 'Retrait en cours de vérification', ref: payoutId, status: 'pending' });
    }

    // 3) Résultat
    if (data.success === 1) {
      await payoutRef.update({ status: 'sent', transferId: data.transfer?.id_transfer || '' });
      console.log(`✅ Retrait initié : ${uid} -${amt} FCFA → ${cleanPhone} (${service})`);
      return res.json({ message: 'Retrait en cours de traitement', ref: payoutId, status: 'pending' });
    }

    await refundPayout(payoutId, data.message || 'Refus PayTech');
    console.error('❌ Échec transfer PayTech:', data.message);
    return res.status(400).json({ error: data.message || 'Échec PayTech — montant remboursé' });

  } catch (err) {
    console.error('❌ Erreur retrait:', err.message);
    return res.status(err.http || 500).json({ error: err.http ? err.message : 'Erreur serveur' });
  }
});

// ── ADMIN : lister les retraits (par défaut : ceux à traiter à la main ; status=all pour tout) ──
app.get('/api/admin/payouts', verifyToken, verifyAdmin, async (req, res) => {
  const status = String(req.query.status || 'pending_manual');
  try {
    let q = db.collection('payouts');
    if (status !== 'all') q = q.where('status', '==', status);
    const snap = await q.get();
    const payouts = snap.docs.map(d => {
      const p = d.data();
      return {
        id: d.id, name: p.name || '', walletId: p.walletId || '',
        phone: p.phone, amount: p.amount, service: p.service, status: p.status,
        createdAt: p.createdAt && p.createdAt.toMillis ? p.createdAt.toMillis() : null
      };
    }).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    res.json({ payouts, total: payouts.length, mode: PAYOUT_MODE });
  } catch (err) {
    console.error('❌ payouts list:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── ADMIN : traiter les retraits manuels ──
app.post('/api/admin/payouts/:id/done', verifyToken, verifyAdmin, async (req, res) => {
  const ref = db.collection('payouts').doc(req.params.id);
  try {
    const ok = await db.runTransaction(async (t) => {
      const snap = await t.get(ref);
      if (!snap.exists || snap.data().status !== 'pending_manual') return false;
      t.update(ref, { status: 'success', doneAt: FV.serverTimestamp(), doneBy: req.uid });
      return true;
    });
    if (!ok) return res.status(409).json({ error: 'Retrait déjà traité ou introuvable' });
    res.json({ message: 'Retrait marqué comme envoyé' });
  } catch (err) {
    console.error('❌ payout done:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/admin/payouts/:id/reject', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const snap = await db.collection('payouts').doc(req.params.id).get();
    if (!snap.exists || snap.data().status !== 'pending_manual') {
      return res.status(409).json({ error: 'Retrait déjà traité ou introuvable' });
    }
    const r = await refundPayout(req.params.id, 'refusé par admin');
    res.json({ message: r.refunded ? 'Retrait refusé et remboursé' : 'Déjà traité' });
  } catch (err) {
    console.error('❌ payout reject:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── CALLBACK TRANSFER PAYTECH ──
app.post('/api/transfer-callback', ipnLimiter, async (req, res) => {
  try {
    if (!paytechSignatureOk(req.body)) {
      console.error('❌ Callback non authentifié');
      return res.status(403).send('Forbidden');
    }
    const { type_event, external_id, id_transfer } = req.body;
    if (typeof external_id !== 'string' || !external_id.startsWith('TTW-')) {
      return res.status(200).send('OK');
    }
    const payoutRef = db.collection('payouts').doc(external_id);

    if (type_event === 'transfer_success') {
      await db.runTransaction(async (t) => {
        const s = await t.get(payoutRef);
        if (!s.exists) return;
        if (s.data().status === 'refunded') {
          console.error('🚨 Succès reçu pour un retrait déjà remboursé — à vérifier :', external_id);
          t.update(payoutRef, { status: 'success_after_refund', transferId: id_transfer || '' });
          return;
        }
        t.update(payoutRef, { status: 'success', transferId: id_transfer || '', doneAt: FV.serverTimestamp() });
      });
      console.log(`✅ Transfer confirmé : ${external_id}`);
    } else if (type_event === 'transfer_failed') {
      const r = await refundPayout(external_id, 'transfer_failed');
      console.error(`❌ Transfer échoué : ${external_id} | remboursé: ${r.refunded}`);
    }
    res.status(200).send('OK');
  } catch (err) {
    console.error('❌ Erreur callback transfer:', err.message);
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
    const { type_event, ref_command, method } = req.body;

    if (!paytechSignatureOk(req.body)) {
      console.error('❌ IPN non authentifié — signature invalide');
      return res.status(403).send('Forbidden');
    }

    if (type_event !== 'sale_complete') {
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
        t.update(userRef, { balance: FV.increment(amount) });
        t.set(histRef, {
          type: 'recharge',
          label: `Recharge via ${finalMethod} — ${ref_command}`,
          amount, ref: ref_command,
          ts: FV.serverTimestamp()
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
          paidAt: FV.serverTimestamp(),
          status: 'pending'
        });

        t.update(userRef, { balance: FV.increment(-amount) });
        t.set(histRef, {
          type: 'ticket',
          label: `Ticket ${meta.gie}/${meta.vehicle} → ${meta.to}`,
          amount: -amount, ref: ref_command,
          ts: FV.serverTimestamp()
        });

        t.update(receiverRef, { balance: FV.increment(receiverAmt) });
        t.set(recvHistRef, {
          type: 'collect',
          label: `Collecte ticket ${meta.gie}/${meta.vehicle} — ${ref_command}`,
          amount: receiverAmt, ref: ref_command,
          ts: FV.serverTimestamp()
        });

        if (ADMIN_UID) {
          t.update(adminRef, { balance: FV.increment(commission) });
          t.set(adminHistRef, {
            type: 'commission',
            label: `Commission 2% — ${meta.gie}/${meta.vehicle} — ${ref_command}`,
            amount: commission, ref: ref_command,
            ts: FV.serverTimestamp()
          });
        }

        t.set(commHistRef, {
          ref: ref_command, amount, commission, receiverAmt,
          rate: COMMISSION_RATE, receiverUid: meta.busUid,
          passengerUid: uid, gie: meta.gie, vehicle: meta.vehicle,
          ts: FV.serverTimestamp()
        });

        console.log(`✅ Ticket : ${uid} -${amount} FCFA | receveur +${receiverAmt} | TataPay +${commission}`);
      }

      t.update(txRef, {
        status: 'credited', method: finalMethod,
        creditedAt: FV.serverTimestamp()
      });
    });

    res.status(200).send('OK');

  } catch (err) {
    console.error('❌ Erreur IPN:', err.message);
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

    res.json({ payload, signature, maxOffline: MAX_OFFLINE_PER_QR });

  } catch (err) {
    console.error('❌ Erreur QR offline:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
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

    const valid   = safeEqual(expectedSig, signature);
    const expired = Date.now() > payload.expiresAt;

    res.json({ valid, expired, maxOffline: MAX_OFFLINE_PER_QR });
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── SYNC TRANSACTIONS HORS-LIGNE ──
// Corrections : prix entier strictement positif (un prix négatif inversait le
// transfert), le receveur qui synchronise est obligatoirement le bénéficiaire
// (receiverUid == req.uid), identifiant syncRef contrôlé.
app.post('/api/offline/sync', verifyToken, requireOfflineSecret, limiter, async (req, res) => {
  const { transactions } = req.body;
  if (!transactions || !Array.isArray(transactions) || transactions.length > 200) {
    return res.status(400).json({ error: 'Tableau de transactions manquant ou trop grand' });
  }

  const results = [];

  for (const tx of transactions) {
    const { payload, signature, price, syncRef } = tx || {};

    try {
      if (!/^[A-Za-z0-9_-]{6,80}$/.test(String(syncRef || ''))) {
        results.push({ syncRef: null, status: 'rejected', reason: 'Référence invalide' });
        continue;
      }
      if (!payload || typeof payload.uid !== 'string' || typeof signature !== 'string') {
        results.push({ syncRef, status: 'rejected', reason: 'Données invalides' });
        continue;
      }
      if (!Number.isInteger(price) || price <= 0 || price > 1000) {
        results.push({ syncRef, status: 'rejected', reason: 'Montant invalide (entier entre 1 et 1000 FCFA)' });
        continue;
      }

      // Le bénéficiaire est toujours l'utilisateur authentifié
      const receiverUid = req.uid;
      if (payload.uid === receiverUid) {
        results.push({ syncRef, status: 'rejected', reason: 'Auto-paiement interdit' });
        continue;
      }

      const expectedSig = crypto
        .createHmac('sha256', OFFLINE_SECRET)
        .update(JSON.stringify(payload))
        .digest('hex');

      if (!safeEqual(expectedSig, signature)) {
        results.push({ syncRef, status: 'rejected', reason: 'Signature invalide' });
        continue;
      }

      if (Date.now() > payload.expiresAt + 24 * 60 * 60 * 1000) {
        results.push({ syncRef, status: 'rejected', reason: 'QR expiré' });
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
          t.get(passengerRef), t.get(sessionRef), t.get(receiverRef)
        ]);

        if (!receiverSnap.exists || receiverSnap.data().role !== 'receiver') {
          rejection = 'Bénéficiaire non autorisé';
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

        t.update(passengerRef, { balance: FV.increment(-price) });
        t.set(passHistRef, {
          type: 'ticket_offline', label: `Ticket hors-ligne — ${syncRef}`,
          amount: -price, ref: syncRef, ts: FV.serverTimestamp()
        });
        t.update(receiverRef, { balance: FV.increment(price) });
        t.set(recvHistRef, {
          type: 'collect_offline', label: `Collecte hors-ligne — ${syncRef}`,
          amount: price, ref: syncRef, ts: FV.serverTimestamp()
        });
        t.set(offlineTxRef, {
          passengerUid: payload.uid, receiverUid, price, syncRef,
          syncedAt: FV.serverTimestamp(), status: 'synced'
        });
        t.set(sessionRef, {
          uid: payload.uid, issuedAt: payload.issuedAt,
          totalSpent: alreadySpent + price,
          updatedAt: FV.serverTimestamp()
        }, { merge: true });
      });

      if (rejection) {
        results.push({ syncRef, status: 'rejected', reason: rejection });
        continue;
      }

      results.push({ syncRef, status: 'synced' });

    } catch (err) {
      console.error(`❌ Erreur sync ${syncRef}:`, err.message);
      results.push({ syncRef, status: 'error', reason: 'Erreur serveur' });
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
// Correctif : une demande ne peut plus écraser un compte existant (rôle/solde).

app.post('/api/owners/request', verifyToken, limiter, async (req, res) => {
  const uid = req.uid;
  const { name, phone, email, companyName, busCount } = req.body;
  if (!name || !phone || !email) {
    return res.status(400).json({ error: 'Nom, téléphone et email sont obligatoires' });
  }
  try {
    const existing = await db.collection('users').doc(uid).get();
    if (existing.exists) {
      return res.status(409).json({ error: 'Ce compte existe déjà' });
    }
    await db.collection('users').doc(uid).set({
      uid, name, phone, email,
      companyName: companyName || '',
      busCount:    busCount || 1,
      role:        'owner',
      status:      'pending',
      balance:     0,
      createdAt:   FV.serverTimestamp()
    });
    res.json({ message: 'Demande envoyée. En attente de validation par l\'administrateur.' });
  } catch (err) {
    console.error('❌ Erreur demande propriétaire:', err.message);
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
      status: 'active', approvedAt: FV.serverTimestamp()
    });
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
      rejectedAt: FV.serverTimestamp(), rejectedBy: req.uid
    });
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
      busCount: d.data().busCount || 0
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
    const existing = await db.collection('users').doc(uid).get();
    if (existing.exists) {
      return res.status(409).json({ error: 'Ce compte existe déjà' });
    }
    await db.collection('users').doc(uid).set({
      uid, name, phone, email, ownerUid,
      ownerName: ownerSnap.data().name,
      role:      'receiver',
      status:    'pending',
      balance:   0,
      createdAt: FV.serverTimestamp()
    });
    res.json({ message: 'Demande envoyée. En attente de validation par le propriétaire.' });
  } catch (err) {
    console.error('❌ Erreur demande receveur:', err.message);
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
      status: 'active', approvedAt: FV.serverTimestamp(), approvedBy: req.uid
    });
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
      rejectedAt: FV.serverTimestamp(), rejectedBy: req.uid
    });
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
      batch.update(d.ref, { status: 'suspended', suspendedAt: FV.serverTimestamp() });
    });
    batch.delete(db.collection('users').doc(ownerUid));
    await batch.commit();
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
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
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
// ════════════════════════════════════════════════════════════
const { GoogleGenAI } = require('@google/genai');

const GEMINI_API_KEY = (process.env.GEMINI_API_KEY || '').trim();
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
    res.json({ answer, lang: lang === 'wo' ? 'wo' : 'fr' });

  } catch (err) {
    console.error('❌ Erreur assistant Gemini:', err.message);
    res.status(500).json({ error: 'Assistant indisponible' });
  }
});

// ── DÉMARRAGE SERVEUR ──
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ TataPay Backend démarré — port ${PORT} | env: ${PAYTECH_ENV}`);
  console.log(`🔒 Offline   : secret ${OFFLINE_SECRET ? 'configuré ✓' : 'MANQUANT ⚠️ (routes désactivées)'} | plafond cumulé ${MAX_OFFLINE_PER_QR} F/QR`);
  console.log(`💸 Retrait  : /api/withdraw (mode ${PAYOUT_MODE}) — réservation atomique + remboursement auto ✓`);

  setInterval(() => {
    https.get('https://tatapay-backend-1.onrender.com/ping', () => {})
         .on('error', () => {});
  }, 9 * 60 * 1000);
});
