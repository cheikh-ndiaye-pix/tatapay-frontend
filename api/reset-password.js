// Vercel Serverless Function — email « mot de passe oublié » envoyé par TataPay (depuis Gmail)
// Variables d'environnement : GMAIL_USER, GMAIL_APP_PASSWORD + le compte de service Firebase déjà utilisé par vos autres fonctions
const nodemailer = require('nodemailer');
const admin = require('firebase-admin');

function initAdmin() {
  if (admin.apps.length) return;
  // ⚠️ Utilisez le MÊME nom de variable que dans votre fichier api/withdraw (compte de service Firebase)
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT || process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  admin.initializeApp({ credential: admin.credential.cert(JSON.parse(raw)) });
}
const esc = t => String(t == null ? '' : t).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const last = new Map(); // anti-abus : 1 email / minute / adresse

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });
  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});
    const email = String(body.email || '').trim().toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'invalid email' });
    const now = Date.now();
    if (last.get(email) && now - last.get(email) < 60000) return res.status(429).json({ error: 'wait' });
    last.set(email, now);

    initAdmin();
    let link;
    try { link = await admin.auth().generatePasswordResetLink(email); }
    catch (e) { return res.status(200).json({ ok: true }); } // compte inconnu : réponse neutre (pas de fuite d'info)

    const mail = nodemailer.createTransport({ service: 'gmail', auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD } });
    await mail.sendMail({
      from: `"TataPay" <${process.env.GMAIL_USER}>`,
      to: email,
      subject: 'TataPay — Réinitialisation de votre mot de passe',
      text: `Bonjour,\n\nVous avez demandé à changer votre mot de passe TataPay.\nOuvrez ce lien pour en choisir un nouveau :\n${link}\n\nSi vous n'êtes pas à l'origine de cette demande, ignorez ce message.\n\nL'équipe TataPay`,
      html: `<p>Bonjour,</p><p>Vous avez demandé à changer votre mot de passe <b>TataPay</b>.</p><p><a href="${esc(link)}" style="background:#009A44;color:#fff;padding:12px 20px;border-radius:8px;text-decoration:none;font-weight:bold;">Choisir un nouveau mot de passe</a></p><p style="color:#888;font-size:12px;">Si vous n'êtes pas à l'origine de cette demande, ignorez ce message.</p><p>— L'équipe TataPay</p>`
    });
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
};
