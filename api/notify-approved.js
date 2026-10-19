// Vercel Serverless Function — email « candidature validée » envoyé par TataPay
// Variables d'environnement à créer dans Vercel : GMAIL_USER, GMAIL_APP_PASSWORD
const nodemailer = require('nodemailer');

const PROJECT = 'tatapay-a4972';
const API_KEY = 'AIzaSyDeCSeZHu9-rsPYpwEJiVfbM0nX8cwD22o'; // clé web publique Firebase
const esc = t => String(t == null ? '' : t).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const val = f => (f && (f.stringValue ?? f.integerValue ?? f.timestampValue)) || '';

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  try {
    const idToken = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    const { receiverUid } = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});
    if (!idToken || !receiverUid) return res.status(400).json({ error: 'missing params' });

    // 1) Qui appelle ? (vérification du jeton Firebase)
    const who = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${API_KEY}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ idToken })
    }).then(r => r.json());
    const callerUid = who.users && who.users[0] && who.users[0].localId;
    if (!callerUid) return res.status(401).json({ error: 'invalid token' });

    // 2) Le receveur vient-il bien d'être accepté PAR CET appelant ? (lecture avec le jeton de l'appelant)
    const fs = f => fetch(`https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/users/${f}`,
      { headers: { Authorization: 'Bearer ' + idToken } }).then(r => r.json());
    const [recv, owner] = await Promise.all([fs(receiverUid), fs(callerUid)]);
    const r = recv.fields || {}, o = owner.fields || {};
    if (val(r.status) !== 'approved' || val(r.approvedOwnerUid) !== callerUid)
      return res.status(403).json({ error: 'not approved by caller' });
    const approvedAt = val(r.approvedAt);
    if (approvedAt && Date.now() - new Date(approvedAt).getTime() > 10 * 60 * 1000)
      return res.status(403).json({ error: 'approval too old' });

    // 3) L'email part vers l'adresse enregistrée sur le profil du receveur (jamais une adresse fournie par le client)
    const to = val(r.email), name = val(r.name) || 'Receveur', ownerName = val(o.name) || 'Un propriétaire de bus';
    if (!to) return res.status(422).json({ error: 'no email' });
    const bus = `${val(r.vehicle)} · Ligne ${val(r.ligne)}`;
    const mail = nodemailer.createTransport({ service: 'gmail', auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD } });
    await mail.sendMail({
      from: `"TataPay" <${process.env.GMAIL_USER}>`,
      to,
      subject: 'TataPay — Votre candidature a été validée ✅',
      text: `Bonjour ${name},\n\n${ownerName} a validé votre candidature.\nBus : ${bus} · ${val(r.trajet)} · Zone ${val(r.zone)} · GIE ${val(r.gie)}\n\nConnectez-vous à l'application TataPay pour commencer.\n\nL'équipe TataPay`,
      html: `<p>Bonjour <b>${esc(name)}</b>,</p><p><b>${esc(ownerName)}</b> a validé votre candidature.</p><p>🚌 ${esc(bus)}<br>🛣️ ${esc(val(r.trajet))} · Zone ${esc(val(r.zone))}<br>🏢 GIE ${esc(val(r.gie))}</p><p>Connectez-vous à l'application TataPay pour commencer.</p><p>— L'équipe TataPay</p>`
    });
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
};
