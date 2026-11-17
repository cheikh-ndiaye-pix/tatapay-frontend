// seed_sentinel.js : crée 35 jours de VENTES D'ESSAI pour un receveur, afin que Sentinel ait un historique.
//
//   node seed_sentinel.js <email_receveur>            -> SIMULATION : n'écrit rien, affiche le résumé
//   node seed_sentinel.js <email_receveur> --go       -> écrit les ventes et versements d'essai
//   node seed_sentinel.js --clean --go                -> supprime TOUT ce que ce script a créé
//
// Les documents portent seed:'sentinel-demo'. Ce sont de FAUSSES données : dis « ventes d'essai » au jury.
// Les soldes (balance) ne sont jamais modifiés. Clé de service : GOOGLE_APPLICATION_CREDENTIALS ou ./serviceAccountKey.json

const TAG = 'sentinel-demo';
const DAYS = 35;

// Générateur pseudo-aléatoire déterministe (même résultat à chaque lancement)
function rng(seed) {
  let s = seed | 0;
  return () => {
    s = (s + 0x6D2B79F5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Retourne la liste des jours, du plus ancien (index 0 = il y a 35 jours) au plus récent (index 34 = hier).
// Chaque jour : { date:Date, tickets:[{price,payMode,time}], paid:<espèces versées ce jour-là> }
function generate(seed = 7) {
  const r = rng(seed);
  const today = new Date(); today.setUTCHours(0, 0, 0, 0);
  const prices = [100, 150, 200, 250];
  const days = [];
  for (let i = 0; i < DAYS; i++) {
    const date = new Date(today.getTime() - (DAYS - i) * 864e5); // i=34 -> hier
    const back = DAYS - i;                                       // 1 = hier, 3 = il y a 3 jours, 9 = il y a 9 jours
    const dow = date.getUTCDay();
    let n = Math.round(90 * (dow === 0 ? 0.7 : dow === 6 ? 0.85 : 1) * (0.93 + r() * 0.14));
    if (back === 1) n = Math.round(n * 0.35);                    // SITUATION 1 : chute de recettes hier
    const tickets = [];
    let cash = 0;
    for (let k = 0; k < n; k++) {
      const price = prices[Math.floor(r() * prices.length)];
      const payMode = r() < 0.5 ? 'especes' : 'wallet';
      if (payMode === 'especes') cash += price;
      const mins = 6 * 60 + Math.floor(r() * 12 * 60);
      tickets.push({ price, payMode, time: String(Math.floor(mins / 60)).padStart(2, '0') + ':' + String(mins % 60).padStart(2, '0') });
    }
    days.push({ date, back, tickets, cash, paid: 0 });
  }
  // Versements d'espèces : normalement 97 à 100 % du jour, versés le jour même.
  days.forEach(d => { d.paid = Math.round(d.cash * (0.97 + r() * 0.03)); });
  // SITUATION 2 : versement incomplet il y a 3 jours (30 % seulement), rattrapé pas du tout le lendemain
  const d3 = days.find(d => d.back === 3); d3.paid = Math.round(d3.cash * 0.30);
  // SITUATION 3 : retard LÉGITIME il y a 9 jours : rien versé ce jour-là, tout rattrapé le lendemain (ne doit PAS être signalé)
  const d9 = days.find(d => d.back === 9), d8 = days.find(d => d.back === 8);
  d8.paid = d8.cash + d9.cash; d9.paid = 0;
  return days;
}

module.exports = { generate, DAYS, TAG };
if (require.main !== module) return;

(async () => {
  const args = process.argv.slice(2);
  const GO = args.includes('--go'), CLEAN = args.includes('--clean');
  const email = args.find(a => !a.startsWith('--'));
  const fs = require('fs'), path = require('path');
  const { initializeApp, cert } = require('firebase-admin/app');
  const { getFirestore, Timestamp } = require('firebase-admin/firestore');
  const { getAuth } = require('firebase-admin/auth');
  const keyPath = process.env.GOOGLE_APPLICATION_CREDENTIALS || './serviceAccountKey.json';
  if (!fs.existsSync(keyPath)) { console.error('Clé de service introuvable : ' + keyPath); process.exit(1); }
  initializeApp({ credential: cert(require(path.resolve(keyPath))) });
  const db = getFirestore(), TS = Timestamp;

  const commit = async ops => { for (let i = 0; i < ops.length; i += 400) { const b = db.batch(); ops.slice(i, i + 400).forEach(f => f(b)); await b.commit(); } };

  if (CLEAN) {
    const refs = [];
    for (const col of ['tickets', 'versements']) (await db.collection(col).where('seed', '==', TAG).get()).forEach(d => refs.push(d.ref));
    console.log(refs.length + ' document(s) d\'essai trouvé(s).');
    if (!GO) { console.log('SIMULATION : rien supprimé. Relance avec --clean --go.'); return; }
    await commit(refs.map(ref => b => b.delete(ref)));
    console.log('Supprimés.'); return;
  }

  if (!email) { console.error('Usage : node seed_sentinel.js <email_receveur> [--go]   |   node seed_sentinel.js --clean --go'); process.exit(1); }
  const user = await getAuth().getUserByEmail(email);
  const snap = await db.collection('users').doc(user.uid).get();
  if (!snap.exists) { console.error('Profil Firestore introuvable pour ' + email); process.exit(1); }
  const p = snap.data();
  if (p.role !== 'receiver') { console.error('Ce compte n\'est pas un receveur (role=' + p.role + ').'); process.exit(1); }
  const ownerUid = p.approvedOwnerUid || p.ownerUid || p.chauffeurUid || '';
  if (!ownerUid) { console.error('Aucun propriétaire/chauffeur relié à ce receveur : Sentinel ne le verrait pas. Approuve-le d\'abord.'); process.exit(1); }
  if (!['approved', 'active'].includes(p.status)) { console.error('Receveur non approuvé (status=' + p.status + ').'); process.exit(1); }

  const days = generate();
  const nT = days.reduce((a, d) => a + d.tickets.length, 0), cash = days.reduce((a, d) => a + d.cash, 0);
  console.log('Receveur : ' + (p.name || email) + ' | bus ' + (p.vehicle || '—') + ' | relié à ' + ownerUid);
  console.log(DAYS + ' jours, ' + nT + ' tickets, ' + days.length + ' versements, espèces dues ' + cash + ' F.');
  console.log('Situations : chute de recettes hier ; versement incomplet il y a 3 jours ; retard légitime il y a 9 jours.');
  if (!GO) { console.log('SIMULATION : rien écrit. Relance avec --go.'); return; }

  const ops = []; let n = 0;
  days.forEach((d, di) => {
    const ymd = d.date.toISOString().slice(0, 10);
    const fr = d.date.toLocaleDateString('fr-FR', { timeZone: 'UTC' });
    d.tickets.forEach((t, k) => {
      const [h, m] = t.time.split(':').map(Number);
      const ts = TS.fromDate(new Date(d.date.getTime() + (h * 60 + m) * 60000));
      ops.push(b => b.set(db.collection('tickets').doc('seed_' + user.uid.slice(0, 6) + '_' + ymd + '_' + k), {
        busUid: user.uid, price: t.price, commission: 0, payMode: t.payMode, passengerName: 'Essai',
        gie: p.gie || '', vehicle: p.vehicle || '', ligne: p.ligne || '', zone: p.zone || '', from: '', to: '', section: 1,
        date: fr, time: t.time, sn: 'SEED' + (++n), ts, seed: TAG
      }));
    });
    if (d.paid > 0) {
      const ts = TS.fromDate(new Date(d.date.getTime() + 19 * 3600000));
      ops.push(b => b.set(db.collection('versements').doc('seed_' + user.uid.slice(0, 6) + '_' + ymd), {
        amount: d.paid, mode: 'especes', note: 'versement d\'essai', ref: 'SEED-' + ymd, date: fr,
        receiverUid: user.uid, receiverName: p.name || '', ownerUid, status: 'confirmed', ts, confirmedAt: ts, seed: TAG
      }));
    }
  });
  await commit(ops);
  console.log('Écrit : ' + ops.length + ' documents d\'essai. Ouvre l\'accueil du compte chauffeur/propriétaire : Sentinel doit afficher des alertes.');
})().catch(e => { console.error('Erreur :', e.message); process.exit(1); });
