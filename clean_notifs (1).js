// clean_notifs.js : nettoie les notifications de test d'un compte TataPay.
//
// Utilisation (dans le dossier de ton backend, là où firebase-admin est installé) :
//   node clean_notifs.js fama2@gmail.com            -> SIMULATION : n'efface rien, affiche ce qui serait supprimé
//   node clean_notifs.js fama2@gmail.com --go       -> supprime les candidatures en double (garde la plus récente par receveur)
//   node clean_notifs.js fama2@gmail.com --all --go -> supprime TOUTES les notifications de ce compte
//
// Clé de service Firebase : variable GOOGLE_APPLICATION_CREDENTIALS, ou fichier ./serviceAccountKey.json

const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');
const { getAuth } = require('firebase-admin/auth');
const fs = require('fs');

const args = process.argv.slice(2);
const email = args.find(a => !a.startsWith('--'));
const GO = args.includes('--go');
const ALL = args.includes('--all');

if (!email) {
  console.error('Usage : node clean_notifs.js <email> [--all] [--go]');
  process.exit(1);
}

const keyPath = process.env.GOOGLE_APPLICATION_CREDENTIALS || './serviceAccountKey.json';
if (!fs.existsSync(keyPath)) {
  console.error('Clé de service introuvable : ' + keyPath);
  console.error('Mets ton fichier de clé ici, ou définis GOOGLE_APPLICATION_CREDENTIALS.');
  process.exit(1);
}
initializeApp({ credential: cert(require(require('path').resolve(keyPath))) });
const db = getFirestore();

(async () => {
  const user = await getAuth().getUserByEmail(email);
  console.log('Compte : ' + email + ' (uid ' + user.uid + ')');

  const snap = await db.collection('notifications').where('toUid', '==', user.uid).get();
  const docs = snap.docs.map(d => ({ ref: d.ref, id: d.id, ...d.data() }));
  console.log(docs.length + ' notification(s) trouvée(s).');

  const byType = {};
  docs.forEach(n => { byType[n.type || '?'] = (byType[n.type || '?'] || 0) + 1; });
  console.log('Par type :', byType);

  let toDelete = [];
  if (ALL) {
    toDelete = docs;
  } else {
    // candidatures en double : même receveur, on garde la plus récente
    const groups = {};
    docs.filter(n => n.type === 'receiver_candidature').forEach(n => {
      const k = n.receiverUid || n.receiverEmail || n.id;
      (groups[k] = groups[k] || []).push(n);
    });
    const millis = n => (n.ts && n.ts.toMillis ? n.ts.toMillis() : 0);
    Object.values(groups).forEach(list => {
      list.sort((a, b) => millis(b) - millis(a));
      toDelete.push(...list.slice(1));
    });
  }

  console.log((GO ? 'À supprimer : ' : 'SIMULATION, serait supprimé : ') + toDelete.length);
  toDelete.slice(0, 20).forEach(n => console.log(' - ' + n.id + ' | ' + (n.type || '?') + ' | ' + (n.receiverName || n.message || '')));
  if (toDelete.length > 20) console.log(' … et ' + (toDelete.length - 20) + ' autres');

  if (!GO) {
    console.log('Rien n\'a été effacé. Relance avec --go pour supprimer.');
    return;
  }
  for (let i = 0; i < toDelete.length; i += 400) {
    const batch = db.batch();
    toDelete.slice(i, i + 400).forEach(n => batch.delete(n.ref));
    await batch.commit();
  }
  console.log('Terminé : ' + toDelete.length + ' notification(s) supprimée(s).');
})().catch(e => { console.error('Erreur :', e.message); process.exit(1); });
