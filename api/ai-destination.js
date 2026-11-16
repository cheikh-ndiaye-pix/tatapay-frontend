// Vercel serverless : /api/ai-destination
// Variables d'environnement à ajouter dans Vercel :
//   ANTHROPIC_API_KEY  (clé Claude, jamais dans le HTML)
//   FIREBASE_API_KEY   (la apiKey publique de ton projet Firebase, sert à vérifier le passager connecté)
const MODEL = 'claude-haiku-5-5';

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
}

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });
  try {
    // 1) Seul un utilisateur TataPay connecté peut appeler l'IA (évite que quelqu'un vide ton crédit)
    const idToken = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (!idToken) return res.status(401).json({ error: 'no token' });
    const v = await fetch('https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=' + process.env.FIREBASE_API_KEY, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ idToken })
    });
    if (!v.ok) return res.status(401).json({ error: 'bad token' });

    // 2) Entrées : ce que le passager a dit + les destinations de CE bus
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});
    const said = String(body.said || '').slice(0, 300);
    const options = (Array.isArray(body.options) ? body.options : []).slice(0, 40).map(x => String(x).slice(0, 80));
    if (!said || !options.length) return res.status(400).json({ error: 'missing data' });

    const system =
      "Tu es l'assistant d'un bus de transport en commun à Dakar (Sénégal). Un passager dit où il veut aller, " +
      "en wolof, français, anglais ou un mélange, avec des fautes de transcription vocale possibles. " +
      "On te donne la liste numérotée des destinations desservies par CE bus. " +
      "Réponds UNIQUEMENT par un JSON {\"index\": <numéro>} si une destination de la liste correspond clairement au lieu demandé " +
      "(même écrit autrement : « Libertay sis » = Liberté 6), ou {\"index\": null} si aucune ne correspond. " +
      "N'invente rien. En cas de doute entre deux lieux différents, réponds null.";
    const user = 'Le passager a dit : « ' + said + ' »\nDestinations du bus :\n' + options.map((o, i) => i + '. ' + o).join('\n');

    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: MODEL, max_tokens: 40, system, messages: [{ role: 'user', content: user }] })
    });
    if (!r.ok) return res.status(502).json({ error: 'llm ' + r.status });
    const j = await r.json();
    const txt = (j.content && j.content[0] && j.content[0].text) || '';
    const m = txt.match(/\{[^}]*\}/);
    let index = null;
    if (m) { try { const p = JSON.parse(m[0]).index; if (Number.isInteger(p) && p >= 0 && p < options.length) index = p; } catch (e) {} }
    return res.status(200).json({ index });
  } catch (e) {
    return res.status(500).json({ error: 'server' });
  }
};
