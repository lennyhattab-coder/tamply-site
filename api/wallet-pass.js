const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const { genererPkpass } = require('./wallet');

function authToken(serialNumber) {
  return crypto.createHash('sha256').update(serialNumber).digest('hex').substring(0, 32);
}

// GET /v1/passes/{passTypeIdentifier}/{serialNumber}
// Header requis : Authorization: ApplePass <authenticationToken>
module.exports = async (req, res) => {
  if (req.method !== 'GET') return res.status(405).end();

  try {
    const { passTypeIdentifier, serialNumber } = req.query;
    if (!passTypeIdentifier || !serialNumber) {
      return res.status(400).json({ error: 'Paramètres manquants' });
    }

    const authHeader = req.headers['authorization'] || '';
    const expected = `ApplePass ${authToken(serialNumber)}`;
    if (authHeader !== expected) {
      return res.status(401).end();
    }

    const [user_id, commercant_id] = serialNumber.split('_');
    if (!user_id || !commercant_id) {
      return res.status(400).json({ error: 'serialNumber invalide' });
    }

    const supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SERVICE_KEY
    );

    const { data: carte, error } = await supabase
      .from('cartes_fidelite')
      .select('points, tampons, ligue, commercants(nom, photo_url, systeme, points_max, carte_couleur_principale)')
      .eq('client_id', user_id)
      .eq('commercant_id', commercant_id)
      .single();
    if (error || !carte) return res.status(404).end();

    const commercant = carte.commercants;
    const pointsActuels = commercant?.systeme === 'points' ? (carte.points ?? 0) : (carte.tampons ?? 0);

    const { data: registration } = await supabase
      .from('wallet_registrations')
      .select('updated_at')
      .eq('user_id', user_id)
      .eq('commercant_id', commercant_id)
      .order('updated_at', { ascending: false })
      .limit(1)
      .maybeSingle();

    const lastModified = registration?.updated_at ? new Date(registration.updated_at) : new Date();

    const ifModifiedSince = req.headers['if-modified-since'];
    if (ifModifiedSince && new Date(ifModifiedSince) >= lastModified) {
      return res.status(304).end();
    }

    const buf = await genererPkpass({
      user_id, commercant_id,
      nom_commerce: commercant?.nom || 'Commerce',
      points: pointsActuels,
      max: commercant?.points_max || 10,
      ligue: carte.ligue || 'Bronze',
      systeme: commercant?.systeme || 'tampons',
      couleur: commercant?.carte_couleur_principale,
      photo_url: commercant?.photo_url,
    });

    res.setHeader('Content-Type', 'application/vnd.apple.pkpass');
    res.setHeader('Last-Modified', lastModified.toUTCString());
    return res.status(200).send(buf);
  } catch (e) {
    console.error('[wallet-pass] error:', e);
    return res.status(500).json({ error: String(e) });
  }
};
