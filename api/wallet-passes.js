const { createClient } = require('@supabase/supabase-js');

// GET /v1/devices/{deviceLibraryIdentifier}/registrations/{passTypeIdentifier}?passesUpdatedSince={tag}
module.exports = async (req, res) => {
  if (req.method !== 'GET') return res.status(405).end();

  try {
    const { deviceLibraryIdentifier, passTypeIdentifier, passesUpdatedSince } = req.query;
    if (!deviceLibraryIdentifier || !passTypeIdentifier) {
      return res.status(400).json({ error: 'Paramètres manquants' });
    }

    const supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SERVICE_KEY
    );

    let query = supabase
      .from('wallet_registrations')
      .select('user_id, commercant_id, updated_at')
      .eq('device_library_id', deviceLibraryIdentifier)
      .eq('pass_type_id', passTypeIdentifier);

    if (passesUpdatedSince) {
      query = query.gt('updated_at', passesUpdatedSince);
    }

    const { data, error } = await query;
    if (error) throw error;

    if (!data?.length) {
      return res.status(204).end();
    }

    const serialNumbers = data.map(r => `${r.user_id}_${r.commercant_id}`);
    const lastUpdated = data.reduce((max, r) => (r.updated_at > max ? r.updated_at : max), data[0].updated_at);

    return res.status(200).json({ lastUpdated, serialNumbers });
  } catch (e) {
    console.error('[wallet-passes] error:', e);
    return res.status(500).json({ error: String(e) });
  }
};
