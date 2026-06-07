const { createClient } = require('@supabase/supabase-js');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY
  );

  // POST → enregistrer l'appareil
  // URL: /v1/devices/{deviceLibraryId}/registrations/{passTypeId}/{serialNumber}
  if (req.method === 'POST') {
    try {
      const { deviceLibraryIdentifier, passTypeIdentifier, serialNumber } = req.query;
      const { pushToken } = req.body || {};

      if (!deviceLibraryIdentifier || !passTypeIdentifier || !serialNumber || !pushToken) {
        return res.status(400).json({ error: 'Paramètres manquants' });
      }

      const [user_id, commercant_id] = serialNumber.split('_');

      await supabase.from('wallet_registrations').upsert({
        user_id,
        commercant_id,
        push_token: pushToken,
        device_library_id: deviceLibraryIdentifier,
        pass_type_id: passTypeIdentifier,
        updated_at: new Date().toISOString(),
      }, { onConflict: 'device_library_id,pass_type_id' });

      return res.status(201).end();
    } catch (e) {
      console.error('[wallet-register] POST error:', e);
      return res.status(500).json({ error: String(e) });
    }
  }

  // DELETE → désinscrire l'appareil
  if (req.method === 'DELETE') {
    try {
      const { deviceLibraryIdentifier, passTypeIdentifier } = req.query;
      await supabase.from('wallet_registrations')
        .delete()
        .eq('device_library_id', deviceLibraryIdentifier)
        .eq('pass_type_id', passTypeIdentifier);
      return res.status(200).end();
    } catch (e) {
      return res.status(500).json({ error: String(e) });
    }
  }

  return res.status(405).end();
};
