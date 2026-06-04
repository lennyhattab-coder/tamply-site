const { PKPass } = require('passkit-generator');

async function genererPkpass(params) {
  const {
    user_id, commercant_id, nom_commerce,
    points, max, ligue, systeme,
    couleur, photo_url
  } = params;

  const p12b64 = process.env.APPLE_PASS_CERTIFICATE;
  const password =
    process.env.APPLE_PASS_CERTIFICATE_PASSWORD;
  if (!p12b64) throw new Error('Certificat manquant');

  const label = systeme === 'points'
    ? 'points' : 'tampons';
  const pts = parseInt(points) || 0;
  const mx = parseInt(max) || 10;
  const restants = Math.max(0, mx - pts);
  const tamponsFilled = '●'.repeat(Math.min(pts, mx));
  const tamponsEmpty = '○'.repeat(restants);
  const tamponsVisuel = tamponsFilled + tamponsEmpty;

  // Télécharger WWDR Apple
  const wwdrResp = await fetch(
    'https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer'
  );
  const wwdrBuffer = Buffer.from(
    await wwdrResp.arrayBuffer());

  // Icône minimale
  const iconB64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVQI12NgAAIABQAABjkB6QAAAAAASUVORK5CYII=';
  const iconBuffer = Buffer.from(iconB64, 'base64');

  // Couleur de fond
  let backgroundColor = 'rgb(79, 70, 229)';
  if (couleur) {
    const clean = couleur.replace(/^#/, '');
    if (/^[0-9a-f]{6}$/i.test(clean)) {
      const r = parseInt(clean.slice(0,2), 16);
      const g = parseInt(clean.slice(2,4), 16);
      const b = parseInt(clean.slice(4,6), 16);
      backgroundColor = `rgb(${r}, ${g}, ${b})`;
    }
  }

  const pass = await PKPass.from({
    model: {
      'pass.json': Buffer.from(JSON.stringify({
        formatVersion: 1,
        passTypeIdentifier:
          'pass.com.lensk0.fidelityapp',
        serialNumber:
          `${user_id}_${commercant_id}`,
        teamIdentifier: 'PSU4H69TXL',
        organizationName: 'Tamply',
        description:
          `Carte ${nom_commerce} — Tamply`,
        logoText: nom_commerce || 'Tamply',
        foregroundColor: 'rgb(238, 238, 248)',
        backgroundColor,
        labelColor: 'rgb(200, 200, 220)',
        storeCard: {
          primaryFields: [{
            key: 'tampons',
            label: 'Progression',
            value: tamponsVisuel
          }],
          secondaryFields: [
            { key: 'commerce',
              label: 'Commerce',
              value: nom_commerce },
            { key: 'points',
              label: `${pts}/${mx}`,
              value: ligue || 'Bronze' }
          ],
          auxiliaryFields: [{
            key: 'prochaine',
            label: restants === 0
              ? 'Récompense disponible !'
              : `Plus que ${restants} tampon${restants > 1 ? 's' : ''}`,
            value: ''
          }],
          backFields: [{
            key: 'info',
            label: 'Comment ça marche',
            value: 'Présentez ce QR code en caisse pour gagner des tampons de fidélité.'
          }]
        },
        barcode: {
          message: `tamply://wallet/${user_id}/${commercant_id}`,
          format: 'PKBarcodeFormatQR',
          messageEncoding: 'iso-8859-1'
        },
        barcodes: [{
          message: `tamply://wallet/${user_id}/${commercant_id}`,
          format: 'PKBarcodeFormatQR',
          messageEncoding: 'iso-8859-1'
        }]
      })),
      'icon.png': iconBuffer,
      'icon@2x.png': iconBuffer,
    },
    certificates: {
      wwdr: wwdrBuffer,
      signerCert: Buffer.from(p12b64, 'base64'),
      signerKey: Buffer.from(p12b64, 'base64'),
      signerKeyPassphrase: password,
    }
  });

  // Strip image = photo du commerce
  if (photo_url) {
    try {
      const stripResp = await fetch(photo_url,
        { signal: AbortSignal.timeout(5000) });
      if (stripResp.ok) {
        const stripBuf = Buffer.from(
          await stripResp.arrayBuffer());
        pass.addBuffer('strip.png', stripBuf);
        pass.addBuffer('strip@2x.png', stripBuf);
      }
    } catch (e) {
      console.warn('Strip fetch échoué:', e.message);
    }
  }

  const stream = pass.generate();
  const chunks = [];
  for await (const chunk of stream) chunks.push(chunk);
  return Buffer.concat(chunks);
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods',
    'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers',
    'Content-Type, Authorization');
  if (req.method === 'OPTIONS')
    return res.status(200).end();

  if (req.method === 'GET') {
    try {
      const {
        user_id, commercant_id, nom_commerce,
        points, max, ligue, systeme,
        couleur, photo_url
      } = req.query;

      if (!user_id || !commercant_id) {
        return res.status(400).json(
          { error: 'user_id et commercant_id requis' });
      }

      const buf = await genererPkpass({
        user_id, commercant_id,
        nom_commerce: nom_commerce || 'Commerce',
        points: parseInt(points) || 0,
        max: parseInt(max) || 10,
        ligue: ligue || 'Bronze',
        systeme: systeme || 'tampons',
        couleur,
        photo_url,
      });

      res.setHeader('Content-Type',
        'application/vnd.apple.pkpass');
      res.setHeader('Content-Disposition',
        'attachment; filename="tamply.pkpass"');
      return res.status(200).send(buf);
    } catch (e) {
      console.error('GET wallet error:', e);
      return res.status(500).json(
        { error: String(e) });
    }
  }

  if (req.method === 'POST') {
    try {
      const buf = await genererPkpass(req.body);
      return res.status(200).json({
        pkpass: buf.toString('base64')
      });
    } catch (e) {
      console.error('POST wallet error:', e);
      return res.status(500).json(
        { error: String(e) });
    }
  }

  return res.status(405).json(
    { error: 'Method not allowed' });
};
