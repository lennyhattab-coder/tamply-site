// passkit-generator est ESM-only — import() dynamique obligatoire (pas require())
const forge = require('node-forge');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

function extractFromP12(p12b64, password) {
  const p12Der = Buffer.from(p12b64, 'base64').toString('binary');
  const p12Asn1 = forge.asn1.fromDer(p12Der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password || '');

  const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });

  const keyBag = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag][0];
  const certBag = certBags[forge.pki.oids.certBag][0];

  if (!keyBag || !certBag) throw new Error('p12: cert ou clé introuvable');

  return {
    certPem: Buffer.from(forge.pki.certificateToPem(certBag.cert)),
    keyPem: Buffer.from(forge.pki.privateKeyToPem(keyBag.key)),
  };
}

function streamToBuffer(stream) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    stream.on('data', chunk => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', reject);
  });
}

async function genererPkpass(params) {
  const {
    user_id, commercant_id, nom_commerce,
    points, max, ligue, systeme,
    couleur, photo_url
  } = params;

  const p12b64 = process.env.APPLE_PASS_CERTIFICATE;
  const password = process.env.APPLE_PASS_CERTIFICATE_PASSWORD;
  console.log('[wallet] Cert présent:', !!p12b64, '| Password présent:', !!password);
  if (!p12b64) throw new Error('Certificat manquant');

  // Import ESM dynamique — obligatoire car passkit-generator est ESM-only
  const { PKPass } = await import('passkit-generator');

  const pts = parseInt(points) || 0;
  const mx = parseInt(max) || 10;
  const restants = Math.max(0, mx - pts);
  const tamponsFilled = '●'.repeat(Math.min(pts, mx));
  const tamponsEmpty = '○'.repeat(restants);
  const tamponsVisuel = tamponsFilled + tamponsEmpty;

  // Couleur parsée en RGB pour sharp (fallback strip colorée)
  const couleurRgb = { r: 79, g: 70, b: 229 };
  if (couleur) {
    const clean = couleur.replace(/^#/, '');
    if (/^[0-9a-f]{6}$/i.test(clean)) {
      couleurRgb.r = parseInt(clean.slice(0, 2), 16);
      couleurRgb.g = parseInt(clean.slice(2, 4), 16);
      couleurRgb.b = parseInt(clean.slice(4, 6), 16);
    }
  }

  let backgroundColor = 'rgb(79, 70, 229)';
  if (couleur) {
    const clean = couleur.replace(/^#/, '');
    if (/^[0-9a-f]{6}$/i.test(clean)) {
      const r = parseInt(clean.slice(0, 2), 16);
      const g = parseInt(clean.slice(2, 4), 16);
      const b = parseInt(clean.slice(4, 6), 16);
      backgroundColor = `rgb(${r}, ${g}, ${b})`;
    }
  }

  const passJson = {
    formatVersion: 1,
    passTypeIdentifier: 'pass.com.lensk0.fidelityapp',
    serialNumber: `${user_id}_${commercant_id}`,
    teamIdentifier: 'PSU4H69TXL',
    organizationName: 'Tamply',
    description: `Carte ${nom_commerce} — Tamply`,
    logoText: nom_commerce || 'Tamply',
    foregroundColor: 'rgb(238, 238, 248)',
    backgroundColor,
    labelColor: 'rgb(200, 200, 220)',
    coupon: {
      primaryFields: [{
        key: 'tampons',
        label: 'Progression',
        value: tamponsVisuel
      }],
      secondaryFields: [
        { key: 'commerce', label: 'Commerce', value: nom_commerce || '' },
        { key: 'points', label: `${pts}/${mx}`, value: ligue || 'Bronze' }
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
  };

  const iconB64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVQI12NgAAIABQAABjkB6QAAAAAASUVORK5CYII=';
  const iconBuffer = Buffer.from(iconB64, 'base64');

  // Fetch WWDR Apple (DER) → convertir en PEM via node-forge
  const wwdrResp = await fetch('https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer');
  const wwdrDer = Buffer.from(await wwdrResp.arrayBuffer());
  const wwdrCert = forge.pki.certificateFromAsn1(forge.asn1.fromDer(wwdrDer.toString('binary')));
  const wwdrPem = Buffer.from(forge.pki.certificateToPem(wwdrCert));

  // Extraire cert PEM + clé PEM depuis le p12
  const { certPem, keyPem } = extractFromP12(p12b64, password);
  console.log('[wallet] wwdrPem:', wwdrPem.length, 'bytes | certPem:', certPem.length, 'bytes | keyPem:', keyPem.length, 'bytes');

  // Écrire le modèle dans /tmp (seul dossier writable sur Vercel)
  const tempDir = path.join(os.tmpdir(), `tamply_${crypto.randomBytes(8).toString('hex')}.pass`);
  fs.mkdirSync(tempDir, { recursive: true });

  try {
    fs.writeFileSync(path.join(tempDir, 'pass.json'), JSON.stringify(passJson));
    fs.writeFileSync(path.join(tempDir, 'icon.png'), iconBuffer);
    fs.writeFileSync(path.join(tempDir, 'icon@2x.png'), iconBuffer);

    const pass = await PKPass.from({
      model: tempDir,
      certificates: {
        wwdr: wwdrPem,
        signerCert: certPem,
        signerKey: keyPem,
      }
    });

    // strip.png : photo pleine largeur (type coupon) — sharp compatible Vercel
    const sharp = require('sharp');
    const stripFallback = async (w, h) => sharp({
      create: { width: w, height: h, channels: 3, background: couleurRgb }
    }).png().toBuffer();

    if (photo_url) {
      try {
        const imgResp = await fetch(photo_url, { signal: AbortSignal.timeout(5000) });
        if (imgResp.ok) {
          const imgBuf = Buffer.from(await imgResp.arrayBuffer());
          const strip1x = await sharp(imgBuf).resize(375, 123, { fit: 'cover' }).png().toBuffer();
          const strip2x = await sharp(imgBuf).resize(750, 246, { fit: 'cover' }).png().toBuffer();
          pass.addBuffer('strip.png', strip1x);
          pass.addBuffer('strip@2x.png', strip2x);
          console.log('[wallet] Strip image ajoutée avec sharp');
        } else {
          pass.addBuffer('strip.png', await stripFallback(375, 123));
          pass.addBuffer('strip@2x.png', await stripFallback(750, 246));
        }
      } catch (e) {
        console.warn('[wallet] Strip échoué:', e.message);
        try {
          pass.addBuffer('strip.png', await stripFallback(375, 123));
          pass.addBuffer('strip@2x.png', await stripFallback(750, 246));
        } catch (e2) {
          console.warn('[wallet] Fallback strip échoué:', e2.message);
        }
      }
    } else {
      try {
        pass.addBuffer('strip.png', await stripFallback(375, 123));
        pass.addBuffer('strip@2x.png', await stripFallback(750, 246));
      } catch (e) {
        console.warn('[wallet] Strip colorée échouée:', e.message);
      }
    }

    // passkit-generator v3.3.0 : getAsBuffer() (pas generate())
    return await pass.getAsBuffer();

  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  if (req.method === 'GET') {
    try {
      const {
        user_id, commercant_id, nom_commerce,
        points, max, ligue, systeme,
        couleur, photo_url
      } = req.query;

      if (!user_id || !commercant_id) {
        return res.status(400).json({ error: 'user_id et commercant_id requis' });
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

      res.setHeader('Content-Type', 'application/vnd.apple.pkpass');
      res.setHeader('Content-Disposition', 'attachment; filename="tamply.pkpass"');
      return res.status(200).send(buf);
    } catch (e) {
      console.error('[wallet] GET error:', e);
      return res.status(500).json({ error: String(e) });
    }
  }

  if (req.method === 'POST') {
    try {
      const buf = await genererPkpass(req.body);
      return res.status(200).json({ pkpass: buf.toString('base64') });
    } catch (e) {
      console.error('[wallet] POST error:', e);
      return res.status(500).json({ error: String(e) });
    }
  }

  return res.status(405).json({ error: 'Method not allowed' });
};
