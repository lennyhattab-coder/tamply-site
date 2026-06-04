const forge = require('node-forge');
const JSZip = require('jszip');
const crypto = require('crypto');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { user_id, commercant_id, nom_commerce,
            points, max, ligue, systeme,
            couleur_fond } = req.body;

    const p12b64 = process.env.APPLE_PASS_CERTIFICATE;
    const password = process.env.APPLE_PASS_CERTIFICATE_PASSWORD;

    if (!p12b64) {
      return res.status(500).json({ error: 'Certificat manquant' });
    }

    const label = systeme === 'points' ? 'points' : 'tampons';
    const restants = Math.max(0, (max || 10) - (points || 0));

    const passJson = {
      formatVersion: 1,
      passTypeIdentifier: 'pass.com.lensk0.fidelityapp',
      serialNumber: `${user_id}_${commercant_id}`,
      teamIdentifier: 'PSU4H69TXL',
      organizationName: 'Tamply',
      description: `Carte ${nom_commerce} — Tamply`,
      logoText: 'Tamply',
      foregroundColor: 'rgb(238, 238, 248)',
      backgroundColor: couleur_fond || 'rgb(79, 70, 229)',
      labelColor: 'rgb(200, 200, 220)',
      storeCard: {
        primaryFields: [{
          key: 'progression',
          label: label.charAt(0).toUpperCase() + label.slice(1),
          value: `${points || 0} / ${max || 10}`
        }],
        secondaryFields: [
          { key: 'commerce', label: 'Commerce', value: nom_commerce },
          { key: 'ligue', label: 'Ligue', value: ligue || 'Bronze' }
        ],
        auxiliaryFields: [{
          key: 'prochaine',
          label: 'Prochaine récompense',
          value: restants === 0 ? 'Disponible !' : `Plus que ${restants} ${label}`
        }],
        backFields: [{
          key: 'info',
          label: 'À propos',
          value: 'Scannez votre QR code pour gagner des tampons'
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

    const passJsonStr = JSON.stringify(passJson, null, 2);

    const iconB64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVQI12NgAAIABQAABjkB6QAAAAAASUVORK5CYII=';
    const iconBytes = Buffer.from(iconB64, 'base64');

    const manifest = {
      'pass.json': crypto.createHash('sha1').update(passJsonStr).digest('hex'),
      'icon.png': crypto.createHash('sha1').update(iconBytes).digest('hex')
    };
    const manifestStr = JSON.stringify(manifest);

    // Signature PKCS7 avec node-forge (Node.js natif — pas de problème Deno)
    const p12Der = Buffer.from(p12b64, 'base64').toString('binary');
    const p12Asn1 = forge.asn1.fromDer(p12Der);
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password);

    const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
    const keyBag = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag][0];

    const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
    const certs = certBags[forge.pki.oids.certBag].map(b => b.cert);

    const p7 = forge.pkcs7.createSignedData();
    p7.content = forge.util.createBuffer(manifestStr, 'utf8');
    certs.forEach(cert => p7.addCertificate(cert));
    p7.addSigner({
      key: keyBag.key,
      certificate: certs[0],
      digestAlgorithm: forge.pki.oids.sha1,
      authenticatedAttributes: [
        { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
        { type: forge.pki.oids.messageDigest },
        { type: forge.pki.oids.signingTime, value: new Date() }
      ]
    });
    p7.sign();

    const sigDer = forge.asn1.toDer(p7.toAsn1()).getBytes();
    const sigBuffer = Buffer.from(sigDer, 'binary');

    const zip = new JSZip();
    zip.file('pass.json', passJsonStr);
    zip.file('manifest.json', manifestStr);
    zip.file('signature', sigBuffer);
    zip.file('icon.png', iconBytes);

    const zipBuffer = await zip.generateAsync({ type: 'nodebuffer', compression: 'STORE' });

    return res.status(200).json({ pkpass: zipBuffer.toString('base64') });

  } catch (e) {
    console.error('Wallet error:', e);
    return res.status(500).json({ error: String(e) });
  }
};
