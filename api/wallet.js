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

    console.log('Cert présent:', !!p12b64, 'longueur:', p12b64?.length ?? 0);
    console.log('Password configuré:', !!password);

    if (!p12b64) {
      return res.status(500).json({ error: 'Certificat manquant' });
    }

    const label = systeme === 'points' ? 'points' : 'tampons';
    const ptsCourants = points || 0;
    const ptsTotaux = max || 10;
    const restants = Math.max(0, ptsTotaux - ptsCourants);

    // Représentation visuelle des tampons
    const tamponsFilled = '●'.repeat(Math.min(ptsCourants, ptsTotaux));
    const tamponsEmpty = '○'.repeat(restants);
    const tamponsVisuel = tamponsFilled + tamponsEmpty;

    const passJson = {
      formatVersion: 1,
      passTypeIdentifier: 'pass.com.lensk0.fidelityapp',
      serialNumber: `${user_id}_${commercant_id}`,
      teamIdentifier: 'PSU4H69TXL',
      organizationName: 'Tamply',
      description: `Carte ${nom_commerce} — Tamply`,
      logoText: nom_commerce || 'Tamply',
      foregroundColor: 'rgb(238, 238, 248)',
      backgroundColor: couleur_fond || 'rgb(79, 70, 229)',
      labelColor: 'rgb(200, 200, 220)',
      storeCard: {
        primaryFields: [{
          key: 'tampons',
          label: 'Progression',
          value: tamponsVisuel,
        }],
        secondaryFields: [
          { key: 'commerce', label: 'Commerce', value: nom_commerce || '' },
          { key: 'points', label: `${ptsCourants}/${ptsTotaux}`, value: ligue || 'Bronze' },
        ],
        auxiliaryFields: [{
          key: 'prochaine',
          label: restants === 0
            ? 'Récompense disponible !'
            : `Plus que ${restants} tampon${restants > 1 ? 's' : ''}`,
          value: '',
        }],
        backFields: [
          {
            key: 'qr_info',
            label: 'Votre QR Code',
            value: `tamply://wallet/${user_id}/${commercant_id}`,
          },
          {
            key: 'info',
            label: 'Comment ça marche',
            value: 'Présentez ce QR code en caisse pour gagner des tampons de fidélité.',
          },
        ],
      },
      barcode: {
        message: `tamply://wallet/${user_id}/${commercant_id}`,
        format: 'PKBarcodeFormatQR',
        messageEncoding: 'iso-8859-1',
        altText: `${nom_commerce || 'Tamply'} — QR Code fidélité`,
      },
      barcodes: [{
        message: `tamply://wallet/${user_id}/${commercant_id}`,
        format: 'PKBarcodeFormatQR',
        messageEncoding: 'iso-8859-1',
        altText: `${nom_commerce || 'Tamply'} — QR Code fidélité`,
      }],
    };

    const passJsonStr = JSON.stringify(passJson, null, 2);

    const iconB64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVQI12NgAAIABQAABjkB6QAAAAAASUVORK5CYII=';
    const iconBytes = Buffer.from(iconB64, 'base64');

    const manifest = {
      'pass.json': crypto.createHash('sha1').update(passJsonStr).digest('hex'),
      'icon.png': crypto.createHash('sha1').update(iconBytes).digest('hex'),
    };
    const manifestStr = JSON.stringify(manifest);

    // Signature PKCS7 avec node-forge
    const p12Der = Buffer.from(p12b64, 'base64').toString('binary');
    const p12Asn1 = forge.asn1.fromDer(p12Der);
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password);

    const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
    const keyBag = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag][0];

    const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
    const certs = certBags[forge.pki.oids.certBag].map(b => b.cert);

    // Télécharger le certificat WWDR Apple pour la chaîne complète
    let wwdrCert = null;
    try {
      const wwdrResp = await fetch('https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer');
      if (wwdrResp.ok) {
        const wwdrDer = Buffer.from(await wwdrResp.arrayBuffer());
        const wwdrBin = wwdrDer.toString('binary');
        wwdrCert = forge.pki.certificateFromAsn1(forge.asn1.fromDer(wwdrBin));
        console.log('WWDR chargé:', wwdrCert.subject.getField('CN')?.value);
      } else {
        console.warn('WWDR inaccessible, status:', wwdrResp.status);
      }
    } catch (e) {
      console.warn('WWDR fetch échoué:', String(e));
    }

    const p7 = forge.pkcs7.createSignedData();
    p7.content = forge.util.createBuffer(manifestStr, 'utf8');
    certs.forEach(cert => p7.addCertificate(cert));
    if (wwdrCert) p7.addCertificate(wwdrCert);
    p7.addSigner({
      key: keyBag.key,
      certificate: certs[0],
      digestAlgorithm: forge.pki.oids.sha1,
      authenticatedAttributes: [
        { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
        { type: forge.pki.oids.messageDigest },
        { type: forge.pki.oids.signingTime, value: new Date() },
      ],
    });
    p7.sign();

    const sigDer = forge.asn1.toDer(p7.toAsn1()).getBytes();
    const sigBuffer = Buffer.from(sigDer, 'binary');

    console.log('Signature size:', sigBuffer.length, 'bytes');

    const zip = new JSZip();
    zip.file('pass.json', passJsonStr);
    zip.file('manifest.json', manifestStr);
    zip.file('signature', sigBuffer);
    zip.file('icon.png', iconBytes);

    const zipBuffer = await zip.generateAsync({ type: 'nodebuffer', compression: 'STORE' });

    console.log('pkpass size:', zipBuffer.length, 'bytes');

    return res.status(200).json({ pkpass: zipBuffer.toString('base64') });

  } catch (e) {
    console.error('Wallet error:', e);
    return res.status(500).json({ error: String(e) });
  }
};
