import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import forge from 'https://esm.sh/node-forge@1.3.1';

// Le certificat APNs (Pass Type ID Certificate dédié aux notifications push,
// distinct du certificat de signature des .pkpass) est fourni en p12 base64.
function extractFromP12(p12b64: string, password: string) {
  const p12Der = atob(p12b64);
  const p12Asn1 = forge.asn1.fromDer(p12Der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password || '');

  const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });

  const keyBag = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0];
  const certBag = certBags[forge.pki.oids.certBag]?.[0];
  if (!keyBag || !certBag) throw new Error('p12 APNs : cert ou clé introuvable');

  return {
    certPem: forge.pki.certificateToPem(certBag.cert),
    keyPem: forge.pki.privateKeyToPem(keyBag.key),
  };
}

// Le client HTTP avec certificat client TLS est coûteux à construire (parsing p12) —
// on le met en cache au niveau du module pour les invocations suivantes (warm start).
let apnsClient: Deno.HttpClient | null = null;
function getApnsClient(): Deno.HttpClient {
  if (apnsClient) return apnsClient;

  const p12b64 = Deno.env.get('APPLE_PASS_APNS_CERTIFICATE');
  const password = Deno.env.get('APPLE_PASS_APNS_PASSWORD') ?? '';
  if (!p12b64) throw new Error('APPLE_PASS_APNS_CERTIFICATE manquant');

  const { certPem, keyPem } = extractFromP12(p12b64, password);
  apnsClient = Deno.createHttpClient({ cert: certPem, key: keyPem });
  return apnsClient;
}

Deno.serve(async (req) => {
  try {
    const { user_id, commercant_id } = await req.json();

    const admin = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    );

    const { data: registrations } = await admin
      .from('wallet_registrations')
      .select('push_token')
      .eq('user_id', user_id)
      .eq('commercant_id', commercant_id);

    if (!registrations?.length) {
      return new Response(JSON.stringify({ sent: 0 }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Met à jour updated_at pour que iOS sache que le pass a changé
    await admin
      .from('wallet_registrations')
      .update({ updated_at: new Date().toISOString() })
      .eq('user_id', user_id)
      .eq('commercant_id', commercant_id);

    const passTypeId = 'pass.com.lensk0.fidelityapp';
    const apnsUrl = 'https://api.push.apple.com/3/device/';
    const client = getApnsClient();

    let sent = 0;
    for (const reg of registrations) {
      try {
        const response = await fetch(`${apnsUrl}${reg.push_token}`, {
          method: 'POST',
          client,
          headers: {
            'apns-topic': passTypeId,
            'apns-push-type': 'background',
            'apns-priority': '10',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({}),
        });
        if (response.ok) sent++;
        else console.error('[APNs] error:', response.status, await response.text());
      } catch (e) {
        console.error('[APNs] send error:', e);
      }
    }

    return new Response(JSON.stringify({ sent }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (e) {
    console.error('[send-wallet-push] error:', e);
    return new Response(JSON.stringify({ error: String(e) }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});
