import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

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

    let sent = 0;
    for (const reg of registrations) {
      try {
        const response = await fetch(`${apnsUrl}${reg.push_token}`, {
          method: 'POST',
          headers: {
            'apns-topic': passTypeId,
            'apns-push-type': 'background',
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
