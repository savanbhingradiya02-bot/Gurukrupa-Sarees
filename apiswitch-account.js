// Real database-level "switch account" for the admin.
//
// This is a server-side function on purpose. The service role key that can
// impersonate any user must NEVER be shipped inside the public HTML file —
// anyone could open dev tools, copy it out, and take over every account,
// including Soham's. Keeping it here, as a Vercel environment variable that
// only this function reads, is what makes this safe.
//
// Flow:
//  1. The browser sends its own current access token + the id of the
//     account to switch into.
//  2. This function asks Supabase whose token that really is (can't be
//     spoofed by editing the browser).
//  3. It looks up that caller's role directly in the database (service
//     role — bypasses the browser entirely, so a modified client can't lie
//     about being an admin).
//  4. Only if that caller is truly role='admin' does it generate a one-time
//     login token for the target account and hand it back. The browser
//     then exchanges that token for a real session via supabase-js.
//
// No password is ever seen, sent, or stored anywhere in this flow.

const SUPABASE_URL = 'https://zgjoonxhxvxgdbrbhmht.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inpnam9vbnhoeHZ4Z2RicmJobWh0Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODcxNjg1OTgsImV4cCI6MjEwMjc0NDU5OH0.79ZPTZ6osv_El8LgdzyHBHl_fkjB59auFN3qGiQzfXM';

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  try {
    const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!SERVICE_KEY) {
      res.status(500).json({ error: 'Server not configured: SUPABASE_SERVICE_ROLE_KEY is missing' });
      return;
    }

    const authHeader = req.headers.authorization || '';
    const callerToken = authHeader.replace(/^Bearer\s+/i, '');
    if (!callerToken) {
      res.status(401).json({ error: 'Missing Authorization header' });
      return;
    }

    // Step 1 — who is actually calling, according to Supabase (not the client's say-so).
    const callerRes = await fetch(SUPABASE_URL + '/auth/v1/user', {
      headers: { apikey: SUPABASE_ANON_KEY, Authorization: 'Bearer ' + callerToken }
    });
    if (!callerRes.ok) {
      res.status(401).json({ error: 'Your session isn\u2019t valid — please sign in again' });
      return;
    }
    const caller = await callerRes.json();

    // Step 2 — is that caller really an admin, checked straight in the database.
    const profRes = await fetch(
      SUPABASE_URL + '/rest/v1/profiles?id=eq.' + encodeURIComponent(caller.id) + '&select=role',
      { headers: { apikey: SERVICE_KEY, Authorization: 'Bearer ' + SERVICE_KEY } }
    );
    const profRows = await profRes.json();
    if (!profRes.ok || !Array.isArray(profRows) || !profRows.length || profRows[0].role !== 'admin') {
      res.status(403).json({ error: 'Only the admin account can switch accounts' });
      return;
    }

    const body = req.body && typeof req.body === 'object' ? req.body : JSON.parse(req.body || '{}');
    const targetUserId = body.targetUserId;
    if (!targetUserId) {
      res.status(400).json({ error: 'targetUserId is required' });
      return;
    }

    // Step 3 — look up the target account's email (needed to mint their login token).
    const targetRes = await fetch(SUPABASE_URL + '/auth/v1/admin/users/' + encodeURIComponent(targetUserId), {
      headers: { apikey: SERVICE_KEY, Authorization: 'Bearer ' + SERVICE_KEY }
    });
    if (!targetRes.ok) {
      res.status(404).json({ error: 'That account could not be found' });
      return;
    }
    const targetUser = await targetRes.json();

    // Step 4 — mint a one-time login token for them. This never sends an
    // email; we hand the token straight back over this same HTTPS response,
    // and the browser exchanges it immediately for a real session.
    const linkRes = await fetch(SUPABASE_URL + '/auth/v1/admin/generate_link', {
      method: 'POST',
      headers: { apikey: SERVICE_KEY, Authorization: 'Bearer ' + SERVICE_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'magiclink', email: targetUser.email })
    });
    if (!linkRes.ok) {
      const errText = await linkRes.text();
      res.status(500).json({ error: 'Could not create login token: ' + errText });
      return;
    }
    const linkData = await linkRes.json();
    const hashedToken = linkData.hashed_token || (linkData.properties && linkData.properties.hashed_token);
    if (!hashedToken) {
      res.status(500).json({ error: 'Login token was not returned' });
      return;
    }

    res.status(200).json({ email: targetUser.email, hashed_token: hashedToken });
  } catch (e) {
    res.status(500).json({ error: (e && e.message) ? e.message : 'Unexpected server error' });
  }
};
