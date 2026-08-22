// Admin-only "set password" for an existing account (staff or reseller).
//
// Same security pattern as switch-account.js and create-account.js: the
// service role key lives only here, read from a Vercel environment
// variable, and this function re-checks role='admin' straight from the
// database before doing anything — it can't be triggered by a modified
// client, and it never sends a reset-link email. The admin sets the
// password directly, once, and can then share it however they choose.

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

      const callerRes = await fetch(SUPABASE_URL + '/auth/v1/user', {
              headers: { apikey: SUPABASE_ANON_KEY, Authorization: 'Bearer ' + callerToken }
      });
          if (!callerRes.ok) {
                  res.status(401).json({ error: 'Your session isn\u2019t valid \u2014 please sign in again' });
                  return;
          }
          const caller = await callerRes.json();

      const profRes = await fetch(
              SUPABASE_URL + '/rest/v1/profiles?id=eq.' + encodeURIComponent(caller.id) + '&select=role',
        { headers: { apikey: SERVICE_KEY, Authorization: 'Bearer ' + SERVICE_KEY } }
            );
          const profRows = await profRes.json();
          if (!profRes.ok || !Array.isArray(profRows) || !profRows.length || profRows[0].role !== 'admin') {
                  res.status(403).json({ error: 'Only the admin account can change other accounts\u2019 passwords' });
                  return;
          }

      const body = req.body && typeof req.body === 'object' ? req.body : JSON.parse(req.body || '{}');
          const { targetUserId, newPassword } = body;
          if (!targetUserId || !newPassword) {
                  res.status(400).json({ error: 'targetUserId and newPassword are required' });
                  return;
          }
          if (newPassword.length < 6) {
                  res.status(400).json({ error: 'Password must be at least 6 characters' });
                  return;
          }

      const updateRes = await fetch(SUPABASE_URL + '/auth/v1/admin/users/' + encodeURIComponent(targetUserId), {
              method: 'PUT',
              headers: { apikey: SERVICE_KEY, Authorization: 'Bearer ' + SERVICE_KEY, 'Content-Type': 'application/json' },
              body: JSON.stringify({ password: newPassword })
      });
          const updated = await updateRes.json();
          if (!updateRes.ok) {
                  res.status(400).json({ error: (updated && updated.msg) || (updated && updated.error_description) || 'Could not update the password' });
                  return;
          }

      res.status(200).json({ id: updated.id, email: updated.email });
    } catch (e) {
          res.status(500).json({ error: (e && e.message) ? e.message : 'Unexpected server error' });
    }
};
