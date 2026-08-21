// Admin-only "create login" for staff and resellers.
  //
  // Same security pattern as switch-account.js: the service role key (which
    // can create/modify any account) lives only in this server-side function,
  // read from a Vercel environment variable. It is never sent to, or
  // reachable from, the browser. This function re-checks role='admin'
  // straight from the database before doing anything, so it can't be
  // triggered by a modified client.
  //
  // The password the admin types is sent once, over HTTPS, straight to
  // Supabase's own account-creation endpoint — this function never stores it,
  // logs it, or writes it anywhere itself.

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
                res.status(403).json({ error: 'Only the admin account can create logins' });
                      return;
              }

              const body = req.body && typeof req.body === 'object' ? req.body : JSON.parse(req.body || '{}');
                const { email, password, role, resellerName, allowedTabs, displayName } = body;
                if (!email || !password) {
                  res.status(400).json({ error: 'Email and password are required' });
                        return;
                }
                if (password.length < 6) {
                  res.status(400).json({ error: 'Password must be at least 6 characters' });
                        return;
                }

                    const createRes = await fetch(SUPABASE_URL + '/auth/v1/admin/users', {
                          method: 'POST',
                    headers: { apikey: SERVICE_KEY, Authorization: 'Bearer ' + SERVICE_KEY, 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: email, password: password, email_confirm: true })
                    });
                const created = await createRes.json();
                if (!createRes.ok) {
                  res.status(400).json({ error: (created && created.msg) || (created && created.error_description) || 'Could not create the login \u2014 that email may already be in use' });
                        return;
                }

                    const profileBody = {
                        id: created.id,
                        display_name: displayName || resellerName || email,
                        role: role || 'reseller',
                        email: email
                };
                if (resellerName) profileBody.reseller_name = resellerName;
                if (allowedTabs) profileBody.allowed_tabs = allowedTabs;

                    const profCreateRes = await fetch(SUPABASE_URL + '/rest/v1/profiles', {
                          method: 'POST',
                    headers: { apikey: SERVICE_KEY, Authorization: 'Bearer ' + SERVICE_KEY, 'Content-Type': 'application/json', Prefer: 'return=representation' },
                    body: JSON.stringify(profileBody)
                    });
                if (!profCreateRes.ok) {
                  const errText = await profCreateRes.text();
                  res.status(500).json({ error: 'Login was created but the profile failed to save: ' + errText });
                        return;
                }

                res.status(200).json({ id: created.id, email: created.email });
                } catch (e) {
                  res.status(500).json({ error: (e && e.message) ? e.message : 'Unexpected server error' });
                }
              };
                
