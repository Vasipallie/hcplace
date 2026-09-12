import express from 'express';
import { createClient } from '@supabase/supabase-js';
import path from 'path';
import { fileURLToPath } from 'url';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import fs from 'fs';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'views')));

const supabaseUrl = process.env.SUPALINK || '';
const supabaseAnonKey = process.env.SUPAKEY || '';
const supabaseServiceKey = process.env.SUPA_SERVICE_KEY || '';
const supabase = (supabaseUrl && supabaseServiceKey)
    ? createClient(supabaseUrl, supabaseServiceKey)
    : null;

const HCA_CID = process.env.HCA_CID;
const HCA_SID = process.env.HCA_SID;
const JWT_SECRET = process.env.JWT_SECRET;
const MODERATOR_SLACK_ID = process.env.MODERATOR_SLACK_ID || 'U08BK9UEC9Y';
const CONCURRENCY_CAP = parseInt(process.env.CONCURRENCY_CAP) || 100;
const RATE_LIMIT_MS = parseInt(process.env.RATE_LIMIT_MS) || 3000;
const HEARTBEAT_TIMEOUT_MS = parseInt(process.env.HEARTBEAT_TIMEOUT_MS) || 30000;

const sessionCookieName = 'hcplace_session';
const oauthStateCookieName = 'hcplace_oauth_state';
const isProduction = process.env.NODE_ENV === 'production';
const sessionCookieMaxAge = 1000 * 60 * 60 * 24 * 30;
const rateLimitMap = new Map();

const VALID_COLORS = [
    '#000000', '#ffffff', '#7f7f7f', '#c3c3c3',
    '#880015', '#ed1c24', '#ff7f27', '#fff200',
    '#22b14c', '#00a2e8', '#3f48cc', '#a349a4',
    '#ffaec9', '#b97a57', '#7092be', '#99d9ea'
];

function safeNextPath(next) {
    return typeof next === 'string' && next.startsWith('/') && !next.startsWith('//')
        ? next
        : '/place';
}

function getSession(req) {
    const token = req.cookies[sessionCookieName];
    if (!token || !JWT_SECRET) {
        return null;
    }
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch {
        return null;
    }
}

function setSessionCookie(res, session) {
    const token = jwt.sign(session, JWT_SECRET, { expiresIn: '30d' });
    res.cookie(sessionCookieName, token, {
        httpOnly: true,
        sameSite: 'lax',
        secure: isProduction,
        maxAge: sessionCookieMaxAge,
    });
}

function getRedirectUri(req) {
    const forwardedProtocol = req.headers['x-forwarded-proto'];
    const protocol = (forwardedProtocol || req.protocol).split(',')[0].trim();
    const configuredRedirectUri = process.env.HACKCLUB_AUTH_REDIRECT_URI;
    if (configuredRedirectUri) {
        return configuredRedirectUri.replace(/\/authenticate$/, '/auth');
    }
    return `${protocol}://${req.get('host')}/auth`;
}

function getUserName(session) {
    const identity = session?.identity?.identity || session?.identity || {};
    const firstName = identity.first_name || identity.given_name || '';
    const lastName = identity.last_name || identity.family_name || '';
    return identity.name || [firstName, lastName].filter(Boolean).join(' ') || 'there';
}

function getSlackId(session) {
    const identity = session?.identity?.identity || session?.identity || {};
    return identity.slack_id || null;
}

function getHeartbeatCutoff() {
    return new Date(Date.now() - HEARTBEAT_TIMEOUT_MS).toISOString();
}

async function getActiveCount() {
    if (!supabase) return 0;
    const { count } = await supabase
        .from('active_sessions')
        .select('*', { count: 'exact', head: true })
        .gte('last_heartbeat', getHeartbeatCutoff());
    return count || 0;
}

async function getGridConfig() {
    if (!supabase) return { width: 800, height: 480 };
    const { data } = await supabase
        .from('grid_config')
        .select('width, height')
        .eq('id', 1)
        .single();
    return data || { width: 800, height: 480 };
}

const memoryCells = new Map();

async function fetchAllCells() {
    let allCells = [];
    if (supabase) {
        let from = 0;
        const batchSize = 10000;
        while (true) {
            const { data } = await supabase
                .from('cells')
                .select('x, y, color, last_user_id')
                .range(from, from + batchSize - 1);
            if (!data || data.length === 0) break;
            allCells = allCells.concat(data);
            if (data.length < batchSize) break;
            from += batchSize;
        }
        allCells.forEach(c => {
            memoryCells.set(`${c.x},${c.y}`, { x: c.x, y: c.y, color: c.color, last_user_id: c.last_user_id });
        });
    }
    return Array.from(memoryCells.values());
}

async function cleanupAndPromote() {
    if (!supabase) return;
    await supabase
        .from('active_sessions')
        .delete()
        .lt('last_heartbeat', getHeartbeatCutoff());

    const activeCount = await getActiveCount();
    const slotsAvailable = CONCURRENCY_CAP - activeCount;

    if (slotsAvailable > 0) {
        const { data: waiters } = await supabase
            .from('queue')
            .select('user_id')
            .order('joined_at', { ascending: true })
            .limit(slotsAvailable);

        if (waiters && waiters.length > 0) {
            const now = new Date().toISOString();
            for (const w of waiters) {
                await supabase
                    .from('active_sessions')
                    .upsert({ user_id: w.user_id, last_heartbeat: now });
            }
            await supabase
                .from('queue')
                .delete()
                .in('user_id', waiters.map(w => w.user_id));
        }
    }
}

function authenty(req, res, next) {
    if (getSession(req)) {
        return next();
    }
    res.clearCookie(sessionCookieName);
    return res.redirect(`/login?next=${encodeURIComponent(req.originalUrl)}`);
}

function isModerator(req, res, next) {
    const session = getSession(req);
    const slackId = getSlackId(session);
    if (slackId !== MODERATOR_SLACK_ID) {
        return res.status(403).send('Access denied.');
    }
    next();
}

app.get('/', (req, res) => {
    res.render('index', { title: 'hc/place' });
});

app.get('/login', (req, res) => {
    if (getSession(req)) {
        return res.redirect('/place');
    }
    if (!HCA_CID || !HCA_SID || !JWT_SECRET) {
        return res.status(500).send('Authentication is not configured.');
    }

    const nextPath = safeNextPath(req.query.next);
    const state = randomUUID();
    res.cookie(oauthStateCookieName, JSON.stringify({ state, nextPath }), {
        httpOnly: true,
        sameSite: 'lax',
        secure: isProduction,
        maxAge: 10 * 60 * 1000,
    });

    const redirectUri = getRedirectUri(req);
    const authUrl = new URL('https://auth.hackclub.com/oauth/authorize');
    authUrl.searchParams.set('client_id', HCA_CID);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', 'email name profile slack_id');
    authUrl.searchParams.set('state', state);
    return res.redirect(authUrl.toString());
});

app.get('/auth', async (req, res) => {
    const storedState = req.cookies[oauthStateCookieName];
    res.clearCookie(oauthStateCookieName);
    if (req.query.error || typeof req.query.code !== 'string' || !storedState) {
        return res.redirect('/');
    }

    let stateData;
    try {
        stateData = JSON.parse(storedState);
    } catch {
        return res.redirect('/');
    }
    if (stateData.state !== req.query.state) {
        return res.status(400).send('Invalid authentication state.');
    }

    const redirectUri = getRedirectUri(req);
    try {
        const tokenResponse = await fetch('https://auth.hackclub.com/oauth/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                client_id: HCA_CID,
                client_secret: HCA_SID,
                redirect_uri: redirectUri,
                code: req.query.code,
                grant_type: 'authorization_code',
            }),
        });
        const token = await tokenResponse.json();
        if (!tokenResponse.ok || !token.access_token) {
            throw new Error('Hack Club token exchange failed.');
        }

        const identityResponse = await fetch('https://auth.hackclub.com/api/v1/me', {
            headers: { Authorization: `Bearer ${token.access_token}` },
        });
        const identity = await identityResponse.json();
        if (!identityResponse.ok) {
            throw new Error('Unable to fetch Hack Club identity.');
        }

        setSessionCookie(res, { identity, createdAt: Date.now() });
        return res.redirect(safeNextPath(stateData.nextPath));
    } catch (error) {
        console.error('Hack Club authentication failed:', error.message);
        return res.status(502).send('Hack Club authentication failed.');
    }
});

app.get('/logout', async (req, res) => {
    const session = getSession(req);
    if (session && supabase) {
        const slackId = getSlackId(session);
        if (slackId) {
            await supabase.from('active_sessions').delete().eq('user_id', slackId);
            await supabase.from('queue').delete().eq('user_id', slackId);
        }
    }
    res.clearCookie(sessionCookieName);
    return res.redirect('/');
});

app.get('/place', authenty, async (req, res) => {
    const session = getSession(req);
    const slackId = getSlackId(session);
    if (!slackId) return res.redirect('/login');

    if (supabase) {
        const { data: user } = await supabase
            .from('users')
            .select('is_banned')
            .eq('slack_id', slackId)
            .single();

        if (user?.is_banned) {
            return res.status(403).send('You have been banned from hc/place.');
        }

        await supabase.from('users').upsert({
            slack_id: slackId,
            name: getUserName(session),
        }, { onConflict: 'slack_id', ignoreDuplicates: true });

        const { data: existing } = await supabase
            .from('active_sessions')
            .select('user_id')
            .eq('user_id', slackId)
            .gte('last_heartbeat', getHeartbeatCutoff())
            .single();

        if (existing) {
            await supabase.from('active_sessions').upsert({
                user_id: slackId,
                last_heartbeat: new Date().toISOString()
            });
        } else {
            const activeCount = await getActiveCount();
            if (activeCount >= CONCURRENCY_CAP) {
                await supabase.from('queue').upsert({
                    user_id: slackId,
                    joined_at: new Date().toISOString()
                }, { onConflict: 'user_id', ignoreDuplicates: true });
                return res.redirect('/queue');
            }
            await supabase.from('active_sessions').upsert({
                user_id: slackId,
                last_heartbeat: new Date().toISOString()
            });
            await supabase.from('queue').delete().eq('user_id', slackId);
        }
    }

    const gridConfig = await getGridConfig();

    res.render('place', {
        title: 'hc/place',
        name: getUserName(session),
        supabaseUrl: supabaseUrl,
        supabaseKey: supabaseAnonKey,
        userId: slackId,
        gridWidth: gridConfig.width,
        gridHeight: gridConfig.height,
        isModerator: slackId === MODERATOR_SLACK_ID
    });
});

app.get('/queue', authenty, async (req, res) => {
    const session = getSession(req);
    const slackId = getSlackId(session);

    let position = 1;
    if (supabase) {
        const { data: active } = await supabase
            .from('active_sessions')
            .select('user_id')
            .eq('user_id', slackId)
            .gte('last_heartbeat', getHeartbeatCutoff())
            .single();

        if (active) return res.redirect('/place');

        const { data: queueEntry } = await supabase
            .from('queue')
            .select('joined_at')
            .eq('user_id', slackId)
            .single();

        if (queueEntry) {
            const { count } = await supabase
                .from('queue')
                .select('*', { count: 'exact', head: true })
                .lte('joined_at', queueEntry.joined_at);
            position = count || 1;
        } else {
            await supabase.from('queue').upsert({
                user_id: slackId,
                joined_at: new Date().toISOString()
            }, { onConflict: 'user_id', ignoreDuplicates: true });
            const { count } = await supabase
                .from('queue')
                .select('*', { count: 'exact', head: true });
            position = count || 1;
        }
    }

    res.render('queue', {
        title: 'hc/place',
        position: position,
        userId: slackId
    });
});

app.get('/kiosk', async (req, res) => {
    const gridConfig = await getGridConfig();
    res.render('kiosk', {
        title: 'hc/place',
        supabaseUrl: supabaseUrl,
        supabaseKey: supabaseAnonKey,
        gridWidth: gridConfig.width,
        gridHeight: gridConfig.height
    });
});

app.get('/admin', authenty, isModerator, async (req, res) => {
    let bannedUsers = [];
    let queueCount = 0;
    let activeCount = 0;

    if (supabase) {
        const { data } = await supabase
            .from('users')
            .select('slack_id, name')
            .eq('is_banned', true);
        bannedUsers = data || [];
        activeCount = await getActiveCount();
        const { count } = await supabase
            .from('queue')
            .select('*', { count: 'exact', head: true });
        queueCount = count || 0;
    }

    const gridConfig = await getGridConfig();

    res.render('admin', {
        title: 'hc/place admin',
        bannedUsers,
        activeCount,
        queueCount,
        gridWidth: gridConfig.width,
        gridHeight: gridConfig.height,
        supabaseUrl,
        supabaseKey: supabaseAnonKey
    });
});

app.get('/api/grid', async (req, res) => {
    const gridConfig = await getGridConfig();
    const cells = await fetchAllCells();

    res.json({
        width: gridConfig.width,
        height: gridConfig.height,
        cells: cells
    });
});

app.post('/api/click', authenty, async (req, res) => {
    const session = getSession(req);
    const slackId = getSlackId(session);
    if (!slackId) return res.status(401).json({ error: 'unauthorized' });

    if (supabase) {
        const { data: user } = await supabase
            .from('users')
            .select('is_banned')
            .eq('slack_id', slackId)
            .single();
        if (user?.is_banned) return res.status(403).json({ error: 'banned' });

        const { data: active } = await supabase
            .from('active_sessions')
            .select('user_id')
            .eq('user_id', slackId)
            .gte('last_heartbeat', getHeartbeatCutoff())
            .single();
        if (!active) return res.status(403).json({ error: 'not_admitted' });
    }

    const now = Date.now();
    const lastClick = rateLimitMap.get(slackId) || 0;
    if (slackId !== MODERATOR_SLACK_ID && now - lastClick < RATE_LIMIT_MS) {
        const remaining = RATE_LIMIT_MS - (now - lastClick);
        return res.status(429).json({ error: 'rate_limited', retryAfter: remaining });
    }

    const { x, y, color } = req.body;
    const gridConfig = await getGridConfig();

    if (typeof x !== 'number' || typeof y !== 'number' ||
        x < 0 || x >= gridConfig.width || y < 0 || y >= gridConfig.height) {
        return res.status(400).json({ error: 'invalid_coordinates' });
    }

    if (!VALID_COLORS.includes(color)) {
        return res.status(400).json({ error: 'invalid_color' });
    }

    rateLimitMap.set(slackId, now);
    memoryCells.set(`${x},${y}`, { x, y, color, last_user_id: slackId });

    if (supabase) {
        const { error: cellError } = await supabase
            .from('cells')
            .upsert({
                x, y, color,
                last_user_id: slackId,
                updated_at: new Date().toISOString()
            });

        if (cellError) return res.status(500).json({ error: 'db_error' });

        await supabase.from('clicks').insert({
            user_id: slackId, x, y, color
        });
    }

    res.json({ ok: true });
});

app.post('/api/heartbeat', authenty, async (req, res) => {
    const session = getSession(req);
    const slackId = getSlackId(session);
    if (!slackId) return res.status(401).json({ error: 'unauthorized' });

    if (supabase) {
        await supabase.from('active_sessions').upsert({
            user_id: slackId,
            last_heartbeat: new Date().toISOString()
        });
        cleanupAndPromote().catch(() => {});
    }

    res.json({ ok: true });
});

app.get('/api/queue/position', authenty, async (req, res) => {
    const session = getSession(req);
    const slackId = getSlackId(session);

    if (!supabase) return res.json({ position: 1, admitted: true });

    const { data: entry } = await supabase
        .from('queue')
        .select('joined_at')
        .eq('user_id', slackId)
        .single();

    if (!entry) return res.json({ position: 0, admitted: true });

    const { count } = await supabase
        .from('queue')
        .select('*', { count: 'exact', head: true })
        .lte('joined_at', entry.joined_at);

    res.json({ position: count || 1, admitted: false });
});

app.get('/api/queue/check', authenty, async (req, res) => {
    const session = getSession(req);
    const slackId = getSlackId(session);

    if (!supabase) return res.json({ admitted: true });

    const { data: active } = await supabase
        .from('active_sessions')
        .select('user_id')
        .eq('user_id', slackId)
        .gte('last_heartbeat', getHeartbeatCutoff())
        .single();

    if (active) return res.json({ admitted: true });

    const { data: inQueue } = await supabase
        .from('queue')
        .select('user_id')
        .eq('user_id', slackId)
        .single();

    if (!inQueue) {
        const activeCount = await getActiveCount();
        if (activeCount < CONCURRENCY_CAP) {
            await supabase.from('active_sessions').upsert({
                user_id: slackId,
                last_heartbeat: new Date().toISOString()
            });
            return res.json({ admitted: true });
        }
        await supabase.from('queue').upsert({
            user_id: slackId,
            joined_at: new Date().toISOString()
        }, { onConflict: 'user_id', ignoreDuplicates: true });
    }

    const { data: entry } = await supabase
        .from('queue')
        .select('joined_at')
        .eq('user_id', slackId)
        .single();

    let position = 1;
    if (entry) {
        const { count } = await supabase
            .from('queue')
            .select('*', { count: 'exact', head: true })
            .lte('joined_at', entry.joined_at);
        position = count || 1;
    }

    res.json({ admitted: false, position });
});

app.post('/api/admin/ban', authenty, isModerator, async (req, res) => {
    const { slackId } = req.body;
    if (!slackId) return res.status(400).json({ error: 'missing_slack_id' });

    if (supabase) {
        await supabase.from('users').upsert({
            slack_id: slackId,
            is_banned: true
        }, { onConflict: 'slack_id' });

        await supabase.from('active_sessions').delete().eq('user_id', slackId);
        await supabase.from('queue').delete().eq('user_id', slackId);
    }
    res.json({ ok: true });
});

app.post('/api/admin/unban', authenty, isModerator, async (req, res) => {
    const { slackId } = req.body;
    if (!slackId) return res.status(400).json({ error: 'missing_slack_id' });

    if (supabase) {
        await supabase.from('users').update({ is_banned: false }).eq('slack_id', slackId);
    }
    res.json({ ok: true });
});

app.post('/api/admin/reset-pixel', authenty, isModerator, async (req, res) => {
    const { x, y } = req.body;
    if (typeof x !== 'number' || typeof y !== 'number') {
        return res.status(400).json({ error: 'invalid_coordinates' });
    }

    if (supabase) {
        await supabase.from('cells').upsert({
            x, y, color: '#ffffff',
            last_user_id: 'admin',
            updated_at: new Date().toISOString()
        });
    }
    res.json({ ok: true });
});

app.post('/api/admin/resize', authenty, isModerator, async (req, res) => {
    const { width, height } = req.body;
    if (typeof width !== 'number' || typeof height !== 'number' || width < 1 || height < 1) {
        return res.status(400).json({ error: 'invalid_dimensions' });
    }

    if (supabase) {
        await supabase.from('grid_config').update({
            width, height,
            updated_at: new Date().toISOString()
        }).eq('id', 1);
    }
    res.json({ ok: true });
});

app.get('/:id', (req, res) => {
    res.render('404', { title: '404' });
});

setInterval(cleanupAndPromote, 15000);

app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});