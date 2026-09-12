//inits
import express from 'express';
import { createClient } from '@supabase/supabase-js';
import bodyParser from 'body-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import multer from 'multer';
import jwt from 'jsonwebtoken';
import { dirname } from 'path';
import { randomUUID } from 'crypto';
dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cookieParser());
const supalink = process.env.SUPALINK ;
const supakey = process.env.SUPAKEY ;
/* 
const supabase = createClient(supalink, supakey);  */

const HCA_CID = process.env.HCA_CID;
const HCA_SID = process.env.HCA_SID;
const JWT_SECRET = process.env.JWT_SECRET;
const sessionCookieName = 'hcplace_session';
const oauthStateCookieName = 'hcplace_oauth_state';
const isProduction = process.env.NODE_ENV === 'production';
const sessionCookieMaxAge = 1000 * 60 * 60 * 24 * 30;

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

// Middleware data stuff, important for app to run
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'views')));
app.use(bodyParser.urlencoded({ extended: true }));

function authenty(req, res, next) {
    if (getSession(req)) {
        return next();
    }
    res.clearCookie(sessionCookieName);
    return res.redirect(`/login?next=${encodeURIComponent(req.originalUrl)}`);
}

app.get('/', (req, res) => {
    if (getSession(req)) {
        return res.redirect('/place');
    }
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

app.get('/logout', (req, res) => {
    res.clearCookie(sessionCookieName);
    return res.redirect('/');
});

app.get('/place', authenty, (req, res) => {
    res.render('place', {
        title: 'hc/place',
        name: getUserName(getSession(req)),
    });
});
app.get('/kiosk', (req, res) => {
    res.render('kiosk', { title: 'hc/place' });
});
app.get('/queue', (req,res)=>{
    res.render('queue', { title: 'hc/place' });
});

app.get('/:id', (req, res) => {
    res.render('404', { title: '404' });
});

//Server start 
app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});