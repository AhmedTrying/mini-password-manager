const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const { body, validationResult } = require('express-validator');
const { db, addUser, authenticateUser } = require('./database');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const app = express();
const port = 3000;

// Setup for HTTPS
const https = require('https');
const fs = require('fs');
const options = {
  key: fs.readFileSync('./key.pem'),
  cert: fs.readFileSync('./cert.pem')
};

app.use(express.static('public')); 
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(session({
    store: new SQLiteStore(),
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true, maxAge: 60000 }
}));

// Input validation and XSS protection using express-validator
app.post('/login', [
    body('username').trim().escape(),
    body('password').trim()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { username, password } = req.body;
    authenticateUser(username, password, (err, user) => {
        if (err) {
            console.error("Authentication error:", err.message);
            if (err.message === 'User not found' || err.message === 'Password is incorrect') {
                return res.status(401).send(err.message);
            }
            return res.status(500).send('Authentication failed');
        }
        req.session.regenerate((err) => {
            if (err) {
                console.error("Session regeneration error:", err);
                return res.status(500).send('Error regenerating session ID');
            }
            req.session.user = username;
            console.log("User authenticated and session set:", req.session.user);
            res.redirect('/menu');
        });
    });
});

// Endpoint to set up MFA for a user
app.post('/setup-mfa', (req, res) => {
    const secret = speakeasy.generateSecret({ length: 20 });
    qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
        if (err) {
            return res.status(500).send('Error generating QR code');
        }
        db.run('UPDATE users SET mfa_secret = ? WHERE username = ?', [secret.base32, req.session.user], (err) => {
            if (err) {
                return res.status(500).send('Error saving MFA secret');
            }
            res.json({ mfa_url: data_url });
        });
    });
});

// Endpoint to verify MFA token
app.post('/verify-mfa', [
    body('token').trim().escape()
], (req, res) => {
    const { token } = req.body;
    const sql = 'SELECT mfa_secret FROM users WHERE username = ?';
    db.get(sql, [req.session.user], (err, user) => {
        if (err) {
            return res.status(500).send('Error accessing the database');
        }
        if (!user) {
            return res.status(404).send('User not found');
        }
        const verified = speakeasy.totp.verify({
            secret: user.mfa_secret,
            encoding: 'base32',
            token: token
        });
        if (verified) {
            res.send('MFA verified successfully');
        } else {
            res.status(400).send('Invalid MFA token');
        }
    });
});

// Password recovery endpoint with validation
app.post('/recover', [
    body('email').isEmail().normalizeEmail()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { email } = req.body;
    const sql = `SELECT * FROM users WHERE email = ?`;
    db.get(sql, [email], (err, user) => {
        if (err) {
            return res.status(500).send('Error accessing the database');
        }
        if (!user) {
            return res.status(404).send('Email not found');
        } else {
            res.send('Password reset email sent (not actually implemented).');
        }
    });
});

// Root route
app.get('/', (req, res) => {
    res.sendFile('index.html', { root: __dirname + '/public' });
});

// Registration endpoint
app.post('/register', [
    body('username').trim().escape(),
    body('password').trim(),
    body('email').isEmail().normalizeEmail()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { username, password, email } = req.body;
    addUser(username, password, email, (err, userId) => {
        if (err) {
            return res.status(500).send('Error saving user to the database');
        }
        res.send('User registered successfully');
    });
});

// Serve menu page
app.get('/menu', (req, res) => {
    if (!req.session.user) {
        console.log("User not logged in, redirecting to login");
        return res.status(401).send('You must be logged in to view the menu');
    }
    console.log("User logged in, serving menu page:", req.session.user);
    res.sendFile('menu.html', { root: __dirname + '/public' });
});

// Serve order page
app.get('/order', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send('You must be logged in to place an order');
    }
    res.sendFile('order.html', { root: __dirname + '/public' });
});

// Handle order submission
app.post('/order', (req, res) => {
    const { pizza, address } = req.body;
    if (!req.session.user) {
        return res.status(401).send('You must be logged in to place an order');
    }
    const sql = 'INSERT INTO orders (username, pizza, address) VALUES (?, ?, ?)';
    db.run(sql, [req.session.user, pizza, address], function(err) {
        if (err) {
            return res.status(500).send('Error saving order to the database');
        }
        res.send('Order placed successfully');
    });
});

// Centralized error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

https.createServer(options, app).listen(443, () => {
    console.log('HTTPS Server running on port 443');
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
