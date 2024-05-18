const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const { body, validationResult } = require('express-validator');
const db = require('./database');
const app = express();
const port = 3000;

app.use(express.static('public')); 
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(session({
    store: new SQLiteStore(),
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, httpOnly: true, maxAge: 60000 } 
}));


app.post('/login', [
    body('username').trim().escape(),
    body('password').trim()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { username, password } = req.body;
    const sql = `SELECT * FROM users WHERE username = ?`;
    db.get(sql, [username], (err, user) => {
        if (err) {
            return res.status(500).send('Error accessing the database');
        }
        if (!user) {
            return res.status(404).send('User not found');
        }
        bcrypt.compare(password, user.password, (err, result) => {
            if (err) {
                return res.status(500).send('Authentication failed');
            }
            if (result) {
                req.session.regenerate((err) => {
                    if (err) {
                        return res.status(500).send('Error regenerating session ID');
                    }
                    req.session.user = username;
                    res.redirect('/menu');
                });
            } else {
                res.send('Password is incorrect');
            }
        });
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
    const saltRounds = 10;

    bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) {
            return res.status(500).send('Error hashing password');
        }
        const sql = 'INSERT INTO users (username, password, email) VALUES (?, ?, ?)';
        db.run(sql, [username, hash, email], function(err) {
            if (err) {
                return res.status(500).send('Error saving user to the database');
            }
            res.send('User registered successfully');
        });
    });
});

// Serve menu page
app.get('/menu', (req, res) => {
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

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});

req.session.regenerate((err) => {
    if (err) {
        return res.status(500).send('Error regenerating session ID');
    }
    req.session.user = username;
    res.redirect('/menu');
});

app.use(session({
    store: new SQLiteStore(),
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, httpOnly: true, maxAge: 60000 }
}));

