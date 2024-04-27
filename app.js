const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const db = require('./database');
const app = express();
const port = 3000;

app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Enhanced login endpoint with validation
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
                res.send('Login successful');
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

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});

// Root route
app.get('/', (req, res) => {
    res.send('Welcome to the Mini-Password Manager! Navigate to /login.html to login, or /register.html to register.');
});
