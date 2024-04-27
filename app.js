const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const db = require('./database');
const app = express();
const port = 3000;

app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Registration endpoint with input validation and error handling
app.post('/register', (req, res) => {
    const { username, password, email } = req.body;
    if (!username || username.length < 5 || username.length > 12) {
        return res.status(400).send('Username must be between 5 and 12 characters long.');
    }
    if (!password || password.length < 6) {
        return res.status(400).send('Password must be at least 6 characters long.');
    }
    if (!email) {
        return res.status(400).send('Email is required.');
    }

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            return res.status(500).send('Error hashing password');
        }
        const sql = `INSERT INTO users (username, password, email) VALUES (?, ?, ?)`;
        db.run(sql, [username, hash, email], (err) => {
            if (err) {
                return res.status(400).send('Could not save user. The username may already be taken.');
            }
            res.send('User registered successfully');
        });
    });
});

// Login endpoint
app.post('/login', (req, res) => {
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

// Password recovery endpoint (simplified for demonstration)
app.post('/recover', (req, res) => {
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
