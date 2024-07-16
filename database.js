const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

// Connect to the database
let db = new sqlite3.Database('./passwordManager.db', (err) => {
    if (err) {
        console.error(err.message);
    } else {
        console.log('Connected to the passwordManager database.');
        initializeDatabase();
    }
});

// Function to initialize the database and create tables
function initializeDatabase() {
    // Create users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        email TEXT,
        mfa_secret TEXT
    )`, (err) => {
        if (err) {
            console.error(err.message);
        } else {
            console.log('Users table created or already exists.');
        }
    });

    // Create orders table
    db.run(`CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        pizza TEXT,
        address TEXT,
        FOREIGN KEY(username) REFERENCES users(username)
    )`, (err) => {
        if (err) {
            console.error(err.message);
        } else {
            console.log('Orders table created or already exists.');
        }
    });
}

// Function to add a new user with hashed password
function addUser(username, password, email, callback) {
    const saltRounds = 10;
    bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) {
            return callback(err);
        }
        const sql = 'INSERT INTO users (username, password, email) VALUES (?, ?, ?)';
        db.run(sql, [username, hash, email], function(err) {
            if (err) {
                return callback(err);
            }
            callback(null, this.lastID);
        });
    });
}

// Function to authenticate a user
function authenticateUser(username, password, callback) {
    const sql = 'SELECT * FROM users WHERE username = ?';
    db.get(sql, [username], (err, user) => {
        if (err) {
            return callback(err);
        }
        if (!user) {
            return callback(new Error('User not found'));
        }
        bcrypt.compare(password, user.password, (err, result) => {
            if (err) {
                return callback(err);
            }
            if (result) {
                callback(null, user);
            } else {
                callback(new Error('Password is incorrect'));
            }
        });
    });
}

module.exports = { db, addUser, authenticateUser };
