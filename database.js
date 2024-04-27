const sqlite3 = require('sqlite3').verbose();

// Connect to the database
let db = new sqlite3.Database('./passwordManager.db', (err) => {
    if (err) {
        console.error(err.message);
    }
    console.log('Connected to the passwordManager database.');
});

// Create users table
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    email TEXT
)`, (err) => {
    if (err) {
        return console.error(err.message);
    }
    console.log('Users table created or already exists.');
});

module.exports = db;
