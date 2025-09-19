const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const db = require('./db');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
  secret: 'secret-key', // change in production
  resave: false,
  saveUninitialized: false
}));

// check if logged in
function checkAuth(req, res, next) {
  if (req.session.userId) {
    next();
  } else {
    res.redirect('/login.html');
  }
}

// Register route
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hash = await bcrypt.hash(password, 10);

  db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hash], function(err) {
    if (err) {
      return res.send('Username already taken.');
    }
    db.run(`INSERT INTO notes (user_id, content) VALUES (?, ?)`, [this.lastID, ""]);
    res.redirect('/login.html');
  });
});

// Login route
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (!user) {
      return res.redirect('/login.html?error=1');
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.redirect('/login.html?error=1');
    }

    req.session.userId = user.id;
    res.redirect('/notepad.html');
  });
});

// Save note
app.post('/save', checkAuth, (req, res) => {
  db.run(`UPDATE notes SET content = ? WHERE user_id = ?`, [req.body.content, req.session.userId]);
  res.send('Saved!');
});

// Load note
app.get('/note', checkAuth, (req, res) => {
  db.get(`SELECT content FROM notes WHERE user_id = ?`, [req.session.userId], (err, row) => {
    res.json(row);
  });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));