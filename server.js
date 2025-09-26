const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));

// === Database setup ===
const db = new sqlite3.Database('handover.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    name TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    name TEXT NOT NULL,
    login_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users (username)
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS handovers (
    id TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  const adminHash = bcrypt.hashSync('admin123', 10);
  const maintenanceHash = bcrypt.hashSync('shift2025', 10);
  
  db.run(`INSERT OR IGNORE INTO users (username, password_hash, role, name) 
          VALUES (?, ?, 'admin', 'System Administrator')`, ['admin', adminHash]);
  
  db.run(`INSERT OR IGNORE INTO users (username, password_hash, role, name) 
          VALUES (?, ?, 'user', 'Maintenance Team')`, ['maintenance', maintenanceHash]);
});

// === API routes ===

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err || !user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    
    if (bcrypt.compareSync(password, user.password_hash)) {
      const sessionId = 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
      
      db.run('INSERT INTO sessions (session_id, username, role, name) VALUES (?, ?, ?, ?)',
        [sessionId, user.username, user.role, user.name], (err) => {
          if (err) {
            return res.status(500).json({ error: 'Session creation failed' });
          }
          
          res.json({
            sessionId,
            user: {
              username: user.username,
              role: user.role,
              name: user.name
            }
          });
        });
    } else {
      res.status(401).json({ error: 'Invalid username or password' });
    }
  });
});

app.post('/api/auth/logout', (req, res) => {
  const { sessionId } = req.body;
  
  db.run('DELETE FROM sessions WHERE session_id = ?', [sessionId], (err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.json({ success: true });
  });
});

app.post('/api/auth/validate', (req, res) => {
  const { sessionId } = req.body;
  
  db.get('SELECT * FROM sessions WHERE session_id = ?', [sessionId], (err, session) => {
    if (err || !session) {
      return res.status(401).json({ error: 'Invalid session' });
    }
    
    res.json({
      username: session.username,
      role: session.role,
      name: session.name,
      loginTime: session.login_time
    });
  });
});

function authenticate(req, res, next) {
  const sessionId = req.headers['x-session-id'] || req.body.sessionId;
  
  if (!sessionId) {
    return res.status(401).json({ error: 'No session provided' });
  }
  
  db.get('SELECT * FROM sessions WHERE session_id = ?', [sessionId], (err, session) => {
    if (err || !session) {
      return res.status(401).json({ error: 'Invalid session' });
    }
    
    req.user = {
      username: session.username,
      role: session.role,
      name: session.name
    };
    next();
  });
}

function authenticateAdmin(req, res, next) {
  authenticate(req, res, () => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    next();
  });
}

app.get('/api/users', authenticateAdmin, (req, res) => {
  db.all('SELECT username, role, name, created_at FROM users', (err, users) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch users' });
    }
    res.json(users);
  });
});

app.post('/api/users', authenticateAdmin, (req, res) => {
  const { username, password, name, role } = req.body;
  
  if (!username || !password || !name) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  const passwordHash = bcrypt.hashSync(password, 10);
  
  db.run('INSERT INTO users (username, password_hash, role, name) VALUES (?, ?, ?, ?)',
    [username, passwordHash, role || 'user', name], function(err) {
      if (err) {
        if (err.code === 'SQLITE_CONSTRAINT') {
          return res.status(409).json({ error: 'Username already exists' });
        }
        return res.status(500).json({ error: 'User creation failed' });
      }
      res.json({ success: true });
    });
});

app.delete('/api/users/:username', authenticateAdmin, (req, res) => {
  const { username } = req.params;
  
  if (username === 'admin') {
    return res.status(403).json({ error: 'Cannot delete admin user' });
  }
  
  db.run('DELETE FROM users WHERE username = ?', [username], function(err) {
    if (err) {
      return res.status(500).json({ error: 'User deletion failed' });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    db.run('DELETE FROM sessions WHERE username = ?', [username]);
    res.json({ success: true });
  });
});

app.get('/api/handover/:id', authenticate, (req, res) => {
  const { id } = req.params;
  
  db.get('SELECT * FROM handovers WHERE id = ?', [id], (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch handover' });
    }
    
    if (!row) {
      return res.status(404).json({ error: 'Handover not found' });
    }
    
    res.json(JSON.parse(row.data));
  });
});

app.post('/api/handover/:id', authenticate, (req, res) => {
  const { id } = req.params;
  const data = req.body;
  
  const dataString = JSON.stringify(data);
  
  db.run('INSERT OR REPLACE INTO handovers (id, data, last_updated) VALUES (?, ?, CURRENT_TIMESTAMP)',
    [id, dataString], (err) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to save handover' });
      }
      res.json({ success: true });
    });
});

app.get('/api/handovers', authenticate, (req, res) => {
  db.all('SELECT id, last_updated FROM handovers ORDER BY last_updated DESC', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch handovers' });
    }
    
    res.json(rows);
  });
});

// === Serve static files AFTER API routes ===
app.use(express.static('public'));

// Fallback: serve index.html for frontend routes (optional)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Optional: Handle SIGINT gracefully
process.on('SIGINT', () => {
  console.log('\nShutting down server...');
  db.close((err) => {
    if (err) {
      console.error(err.message);
    }
    console.log('Database connection closed.');
    process.exit(0);
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
