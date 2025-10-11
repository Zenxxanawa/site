const express = require('express');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const app = express();

const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Database setup
const db = new sqlite3.Database(':memory:');

// Initialize database
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_value TEXT UNIQUE,
        hwid TEXT,
        user_id TEXT,
        generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME,
        is_used BOOLEAN DEFAULT 0
    )`);
    
    // Insert demo keys
    db.run(`INSERT OR IGNORE INTO keys (key_value, expires_at) VALUES 
        ('TEST1-2345-6789-ABCD', datetime('now', '+30 days')),
        ('DEMO-KEY-1234-5678', datetime('now', '+90 days'))
    `);
});

// Generate HWID
function generateHWID(clientInfo) {
    const data = `${clientInfo.userId}-${clientInfo.executor}-${clientInfo.placeId}`;
    return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
}

// API Routes
app.get('/', (req, res) => {
    res.json({ 
        message: 'Key System API - Running on Render',
        status: 'Online',
        version: '1.0.0'
    });
});

app.post('/api/validate', (req, res) => {
    const { key, userId, executor, placeId } = req.body;
    
    if (!key || !userId) {
        return res.json({ success: false, error: 'Missing key or userId' });
    }
    
    const hwid = generateHWID({ 
        userId, 
        executor: executor || 'unknown', 
        placeId: placeId || 'unknown' 
    });
    
    db.get(
        `SELECT * FROM keys WHERE key_value = ?`,
        [key.toUpperCase().trim()],
        (err, row) => {
            if (err || !row) {
                return res.json({ success: false, error: 'Invalid key' });
            }
            
            if (row.is_used && row.hwid !== hwid) {
                return res.json({ success: false, error: 'Key already used on different device' });
            }
            
            if (new Date(row.expires_at) < new Date()) {
                return res.json({ success: false, error: 'Key expired' });
            }
            
            // First time use
            if (!row.is_used) {
                db.run(
                    `UPDATE keys SET hwid = ?, is_used = 1, user_id = ? WHERE key_value = ?`,
                    [hwid, userId, key]
                );
            }
            
            res.json({
                success: true,
                message: 'Key valid',
                hwid: hwid,
                expires: row.expires_at
            });
        }
    );
});

app.listen(PORT, () => {
    console.log(`✅ Key system running on port ${PORT}`);
});
