const express = require('express');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const path = require('path');
const app = express();

const PORT = process.env.PORT || 3000;


app.use(cors());
app.use(express.json());


const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});
app.use(limiter);


const db = new sqlite3.Database(':memory:'); // Use memory for demo (change to file for production)

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_value TEXT UNIQUE,
        hwid TEXT,
        user_id TEXT,
        generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        activated_at DATETIME,
        expires_at DATETIME,
        is_used BOOLEAN DEFAULT 0,
        is_banned BOOLEAN DEFAULT 0,
        key_type TEXT DEFAULT 'STANDARD',
        uses INTEGER DEFAULT 0,
        max_uses INTEGER DEFAULT 1
    )`);
    
    db.run(`INSERT OR IGNORE INTO keys (key_value, key_type, expires_at, max_uses) VALUES 
        ('TEST1-2345-6789-ABCD', 'STANDARD', datetime('now', '+30 days'), 5),
        ('DEMO-KEY-1234-5678', 'PREMIUM', datetime('now', '+90 days'), 1)
    `);
});


function generateHWID(clientInfo) {
    const data = `${clientInfo.userId}-${clientInfo.executor}-${clientInfo.placeId}`;
    return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
}


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
    
    const hwid = generateHWID({ userId, executor: executor || 'unknown', placeId: placeId || 'unknown' });
    
    db.get(
        `SELECT * FROM keys WHERE key_value = ? AND is_banned = 0`,
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
            
            if (row.uses >= row.max_uses) {
                return res.json({ success: false, error: 'Key usage limit reached' });
            }
            
            db.run(`UPDATE keys SET uses = uses + 1 WHERE key_value = ?`, [key]);
            
            res.json({
                success: true,
                message: 'Key valid',
                key_type: row.key_type,
                expires: row.expires_at,
                uses: row.uses + 1,
                max_uses: row.max_uses
            });
        }
    );
});

app.post('/api/activate', (req, res) => {
    const { key, userId, executor, placeId } = req.body;
    
    const hwid = generateHWID({ userId, executor: executor || 'unknown', placeId: placeId || 'unknown' });
    
    db.get(
        `SELECT * FROM keys WHERE key_value = ? AND is_banned = 0`,
        [key.toUpperCase().trim()],
        (err, row) => {
            if (err || !row) {
                return res.json({ success: false, error: 'Invalid key' });
            }
            
            if (row.is_used && row.hwid !== hwid) {
                return res.json({ success: false, error: 'Key already activated on different device' });
            }
            
            if (!row.is_used) {
                db.run(
                    `UPDATE keys SET hwid = ?, is_used = 1, activated_at = CURRENT_TIMESTAMP, user_id = ? WHERE key_value = ?`,
                    [hwid, userId, key]
                );
            }
            
            res.json({
                success: true,
                message: 'Key activated successfully',
                hwid: hwid,
                key_type: row.key_type
            });
        }
    );
});

app.listen(PORT, () => {
    console.log(`Key system running on port ${PORT}`);
});
