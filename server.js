require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto'); 
const fs = require('fs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key-car-rental';

// HÃ m phÃ¢n tÃ­ch cookie thá»§ cÃ´ng tá»« headers
const parseCookies = (cookieHeader) => {
    const list = {};
    if (!cookieHeader) return list;
    cookieHeader.split(';').forEach(cookie => {
        const parts = cookie.split('=');
        list[parts.shift().trim()] = decodeURIComponent(parts.join('='));
    });
    return list;
};

// HÃ m bÄƒm máº­t kháº©u sá»­ dá»¥ng thuáº­t toÃ¡n Scrypt vÃ  Salt ngáº«u nhiÃªn (Lá»›p 3)
const hashPassword = (password) => {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${hash}`;
};

// HÃ m xÃ¡c thá»±c máº­t kháº©u bÄƒm Scrypt
const verifyPassword = (password, storedValue) => {
    if (!storedValue || !storedValue.includes(':')) return false;
    const [salt, originalHash] = storedValue.split(':');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return hash === originalHash;
};
const TELEMATICS_SECRET = process.env.TELEMATICS_SECRET || "secure-car-telematics-key";

// KhÃ³a mÃ£ hÃ³a CSDL local AES-256-GCM (Lá»›p 3)
const DB_ENCRYPTION_KEY = Buffer.from(process.env.DB_ENCRYPTION_KEY || '0000000000000000000000000000000000000000000000000000000000000000', 'hex');

function encryptAES(text) {
    if (!text) return text;
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', DB_ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

function decryptAES(cipherText) {
    if (!cipherText || !cipherText.includes(':')) return cipherText;
    try {
        const [ivHex, authTagHex, encryptedHex] = cipherText.split(':');
        if (!ivHex || !authTagHex || !encryptedHex) return cipherText;
        const iv = Buffer.from(ivHex, 'hex');
        const authTag = Buffer.from(authTagHex, 'hex');
        const decipher = crypto.createDecipheriv('aes-256-gcm', DB_ENCRYPTION_KEY, iv);
        decipher.setAuthTag(authTag);
        let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (e) {
        console.error("Giáº£i mÃ£ CSDL lá»—i:", e.message);
        return cipherText;
    }
}

// Bá»™ lá»c TÆ°á»ng lá»­a WAF mÃ´ phá»ng (Lá»›p 1)
const wafMiddleware = (req, res, next) => {
    const checkMalicious = (val) => {
        if (typeof val !== 'string') return false;
        // PhÃ¡t hiá»‡n dáº¥u hiá»‡u SQLi hoáº·c XSS
        const sqliPattern = /union\s+select|or\s+1\s*=\s*1|--/i;
        const xssPattern = /<script|onerror|onload/i;
        return sqliPattern.test(val) || xssPattern.test(val);
    };

    let isMalicious = false;
    const payload = JSON.stringify(req.body || {}) + JSON.stringify(req.query || {}) + JSON.stringify(req.params || {});
    
    if (checkMalicious(payload)) {
        isMalicious = true;
    }

    if (isMalicious) {
        const logMsg = `[WAF BLOCK] Cháº·n Ä‘á»©ng táº¥n cÃ´ng tá»« IP ${req.ip || '127.0.0.1'}: PhÃ¡t hiá»‡n payload chá»©a mÃ£ Ä‘á»™c!`;
        db.run(`INSERT INTO SystemLogs (Description) VALUES (?)`, [logMsg]);
        return res.status(403).json({ error: "[WAF] YÃªu cáº§u bá»‹ cháº·n: PhÃ¡t hiá»‡n payload táº¥n cÃ´ng chá»©a mÃ£ Ä‘á»™c!" });
    }
    next();
};

// HÃ m sinh mÃ£ OTP 6 sá»‘ theo thá»i gian thá»±c (chu ká»³ 30s) chuáº©n TOTP
const getTOTP = (secret, timeStep = 30) => {
    const counter = Math.floor(Date.now() / 1000 / timeStep);
    const buffer = Buffer.alloc(8);
    buffer.writeUInt32BE(counter, 4);
    
    const hmac = crypto.createHmac('sha1', secret).update(buffer).digest();
    const offset = hmac[hmac.length - 1] & 0xf;
    const code = ((hmac[offset] & 0x7f) << 24) |
                 ((hmac[offset + 1] & 0xff) << 16) |
                 ((hmac[offset + 2] & 0xff) << 8) |
                 (hmac[offset + 3] & 0xff);
    return String(code % 1000000).padStart(6, '0');
};

const app = express();
app.use(express.json());
app.use(cors({ origin: true, credentials: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/public', express.static(path.join(__dirname, 'public')));

// =========================================================
// Táº O Cáº¶P KHÃ“A RSA (Cho Ká»‹ch báº£n 4) - LÆ¯U Cá» Äá»ŠNH XUá»NG Tá»†P PEM
// =========================================================
const publicKeyPath = path.join(__dirname, 'public.pem');
const privateKeyPath = path.join(__dirname, 'private.pem');

let publicKey, privateKey;
if (fs.existsSync(publicKeyPath) && fs.existsSync(privateKeyPath)) {
    publicKey = fs.readFileSync(publicKeyPath, 'utf8');
    privateKey = fs.readFileSync(privateKeyPath, 'utf8');
    console.log('ÄÃ£ táº£i cáº·p khÃ³a RSA hiá»‡n cÃ³ tá»« tá»‡p tin.');
} else {
    // Táº¡o khÃ³a cÃ´ng khai (Public Key) vÃ  khÃ³a bÃ­ máº­t (Private Key) Ä‘á»™ dÃ i 2048-bit
    const keys = crypto.generateKeyPairSync("rsa", {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    publicKey = keys.publicKey;
    privateKey = keys.privateKey;
    fs.writeFileSync(publicKeyPath, publicKey, 'utf8');
    fs.writeFileSync(privateKeyPath, privateKey, 'utf8');
    console.log('ÄÃ£ sinh má»›i vÃ  lÆ°u cáº·p khÃ³a RSA xuá»‘ng tá»‡p tin.');
}

// =========================================================
// PHáº¦N 1: KHá»žI Táº O CÆ  Sá»ž Dá»® LIá»†U SQLITE
// =========================================================
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) console.error(err.message);
    console.log('ÄÃ£ káº¿t ná»‘i vá»›i CSDL SQLite.');
});
db.on('error', (err) => console.error('GLOBAL DB ERROR:', err));

// Hook to intercept SecurityAlerts and format them nicely in the terminal
const originalDbRun = db.run.bind(db);
db.run = function(sql, params, callback) {
    if (typeof sql === 'string' && sql.includes('INSERT INTO SecurityAlerts')) {
        let type = 'UNKNOWN', msg = 'KhÃ´ng cÃ³ thÃ´ng tin', severity = 'INFO';
        if (Array.isArray(params) && params.length >= 5) {
            type = params[2]; msg = params[3]; severity = params[4];
        }
        
        const colors = {
            'CRITICAL': '\x1b[41m\x1b[37m\x1b[1m',
            'HIGH': '\x1b[31m\x1b[1m',
            'WARNING': '\x1b[33m\x1b[1m',
            'INFO': '\x1b[36m'
        };
        const reset = '\x1b[0m';
        const color = colors[severity] || reset;
        
        console.log(`\n${color}[================ SECURITY ALERT ================]${reset}`);
        console.log(`${color} SEVERITY : ${severity}${reset}`);
        console.log(`${color} TYPE     : ${type}${reset}`);
        console.log(`${color} MESSAGE  : ${msg}${reset}`);
        console.log(`${color}[================================================]${reset}\n`);
    }
    return originalDbRun(sql, params, callback);
};


// =========================================================
// HÃ€M RESET DATABASE (Seed dá»¯ liá»‡u 15 xe toÃ n quá»‘c)
// =========================================================

// =========================================================
// HÃ€M RESET DATABASE (Seed dá»¯ liá»‡u 10 xe toÃ n quá»‘c cÃ³ Há»™p Ä‘en & GPS)
function restoreGpsSessions() {
    console.log('[GPS] KhÃ´i phá»¥c cÃ¡c xe Ä‘ang hoáº¡t Ä‘á»™ng sau khi Reset...');
    db.all(`SELECT * FROM Rentals WHERE Status = 'Active'`, (err, rentals) => {
        if (err) {
            console.error('[GPS] Lá»—i láº¥y Rentals:', err);
            return;
        }
        if (!rentals) return;
        console.log(`[GPS] ÄÃ£ tÃ¬m tháº¥y ${rentals.length} Rentals Active.`);
        rentals.forEach(r => { 
            if (!gpsState[r.VehicleID]) {
                db.get(`SELECT * FROM VehicleGPS WHERE VehicleID = ?`, [r.VehicleID], (err, gps) => {
                    initGpsSession(r.VehicleID, r.AccountID, r.RouteType || 'hanoi', gps);
                });
            }
        });
        if (rentals.length) console.log(`[V3-GPS] KhÃ´i phá»¥c thÃ nh cÃ´ng ${rentals.length} phiÃªn GPS Ä‘ang cháº¡y (Persistence).`);
    });
}

const resetDatabase = () => {
    return new Promise((resolve, reject) => {
        // Dá»«ng táº¥t cáº£ GPS sessions Ä‘ang cháº¡y
        for (let vid in gpsState) {
            const s = gpsState[vid];
            if (s && s.intervalId) clearInterval(s.intervalId);
            delete gpsState[vid];
        }

        const adminHash = hashPassword('admin');
        const user1Hash = hashPassword('user1');
        const user2Hash = hashPassword('user2');

        const sql = `
            PRAGMA foreign_keys = OFF;
            DROP TABLE IF EXISTS Accounts;
            DROP TABLE IF EXISTS Vehicles;
            DROP TABLE IF EXISTS SystemLogs;
            DROP TABLE IF EXISTS UserDocuments;
            DROP TABLE IF EXISTS Rentals;
            DROP TABLE IF EXISTS VehicleInfotainment;
            DROP TABLE IF EXISTS VehicleGPS;
            DROP TABLE IF EXISTS SecurityAlerts;
            DROP TABLE IF EXISTS VehicleCategories;
            DROP TABLE IF EXISTS Reviews;
            DROP TABLE IF EXISTS LoginLogs;

            CREATE TABLE Accounts (AccountID INTEGER PRIMARY KEY AUTOINCREMENT, Username TEXT, PasswordPlain TEXT, PasswordHash TEXT, Role TEXT, MfaSecret TEXT, MfaEnabled BOOLEAN, LoginAttempts INTEGER DEFAULT 0, LockoutUntil DATETIME DEFAULT NULL, FullName TEXT DEFAULT '', Phone TEXT DEFAULT '', Email TEXT DEFAULT '', DeviceModel TEXT DEFAULT 'Unknown');
            CREATE TABLE SystemLogs (LogID INTEGER PRIMARY KEY AUTOINCREMENT, Description TEXT, Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE UserDocuments (DocID INTEGER PRIMARY KEY AUTOINCREMENT, AccountID INTEGER, LicenseData TEXT, IsEncrypted BOOLEAN, LicenseNumber TEXT DEFAULT '', ImageURL TEXT DEFAULT '', VerifiedStatus TEXT DEFAULT 'pending');
            CREATE TABLE VehicleInfotainment (VehicleID INTEGER PRIMARY KEY, SyncedContacts TEXT, GPSHistory TEXT, ActiveBluetoothDevice TEXT);
            CREATE TABLE VehicleGPS (VehicleID INTEGER PRIMARY KEY, Lat REAL, Lon REAL, Speed REAL, Heading REAL, Mode TEXT, Address TEXT, LastReported TEXT, Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE SecurityAlerts (AlertID INTEGER PRIMARY KEY AUTOINCREMENT, VehicleID INTEGER, AccountID INTEGER, Type TEXT, Message TEXT, Severity TEXT, Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, Resolved BOOLEAN DEFAULT 0);
            CREATE TABLE VehicleCategories (CategoryID INTEGER PRIMARY KEY AUTOINCREMENT, Name TEXT, Icon TEXT);
            CREATE TABLE Vehicles (VehicleID INTEGER PRIMARY KEY AUTOINCREMENT, LicensePlate TEXT, Model TEXT, Status TEXT, CategoryID INTEGER DEFAULT 1, Year INTEGER DEFAULT 2023, Seats INTEGER DEFAULT 5, Transmission TEXT DEFAULT 'Auto', FuelType TEXT DEFAULT 'Petrol', PricePerDay INTEGER DEFAULT 500000, Features TEXT DEFAULT '[]', Description TEXT DEFAULT '', ImageURL TEXT DEFAULT '', Version INTEGER DEFAULT 1);
            CREATE TABLE Rentals (RentalID INTEGER PRIMARY KEY AUTOINCREMENT, VehicleID INTEGER, AccountID INTEGER, Status TEXT, StartDate TEXT, EndDate TEXT, PickupLocation TEXT DEFAULT 'Ha Noi', ReturnLocation TEXT DEFAULT 'Ha Noi', TotalAmount INTEGER DEFAULT 0, RouteType TEXT DEFAULT 'hanoi');
            CREATE TABLE Reviews (ReviewID INTEGER PRIMARY KEY AUTOINCREMENT, AccountID INTEGER, VehicleID INTEGER, RentalID INTEGER, Rating INTEGER, Comment TEXT, Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE LoginLogs (LogID INTEGER PRIMARY KEY AUTOINCREMENT, AccountID INTEGER, Lat REAL, Lon REAL, Timestamp TEXT);

            INSERT INTO Accounts (Username, PasswordPlain, PasswordHash, Role, FullName, Phone, Email, DeviceModel) VALUES 
                ('admin', 'admin', '${adminHash}', 'Admin', 'Nguyen Van Admin', '0901234567', 'admin@rentalshield.vn', 'iPhone 15 Pro Max'),
                ('user1', 'user1', '${user1Hash}', 'User', 'Tran Thi Thu', '0912345678', 'thu@gmail.com', 'iPhone 13'),
                ('user2', 'user2', '${user2Hash}', 'User', 'Le Van Hung', '0923456789', 'hung@gmail.com', 'Samsung Galaxy S24 Ultra');

            INSERT INTO VehicleCategories (Name, Icon) VALUES ('Sedan', 'sedan'), ('SUV', 'suv'), ('Pickup', 'pickup'), ('Electric', 'electric'), ('Luxury', 'luxury');

            INSERT INTO Vehicles (LicensePlate, Model, Status, ImageURL) VALUES 
                ('29A-11111', 'Toyota Vios', 'Available', 'toyota_vios.png'),
                ('30F-22222', 'Tesla Model Y', 'Rented', 'tesla_modely.png'),
                ('30H-33333', 'BMW 320i', 'Rented', 'bmw_320i.png'),
                ('43A-44444', 'Honda Civic', 'Available', 'honda_civic.png'),
                ('51G-55555', 'Hyundai SantaFe', 'Rented', 'hyundai_santafe.png'),
                ('51H-66666', 'Ford Ranger', 'Available', 'ford_ranger.png'),
                ('29C-77777', 'VinFast VF8', 'Rented', 'vinfast_vf8.png'),
                ('65A-88888', 'Kia Seltos', 'Rented', 'kia_seltos.png'),
                ('30K-99999', 'Mercedes C300', 'Available', 'mercedes_c300.png'),
                ('51K-10101', 'Mazda 3', 'Rented', 'mazda_3.png');

            INSERT INTO Rentals (VehicleID, AccountID, Status) VALUES 
                (2, 3, 'Active'), (3, 2, 'Active'), (5, 2, 'Active'), (7, 2, 'Active'), (8, 3, 'Active');

            INSERT INTO UserDocuments (AccountID, LicenseData, IsEncrypted, LicenseNumber, ImageURL, VerifiedStatus) 
                SELECT AccountID, PasswordHash, 0, 'B2-' || printf('%06d', AccountID * 111111), '', 'verified'
                FROM Accounts WHERE Role = 'User';

            INSERT INTO VehicleGPS (VehicleID, Lat, Lon, Speed, Mode, Address, LastReported) VALUES 
                (1, 21.0285, 105.8542, 0, 'Parked', 'Gara VNCars HoÃ n Kiáº¿m (Trong nhÃ )', 'Cáº­p nháº­t má»—i 1 giá»'),
                (2, 21.0333, 105.8500, 45, 'Moving', 'ÄÆ°á»ng Thanh NiÃªn, Quáº­n TÃ¢y Há»“, HÃ  Ná»™i', 'Vá»«a xong (Live)'),
                (3, 20.8449, 106.6881, 60, 'Moving', 'ÄÆ°á»ng Láº¡ch Tray, Quáº­n NgÃ´ Quyá»n, Háº£i PhÃ²ng', 'Vá»«a xong (Live)'),
                (4, 16.0471, 108.2068, 0, 'Parked', 'Gara VNCars Háº£i ChÃ¢u (Trong nhÃ )', 'Cáº­p nháº­t má»—i 1 giá»'),
                (5, 16.0544, 108.2022, 50, 'Moving', 'ÄÆ°á»ng VÃµ NguyÃªn GiÃ¡p, Quáº­n SÆ¡n TrÃ , ÄÃ  Náºµng', 'Vá»«a xong (Live)'),
                (6, 12.2388, 109.1967, 0, 'Parked', 'Gara VNCars Nha Trang (Trong nhÃ )', 'Cáº­p nháº­t má»—i 1 giá»'),
                (7, 10.7626, 106.6602, 30, 'Moving', 'ÄÆ°á»ng Nguyá»…n Huá»‡, Quáº­n 1, TP.HCM', 'Vá»«a xong (Live)'),
                (8, 10.8231, 106.6297, 0, 'Parked', 'Gara VNCars TÃ¢n BÃ¬nh (Trong nhÃ )', 'Vá»«a xong (Live)'),
                (9, 10.0452, 105.7469, 0, 'Parked', 'Gara VNCars Ninh Kiá»u (Trong nhÃ )', 'Cáº­p nháº­t má»—i 1 giá»'),
                (10, 10.0234, 105.7500, 0, 'Parked', 'Gara VNCars CÃ¡i RÄƒng (Trong nhÃ )', 'Cáº­p nháº­t má»—i 1 giá»');

            INSERT INTO VehicleInfotainment (VehicleID, SyncedContacts, GPSHistory, ActiveBluetoothDevice) VALUES 
                (1, 'LÆ°u váº¿t KhÃ¡ch cÅ©: CÃ´ng ty (0243333)', 'Nháº­t kÃ½ GPS: BÃ£i Ä‘á»— xe', 'Ngáº¯t káº¿t ná»‘i (Offline)'),
                (2, 'Danh báº¡ user2: Máº¹ (0901234567), Vá»£ (0911223344)', 'Nháº­t kÃ½ GPS: Cáº§u Giáº¥y -> Há»“ GÆ°Æ¡m', 'Samsung Galaxy S24 Ultra (Äang káº¿t ná»‘i)'),
                (3, 'Danh báº¡ user1: Boss (0988888888)', 'Nháº­t kÃ½ GPS: Äá»“ SÆ¡n -> Láº¡ch Tray', 'iPhone 13 (Äang káº¿t ná»‘i)'),
                (4, 'LÆ°u váº¿t KhÃ¡ch cÅ©: Gara (09121212)', 'Nháº­t kÃ½ GPS: SÃ¢n bay ÄÃ  Náºµng', 'Ngáº¯t káº¿t ná»‘i (Offline)'),
                (5, 'Danh báº¡ user1: Äá»‘i tÃ¡c (09333333)', 'Nháº­t kÃ½ GPS: Cáº§u Rá»“ng -> Há»™i An', 'iPhone 13 (Äang káº¿t ná»‘i)'),
                (6, 'LÆ°u váº¿t KhÃ¡ch cÅ©: Vá»£ (09222222)', 'Nháº­t kÃ½ GPS: Vinpearl Nha Trang', 'Ngáº¯t káº¿t ná»‘i (Offline)'),
                (7, 'Danh báº¡ user1: Báº¡n thÃ¢n (0912345678)', 'Nháº­t kÃ½ GPS: Q1 -> Landmark 81', 'iPhone 13 (Äang káº¿t ná»‘i)'),
                (8, 'Danh báº¡ user2: CÃ´ng ty (08888888)', 'Nháº­t kÃ½ GPS: TÃ¢n SÆ¡n Nháº¥t -> Q3', 'Samsung Galaxy S24 Ultra (Äang káº¿t ná»‘i)'),
                (9, 'LÆ°u váº¿t KhÃ¡ch cÅ©: NhÃ  hÃ ng (0292222)', 'Nháº­t kÃ½ GPS: Báº¿n Ninh Kiá»u', 'Ngáº¯t káº¿t ná»‘i (Offline)'),
                (10, 'LÆ°u váº¿t KhÃ¡ch cÅ©: Máº¹ (09999999)', 'Nháº­t kÃ½ GPS: CÃ¡i RÄƒng -> VÄ©nh Long', 'Ngáº¯t káº¿t ná»‘i (Offline)');
            PRAGMA foreign_keys = ON;
        `;
        db.exec(sql, (err) => {
            if (err) {
                console.error("Lá»—i khi resetDatabase:", err);
                reject(err);
            } else {
                console.log("ÄÃ£ resetDatabase báº±ng db.exec.");
                setTimeout(() => {
                    restoreGpsSessions();
                }, 500);
                resolve();
            }
        });
    });
};

db.get(`SELECT count(*) as count FROM sqlite_master WHERE type='table' AND name='Accounts'`, (err, row) => {
    if (row && row.count > 0) {
        console.log('Database Ä‘Ã£ tá»“n táº¡i. Äang khÃ´i phá»¥c cÃ¡c phiÃªn GPS Ä‘ang cháº¡y...');
        restoreGpsSessions();
    } else {
        resetDatabase().then(() => console.log('ÄÃ£ táº¡o má»›i vÃ  seed dá»¯ liá»‡u CSDL ban Ä‘áº§u.'));
    }
});

// =========================================================
// API XEM DATABASE DÃ™NG Äá»‚ Äá»I CHá»¨NG
// =========================================================
app.get('/api/db/accounts', (req, res) => {
    db.all(`SELECT a.*, CASE WHEN d.VerifiedStatus = 'verified' THEN 1 ELSE 0 END as HasLicense
        FROM Accounts a LEFT JOIN UserDocuments d ON a.AccountID = d.AccountID`, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});
app.get('/api/db/vehicles', (req, res) => {
    db.all(`SELECT * FROM Vehicles`, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});
app.get('/api/db/logs', (req, res) => {
    db.all(`SELECT * FROM SystemLogs`, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});
app.get('/api/db/documents', (req, res) => {
    db.all(`SELECT d.*, a.Username FROM UserDocuments d LEFT JOIN Accounts a ON d.AccountID = a.AccountID`, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});
app.get('/api/db/rentals', (req, res) => {
    db.all(`SELECT * FROM Rentals`, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});
app.get('/api/db/infotainment', (req, res) => {
    db.all(`SELECT * FROM VehicleInfotainment`, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});


// =========================================================
// PHáº¦N 2: CÃC API PHIÃŠN Báº¢N V1 - Lá»–I (VULNERABLE)
// =========================================================

// KB1 (Lá»—i SQLi): Ná»‘i chuá»—i trá»±c tiáº¿p
app.post('/api/v1/messages/admin', (req, res) => {
    const userMessage = req.body.Message;
    const query = `SELECT * FROM SystemLogs WHERE Description LIKE '%${userMessage}%'`;
    db.all(query, (err, rows) => { res.json(rows); });
});

// KB2 (Lá»›p 2: Báº£o máº­t táº§ng á»¨ng dá»¥ng & Äá»‹nh danh) - ÄÄƒng nháº­p V1 (Tráº£ Token vá» Body - Dá»… bá»‹ XSS Ä‘Ã¡nh cáº¯p qua localStorage)
app.post('/api/v1/auth/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM Accounts WHERE Username = ? AND PasswordPlain = ?`, [username, password], (err, row) => {
        if (err || !row) return res.status(401).json({ error: "Sai tÃ i khoáº£n hoáº·c máº­t kháº©u!" });
        const token = jwt.sign({ AccountID: row.AccountID, Username: row.Username, Role: row.Role }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, message: "[V1] ÄÄƒng nháº­p thÃ nh cÃ´ng! Token Ä‘Æ°á»£c tráº£ vá» trong body." });
    });
});

// KB2 (Lá»—i PhÃ¢n quyá»n): KhÃ´ng kiá»ƒm tra Role Admin
const verifyTokenV1 = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        // Fallback vá» mock user nhÆ° cÅ© náº¿u khÃ´ng truyá»n token Ä‘á»ƒ trÃ¡nh há»ng cÃ¡c script test cÅ©
        req.user = { AccountID: 2, Username: 'user1', Role: 'User' }; 
        return next();
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Token khÃ´ng há»£p lá»‡!" });
        req.user = decoded;
        next();
    });
};

app.delete('/api/v1/admin/vehicles/delete', verifyTokenV1, (req, res) => {
    const vehicleId = req.body.VehicleID;
    db.run(`DELETE FROM Vehicles WHERE VehicleID = ${vehicleId}`, (err) => {
        res.send(`[V1] ÄÃ£ xÃ³a phÆ°Æ¡ng tiá»‡n ID: ${vehicleId} báº±ng quyá»n User!`);
    });
});

// KB3 (Lá»—i Upload File): KhÃ´ng check Ä‘uÃ´i tá»‡p
const storageV1 = multer.diskStorage({
  destination: (req, file, cb) => { cb(null, 'uploads/') },
  filename: (req, file, cb) => { cb(null, "V1_" + file.originalname) }
});
const uploadV1 = multer({ storage: storageV1 });
app.post('/api/v1/upload-license', uploadV1.single('license_image'), (req, res) => {
  res.send("[V1] Táº£i tá»‡p lÃªn thÃ nh cÃ´ng (Cháº¥p nháº­n cáº£ mÃ£ Ä‘á»™c)!");
});


// KB4 (Lá»—i PII): LÆ°u trá»¯ thÃ´ng tin nháº¡y cáº£m dÆ°á»›i dáº¡ng vÄƒn báº£n gá»‘c (Plaintext)
app.post('/api/v1/user/document', verifyTokenV1, (req, res) => {
    const licenseData = req.body.LicenseNumber; // Dá»¯ liá»‡u nháº¡y cáº£m
    
    // ÄÃƒ Sá»¬A: Bá»• sung máº£ng chá»©a dá»¯ liá»‡u truyá»n vÃ o cÃ¡c dáº¥u ?
    db.run(`INSERT INTO UserDocuments (AccountID, LicenseData, IsEncrypted) VALUES (?,?,?)`, [req.user.AccountID, licenseData, false], (err) => {
        if (err) return res.status(500).send(err.message);
        res.send("[V1] ÄÃ£ lÆ°u giáº¥y phÃ©p lÃ¡i xe dÆ°á»›i dáº¡ng KHÃ”NG MÃƒ HÃ“A.");
    });
});

// PHáº¦N 3: CÃC API PHIÃŠN Báº¢N V2 - AN TOÃ€N (SECURED)
// =========================================================
app.use('/api/v2/', express.json({ limit: '10kb' }));
app.use('/api/v2/', helmet());
app.use('/api/v2/', rateLimit({ 
    windowMs: 15 * 60 * 1000, 
    max: 5000,
    message: { error: 'QuÃ¡ nhiá»u yÃªu cáº§u, vui lÃ²ng thá»­ láº¡i sau.' },
    standardHeaders: true,
    legacyHeaders: false
}));
app.use('/api/v2/', wafMiddleware);

// KB1 (Báº£o máº­t SQLi): DÃ¹ng Parameterized Queries
app.post('/api/v2/messages/admin', (req, res) => {
    const userMessage = req.body.Message;
    const query = `SELECT * FROM SystemLogs WHERE Description LIKE?`;
    db.all(query, [`%${userMessage}%`], (err, rows) => { res.json(rows); });
});

// KB2 (Lá»›p 2: Báº£o máº­t táº§ng á»¨ng dá»¥ng & Äá»‹nh danh) - ÄÄƒng nháº­p V2 (LÆ°u JWT vÃ o HttpOnly Cookie + Lockout)
app.post('/api/v2/auth/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM Accounts WHERE Username = ?`, [username], (err, row) => {
        if (err || !row) return res.status(401).json({ error: "Sai tÃ i khoáº£n hoáº·c máº­t kháº©u!" });
        
        // Kiá»ƒm tra xem tÃ i khoáº£n cÃ³ Ä‘ang bá»‹ khÃ³a lockout khÃ´ng
        if (row.LockoutUntil && new Date(row.LockoutUntil) > new Date()) {
            const timeLeft = Math.round((new Date(row.LockoutUntil) - new Date()) / 1000);
            return res.status(423).json({ error: `TÃ i khoáº£n táº¡m thá»i bá»‹ khÃ³a do nháº­p sai nhiá»u láº§n. Vui lÃ²ng thá»­ láº¡i sau ${timeLeft} giÃ¢y.` });
        }

        // XÃ¡c thá»±c máº­t kháº©u Ä‘Ã£ bÄƒm báº±ng Scrypt + Salt
        const isMatch = verifyPassword(password, row.PasswordHash);
        if (!isMatch) {
            const newAttempts = (row.LoginAttempts || 0) + 1;
            if (newAttempts >= 3) {
                const lockoutTime = new Date(Date.now() + 60 * 1000).toISOString(); // khÃ³a 1 phÃºt
                db.run(`UPDATE Accounts SET LoginAttempts = ?, LockoutUntil = ? WHERE AccountID = ?`, [newAttempts, lockoutTime, row.AccountID]);
                return res.status(423).json({ error: "Sai máº­t kháº©u! TÃ i khoáº£n Ä‘Ã£ bá»‹ táº¡m khÃ³a trong 1 phÃºt do nháº­p sai 3 láº§n." });
            } else {
                db.run(`UPDATE Accounts SET LoginAttempts = ? WHERE AccountID = ?`, [newAttempts, row.AccountID]);
                return res.status(401).json({ error: `Sai tÃ i khoáº£n hoáº·c máº­t kháº©u! Báº¡n cÃ²n ${3 - newAttempts} láº§n thá»­.` });
            }
        }

        // Reset attempts khi Ä‘Äƒng nháº­p Ä‘Ãºng
        db.run(`UPDATE Accounts SET LoginAttempts = 0, LockoutUntil = NULL WHERE AccountID = ?`, [row.AccountID]);

        const loginLat = parseFloat(req.body.lat);
        const loginLon = parseFloat(req.body.lon);

        if (!isNaN(loginLat) && !isNaN(loginLon)) {
            // Láº¥y lá»‹ch sá»­ Ä‘Äƒng nháº­p trÆ°á»›c Ä‘Ã³
            db.get(`SELECT * FROM LoginLogs WHERE AccountID = ? ORDER BY LogID DESC LIMIT 1`, [row.AccountID], (errLog, lastLog) => {
                if (lastLog) {
                    const distKm = haversineKm(loginLat, loginLon, lastLog.Lat, lastLog.Lon);
                    const timeDiffHours = (Date.now() - new Date(lastLog.Timestamp).getTime()) / (1000 * 60 * 60);
                    
                    if (timeDiffHours > 0) {
                        const requiredSpeed = distKm / timeDiffHours;
                        // Náº¿u tá»‘c Ä‘á»™ di chuyá»ƒn yÃªu cáº§u > 900 km/h (váº­n tá»‘c mÃ¡y bay thÆ°Æ¡ng máº¡i)
                        // vÃ  khoáº£ng thá»i gian < 1 giá», thÃ¬ Ä‘Ã¢y lÃ  Impossible Travel!
                        if (requiredSpeed > 900 && timeDiffHours < 1) {
                            const alertMsg = `ðŸš¨ PHÃT HIá»†N IMPOSSIBLE TRAVEL: TÃ i khoáº£n "${row.Username}" Ä‘Äƒng nháº­p tá»« hai Ä‘á»‹a Ä‘iá»ƒm cÃ¡ch nhau quÃ¡ xa trong thá»i gian ngáº¯n (${distKm.toFixed(0)}km trong ${(timeDiffHours*60).toFixed(0)} phÃºt, tá»‘c Ä‘á»™ cáº§n thiáº¿t: ${requiredSpeed.toFixed(0)} km/h).`;
                            
                            // KhÃ³a tÃ i khoáº£n táº¡m thá»i
                            const lockoutTime = new Date(Date.now() + 5 * 60 * 1000).toISOString(); // khÃ³a 5 phÃºt
                            db.run(`UPDATE Accounts SET LockoutUntil = ? WHERE AccountID = ?`, [lockoutTime, row.AccountID]);
                            
                            db.run(`INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)`,
                                [null, row.AccountID, 'IMPOSSIBLE_TRAVEL', alertMsg, 'CRITICAL']);
                            
                            return res.status(423).json({ error: `[Báº¢O Máº¬T] ÄÄƒng nháº­p bá»‹ cháº·n: PhÃ¡t hiá»‡n dá»‹ch chuyá»ƒn báº¥t kháº£ thi (Impossible Travel). TÃ i khoáº£n bá»‹ táº¡m khÃ³a 5 phÃºt Ä‘á»ƒ báº£o máº­t!` });
                        }
                    }
                }
                
                // LÆ°u log Ä‘Äƒng nháº­p má»›i
                db.run(`INSERT INTO LoginLogs (AccountID, Lat, Lon, Timestamp) VALUES (?, ?, ?, ?)`,
                    [row.AccountID, loginLat, loginLon, new Date().toISOString()]);
                
                continueLoginFlow();
            });
        } else {
            continueLoginFlow();
        }

        function continueLoginFlow() {
            // Náº¿u tÃ i khoáº£n Ä‘Ã£ kÃ­ch hoáº¡t MFA OTP -> YÃªu cáº§u xÃ¡c thá»±c OTP trÆ°á»›c
            if (row.MfaEnabled === 1) {
                return res.json({ mfaRequired: true, username: row.Username, message: "YÃªu cáº§u mÃ£ xÃ¡c thá»±c OTP Ä‘á»ƒ hoÃ n táº¥t Ä‘Äƒng nháº­p." });
            }

            const token = jwt.sign({ AccountID: row.AccountID, Username: row.Username, Role: row.Role }, JWT_SECRET, { expiresIn: '1h' });
            
            // Thiáº¿t láº­p Cookie an toÃ n vá»›i cá» HttpOnly, SameSite=Strict
            res.setHeader('Set-Cookie', `access_token=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600`);
            res.json({ message: "[V2] ÄÄƒng nháº­p thÃ nh cÃ´ng! Token Ä‘Ã£ Ä‘Æ°á»£c lÆ°u an toÃ n trong HttpOnly Cookie." });
        }
    });
});

// API V2: ÄÄƒng kÃ½ tÃ i khoáº£n má»›i
app.post('/api/v2/auth/register', (req, res) => {
    const { username, password, confirmPassword, fullName, phone, email } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Vui lÃ²ng nháº­p tÃªn Ä‘Äƒng nháº­p vÃ  máº­t kháº©u.' });
    if (username.length < 4) return res.status(400).json({ error: 'TÃªn Ä‘Äƒng nháº­p pháº£i cÃ³ Ã­t nháº¥t 4 kÃ½ tá»±.' });
    if (password.length < 6) return res.status(400).json({ error: 'Máº­t kháº©u pháº£i cÃ³ Ã­t nháº¥t 6 kÃ½ tá»±.' });
    if (confirmPassword && password !== confirmPassword) return res.status(400).json({ error: 'Máº­t kháº©u xÃ¡c nháº­n khÃ´ng khá»›p.' });
    db.get(`SELECT AccountID FROM Accounts WHERE Username = ?`, [username], (err, existing) => {
        if (existing) return res.status(409).json({ error: 'TÃªn Ä‘Äƒng nháº­p Ä‘Ã£ tá»“n táº¡i.' });
        const hash = hashPassword(password);
        db.run(`INSERT INTO Accounts (Username, PasswordPlain, PasswordHash, Role, FullName, Phone, Email) VALUES (?,?,?,'User',?,?,?)`,
            [username, password, hash, fullName || '', phone || '', email || ''], function(err2) {
            if (err2) return res.status(500).json({ error: 'Lá»—i táº¡o tÃ i khoáº£n.' });
            const token = jwt.sign({ AccountID: this.lastID, Username: username, Role: 'User' }, JWT_SECRET, { expiresIn: '1h' });
            res.setHeader('Set-Cookie', `access_token=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600`);
            res.json({ message: 'ÄÄƒng kÃ½ thÃ nh cÃ´ng! ChÃ o má»«ng báº¡n Ä‘áº¿n vá»›i VNCars.', username });
        });
    });
});

// API V2: ÄÄƒng xuáº¥t - XÃ³a Cookie
app.post('/api/v2/auth/logout', (req, res) => {
    res.setHeader('Set-Cookie', 'access_token=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
    res.json({ message: 'ÄÄƒng xuáº¥t thÃ nh cÃ´ng.' });
});

// API V2: ÄÄƒng nháº­p bÆ°á»›c 2 - XÃ¡c thá»±c mÃ£ OTP (MFA Login) - Chá»‘ng Brute force & Lockout
app.post('/api/v2/auth/mfa-login', (req, res) => {
    const { username, otp } = req.body;
    if (!username || !otp) {
        return res.status(400).json({ error: "Thiáº¿u thÃ´ng tin username hoáº·c otp." });
    }

    db.get(`SELECT * FROM Accounts WHERE Username = ?`, [username], (err, row) => {
        if (err || !row || !row.MfaEnabled || !row.MfaSecret) {
            return res.status(400).json({ error: "TÃ i khoáº£n chÆ°a kÃ­ch hoáº¡t báº£o máº­t Ä‘Äƒng nháº­p 2 lá»›p (MFA)." });
        }

        // Kiá»ƒm tra xem tÃ i khoáº£n cÃ³ Ä‘ang bá»‹ khÃ³a lockout khÃ´ng
        if (row.LockoutUntil && new Date(row.LockoutUntil) > new Date()) {
            const timeLeft = Math.round((new Date(row.LockoutUntil) - new Date()) / 1000);
            return res.status(423).json({ error: `TÃ i khoáº£n táº¡m thá»i bá»‹ khÃ³a do nháº­p sai nhiá»u láº§n. Vui lÃ²ng thá»­ láº¡i sau ${timeLeft} giÃ¢y.` });
        }

        const decryptedSecret = decryptAES(row.MfaSecret);
        const expectedOTP = getTOTP(decryptedSecret);
        if (otp === expectedOTP) {
            // ÄÃºng OTP: Reset attempts
            db.run(`UPDATE Accounts SET LoginAttempts = 0, LockoutUntil = NULL WHERE AccountID = ?`, [row.AccountID]);

            // Thiáº¿t láº­p Cookie access_token chÃ­nh thá»©c
            const token = jwt.sign({ AccountID: row.AccountID, Username: row.Username, Role: row.Role }, JWT_SECRET, { expiresIn: '1h' });
            res.setHeader('Set-Cookie', `access_token=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600`);
            res.json({ message: "ÄÄƒng nháº­p thÃ nh cÃ´ng! XÃ¡c thá»±c 2 lá»›p hoÃ n táº¥t." });
        } else {
            // Sai OTP: TÃ­nh attempts
            const newAttempts = (row.LoginAttempts || 0) + 1;
            if (newAttempts >= 3) {
                const lockoutTime = new Date(Date.now() + 60 * 1000).toISOString(); // khÃ³a 1 phÃºt
                db.run(`UPDATE Accounts SET LoginAttempts = ?, LockoutUntil = ? WHERE AccountID = ?`, [newAttempts, lockoutTime, row.AccountID]);
                return res.status(423).json({ error: "MÃ£ OTP khÃ´ng chÃ­nh xÃ¡c! TÃ i khoáº£n Ä‘Ã£ bá»‹ táº¡m khÃ³a trong 1 phÃºt do nháº­p sai 3 láº§n." });
            } else {
                db.run(`UPDATE Accounts SET LoginAttempts = ? WHERE AccountID = ?`, [newAttempts, row.AccountID]);
                return res.status(401).json({ error: `MÃ£ OTP khÃ´ng khá»›p hoáº·c Ä‘Ã£ háº¿t háº¡n! Báº¡n cÃ²n ${3 - newAttempts} láº§n thá»­.` });
            }
        }
    });
});

// API V2: ÄÄƒng nháº­p Google giáº£ láº­p (OAuth 2.0 CSRF Demo)
app.get('/api/v2/auth/google-start', (req, res) => {
    const { mode } = req.query; // 'v1' or 'v2'
    
    if (mode === 'v2') {
        const state = crypto.randomBytes(16).toString('hex');
        res.setHeader('Set-Cookie', `oauth_state=${state}; HttpOnly; SameSite=Strict; Path=/; Max-Age=300`);
        return res.json({
            mode: 'v2',
            state,
            redirectUrl: `/api/v2/auth/google-callback?code=simulated_google_code_for_admin&state=${state}&mode=v2`
        });
    } else {
        res.setHeader('Set-Cookie', `oauth_state=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
        return res.json({
            mode: 'v1',
            state: null,
            redirectUrl: `/api/v2/auth/google-callback?code=simulated_google_code_for_admin&mode=v1`
        });
    }
});

app.get('/api/v2/auth/google-callback', (req, res) => {
    const { code, state, mode } = req.query;
    const cookies = parseCookies(req.headers.cookie);
    const savedState = cookies['oauth_state'];

    // V2 mode: luÃ´n báº¯t buá»™c kiá»ƒm tra state â€” báº¥t ká»ƒ cookie cÃ³ hay khÃ´ng
    if (mode === 'v2') {
        if (!state || !savedState || state !== savedState) {
            const alertMsg = `ðŸš¨ PHÃT HIá»†N Táº¤N CÃ”NG OAUTH CSRF: YÃªu cáº§u Ä‘Äƒng nháº­p Google bá»‹ cháº·n Ä‘á»©ng do tham sá»‘ state khÃ´ng khá»›p (Nháº­n: "${state || 'null'}", Mong Ä‘á»£i: "${savedState || 'null'}").`;
            db.run(`INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)`,
                [null, 1, 'OAUTH_CSRF_ATTACK', alertMsg, 'HIGH']);
            return res.status(403).json({ error: '[OAUTH-CSRF] Tá»« chá»‘i Ä‘Äƒng nháº­p: Lá»—i xÃ¡c thá»±c tham sá»‘ state OAuth 2.0 (CSRF Blocked)!' });
        }
    }
    // V1 mode: khÃ´ng kiá»ƒm tra state â€” dá»… bá»‹ CSRF

    db.get(`SELECT * FROM Accounts WHERE Username = 'admin'`, (err, row) => {
        if (err || !row) return res.status(500).json({ error: 'KhÃ´ng tÃ¬m tháº¥y tÃ i khoáº£n admin.' });
        
        const token = jwt.sign({ AccountID: row.AccountID, Username: row.Username, Role: row.Role }, JWT_SECRET, { expiresIn: '1h' });
        
        res.setHeader('Set-Cookie', [
            `access_token=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600`,
            `oauth_state=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`
        ]);
        
        res.json({
            message: `[Google OAuth] ÄÄƒng nháº­p Google thÃ nh cÃ´ng vá»›i tÃ i khoáº£n ${row.Email}!`,
            user: { username: row.Username, email: row.Email, fullName: row.FullName }
        });
    });
});

// API V2: Äá»•i máº­t kháº©u tÃ i khoáº£n - XÃ¡c thá»±c máº­t kháº©u cÅ© vÃ  bÄƒm Scrypt máº­t kháº©u má»›i
app.post('/api/v2/auth/change-password', (req, res, next) => {
    // Gá»i middleware verifyTokenV2 thá»§ cÃ´ng á»Ÿ Ä‘Ã¢y Ä‘á»ƒ giá»¯ cáº¥u trÃºc route gá»n gÃ ng
    verifyTokenV2(req, res, () => {
        const { oldPassword, newPassword } = req.body;
        if (!oldPassword || !newPassword) {
            return res.status(400).json({ error: "Thiáº¿u thÃ´ng tin máº­t kháº©u cÅ© hoáº·c máº­t kháº©u má»›i." });
        }

        db.get(`SELECT * FROM Accounts WHERE AccountID = ?`, [req.user.AccountID], (err, row) => {
            if (err || !row) return res.status(404).json({ error: "TÃ i khoáº£n khÃ´ng tá»“n táº¡i." });

            // 1. XÃ¡c thá»±c máº­t kháº©u cÅ©
            const isMatch = verifyPassword(oldPassword, row.PasswordHash);
            if (!isMatch) {
                return res.status(400).json({ error: "Máº­t kháº©u hiá»‡n táº¡i khÃ´ng chÃ­nh xÃ¡c!" });
            }

            // 2. BÄƒm máº­t kháº©u má»›i (Scrypt) vÃ  cáº­p nháº­t CSDL
            const newHash = hashPassword(newPassword);
            db.run(`UPDATE Accounts SET PasswordPlain = ?, PasswordHash = ? WHERE AccountID = ?`, [newPassword, newHash, req.user.AccountID], (err) => {
                if (err) return res.status(500).json({ error: "Lá»—i cáº­p nháº­t máº­t kháº©u má»›i vÃ o CSDL." });
                res.json({ message: "Äá»•i máº­t kháº©u thÃ nh cÃ´ng! Máº­t kháº©u má»›i Ä‘Ã£ Ä‘Æ°á»£c bÄƒm vÃ  lÆ°u trá»¯ an toÃ n." });
            });
        });
    });
});

// Middleware V2: XÃ¡c thá»±c Token tá»« Cookie cho ngÆ°á»i dÃ¹ng thÆ°á»ng
const verifyTokenV2 = (req, res, next) => {
    const cookies = parseCookies(req.headers.cookie);
    const token = cookies['access_token'];

    if (!token) {
        return res.status(401).json({ error: "[V2] Tá»« chá»‘i truy cáº­p: KhÃ´ng tÃ¬m tháº¥y Token xÃ¡c thá»±c (Cookie)!" });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: "[V2] Token háº¿t háº¡n hoáº·c khÃ´ng há»£p lá»‡!" });
        req.user = decoded;
        next();
    });
};

// Middleware V2: XÃ¡c thá»±c Token tá»« Cookie vÃ  phÃ¢n quyá»n Admin
const verifyTokenAndAdminV2 = (req, res, next) => {
    const cookies = parseCookies(req.headers.cookie);
    const token = cookies['access_token'];

    if (!token) {
        return res.status(401).json({ error: "[V2] Tá»« chá»‘i truy cáº­p: KhÃ´ng tÃ¬m tháº¥y Token xÃ¡c thá»±c (Cookie)!" });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: "[V2] Token háº¿t háº¡n hoáº·c khÃ´ng há»£p lá»‡!" });
        
        req.user = decoded;
        if (req.user.Role !== 'Admin') {
            return res.status(403).json({ error: "[V2] Bá»‹ tá»« chá»‘i: Cáº§n quyá»n Admin." });
        }
        next();
    });
};

// KB2 (Lá»›p 2: Báº£o máº­t táº§ng á»¨ng dá»¥ng & Äá»‹nh danh) - KÃ­ch hoáº¡t/Cáº¥u hÃ¬nh MFA TOTP
app.post('/api/v2/auth/mfa-setup', verifyTokenV2, (req, res) => {
    const secret = crypto.randomBytes(10).toString('hex');
    const encryptedSecret = encryptAES(secret);
    db.run(`UPDATE Accounts SET MfaSecret = ?, MfaEnabled = 1 WHERE AccountID = ?`, [encryptedSecret, req.user.AccountID], (err) => {
        if (err) return res.status(500).json({ error: "Lá»—i DB khi thiáº¿t láº­p MFA." });
        
        const currentOTP = getTOTP(secret);
        res.json({
            secret,
            currentOTP,
            message: "[V2] Thiáº¿t láº­p xÃ¡c thá»±c Ä‘a yáº¿u tá»‘ MFA thÃ nh cÃ´ng! Báº£n ghi DB cá»§a báº¡n Ä‘Ã£ cáº­p nháº­t MfaSecret (Ä‘Ã£ Ä‘Æ°á»£c mÃ£ hÃ³a AES-256-GCM)."
        });
    });
});

// KB2 (Lá»›p 2: Báº£o máº­t táº§ng á»¨ng dá»¥ng & Äá»‹nh danh) - XÃ¡c thá»±c mÃ£ OTP
app.post('/api/v2/auth/mfa-verify', verifyTokenV2, (req, res) => {
    const { otp } = req.body;
    db.get(`SELECT MfaSecret, MfaEnabled, LockoutUntil, LoginAttempts FROM Accounts WHERE AccountID = ?`, [req.user.AccountID], (err, row) => {
        if (err || !row || !row.MfaEnabled || !row.MfaSecret) {
            return res.status(400).json({ error: "TÃ i khoáº£n cá»§a báº¡n chÆ°a kÃ­ch hoáº¡t MFA." });
        }
        
        // Kiá»ƒm tra xem tÃ i khoáº£n cÃ³ Ä‘ang bá»‹ khÃ³a lockout khÃ´ng
        if (row.LockoutUntil && new Date(row.LockoutUntil) > new Date()) {
            const timeLeft = Math.round((new Date(row.LockoutUntil) - new Date()) / 1000);
            return res.status(423).json({ error: `TÃ i khoáº£n táº¡m thá»i bá»‹ khÃ³a do nháº­p sai nhiá»u láº§n. Vui lÃ²ng thá»­ láº¡i sau ${timeLeft} giÃ¢y.` });
        }

        const decryptedSecret = decryptAES(row.MfaSecret);
        const expectedOTP = getTOTP(decryptedSecret);
        if (otp === expectedOTP) {
            // ÄÃºng OTP: Reset attempts
            db.run(`UPDATE Accounts SET LoginAttempts = 0, LockoutUntil = NULL WHERE AccountID = ?`, [req.user.AccountID]);
            res.json({ success: true, message: "[V2] XÃ¡c thá»±c mÃ£ OTP thÃ nh cÃ´ng! Quyá»n truy cáº­p quáº£n trá»‹ Ä‘Æ°á»£c phÃª chuáº©n." });
        } else {
            // Sai OTP: TÃ­nh attempts
            const newAttempts = (row.LoginAttempts || 0) + 1;
            if (newAttempts >= 3) {
                const lockoutTime = new Date(Date.now() + 60 * 1000).toISOString(); // khÃ³a 1 phÃºt
                db.run(`UPDATE Accounts SET LoginAttempts = ?, LockoutUntil = ? WHERE AccountID = ?`, [newAttempts, lockoutTime, req.user.AccountID]);
                return res.status(423).json({ error: "[V2] MÃ£ OTP khÃ´ng chÃ­nh xÃ¡c! TÃ i khoáº£n Ä‘Ã£ bá»‹ táº¡m khÃ³a trong 1 phÃºt do nháº­p sai 3 láº§n." });
            } else {
                db.run(`UPDATE Accounts SET LoginAttempts = ? WHERE AccountID = ?`, [newAttempts, req.user.AccountID]);
                return res.status(401).json({ error: `[V2] MÃ£ OTP khÃ´ng khá»›p hoáº·c Ä‘Ã£ háº¿t háº¡n! Báº¡n cÃ²n ${3 - newAttempts} láº§n thá»­.` });
            }
        }
    });
});

// API V2: Láº¥y tráº¡ng thÃ¡i kÃ­ch hoáº¡t MFA OTP cá»§a tÃ i khoáº£n hiá»‡n táº¡i
app.get('/api/v2/auth/mfa-status', verifyTokenV2, (req, res) => {
    db.get(`SELECT MfaEnabled, MfaSecret FROM Accounts WHERE AccountID = ?`, [req.user.AccountID], (err, row) => {
        if (err || !row) return res.status(404).json({ error: "TÃ i khoáº£n khÃ´ng tá»“n táº¡i." });
        if (row.MfaEnabled && row.MfaSecret) {
            const decryptedSecret = decryptAES(row.MfaSecret);
            const currentOTP = getTOTP(decryptedSecret);
            return res.json({ mfaEnabled: true, secret: decryptedSecret, currentOTP });
        } else {
            return res.json({ mfaEnabled: false });
        }
    });
});

// API V2: Há»§y kÃ­ch hoáº¡t MFA OTP cho tÃ i khoáº£n hiá»‡n táº¡i
app.post('/api/v2/auth/mfa-disable', verifyTokenV2, (req, res) => {
    db.run(`UPDATE Accounts SET MfaSecret = NULL, MfaEnabled = 0 WHERE AccountID = ?`, [req.user.AccountID], (err) => {
        if (err) return res.status(500).json({ error: "Lá»—i CSDL khi há»§y kÃ­ch hoáº¡t MFA." });
        res.json({ message: "ÄÃ£ há»§y kÃ­ch hoáº¡t xÃ¡c thá»±c 2 lá»›p (OTP) thÃ nh cÃ´ng." });
    });
});

app.delete('/api/v2/admin/vehicles/delete', verifyTokenAndAdminV2, (req, res) => {
    const vehicleId = req.body.VehicleID;
    db.run(`DELETE FROM Vehicles WHERE VehicleID =?`, [vehicleId], (err) => {
        res.send(`[V2] ÄÃ£ xÃ³a an toÃ n.`);
    });
});

// KB3 (Báº£o máº­t Upload): Lá»c Ä‘uÃ´i tá»‡p, Ä‘á»•i tÃªn ngáº«u nhiÃªn vÃ  chá»‘ng Path Traversal
const storageV2 = multer.diskStorage({
  destination: (req, file, cb) => { cb(null, 'uploads/') },
  filename: (req, file, cb) => { 
      // Láº¥y tÃªn file gá»‘c an toÃ n, loáº¡i bá» cÃ¡c kÃ½ tá»± Ä‘iá»u hÆ°á»›ng thÆ° má»¥c
      const safeName = path.basename(file.originalname);
      const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
      
      // Äáº£m báº£o Ä‘Æ°á»ng dáº«n tuyá»‡t Ä‘á»‘i cá»§a tá»‡p Ä‘Ã­ch thá»±c sá»± náº±m bÃªn trong thÆ° má»¥c uploads
      const targetDir = path.resolve('uploads');
      const targetPath = path.resolve(targetDir, "V2_" + uniqueSuffix + path.extname(safeName));
      
      if (!targetPath.startsWith(targetDir)) {
          return cb(new Error("[V2] PhÃ¡t hiá»‡n táº¥n cÃ´ng Path Traversal!"));
      }
      
      cb(null, path.basename(targetPath));
  }
});
const uploadSecure = multer({ 
    storage: storageV2,
    limits: { fileSize: 2 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        if (extname && mimetype) return cb(null, true);
        cb(new Error("[V2] Lá»—i: Chá»‰ cho phÃ©p tá»‡p JPG/PNG."));
    }
});
app.post('/api/v2/upload-license', (req, res, next) => {
    // First check auth
    verifyTokenV2(req, res, () => {
        uploadSecure.single('license_image')(req, res, (uploadErr) => {
            if (uploadErr) return res.status(400).json({ error: uploadErr.message });
            if (!req.file) return res.status(400).json({ error: '[V2] KhÃ´ng cÃ³ tá»‡p Ä‘Æ°á»£c táº£i lÃªn.' });
            const filePath = req.file.path;
            const licenseNumber = req.body.licenseNumber || '';
            try {
                const buffer = Buffer.alloc(4);
                const fd = fs.openSync(filePath, 'r');
                fs.readSync(fd, buffer, 0, 4, 0);
                fs.closeSync(fd);
                const hex = buffer.toString('hex').toUpperCase();
                const isJpeg = hex.startsWith('FFD8FF');
                const isPng = hex.startsWith('89504E47');
                if (!isJpeg && !isPng) {
                    fs.unlinkSync(filePath);
                    return res.status(400).json({ error: '[V2] Tá»‡p táº£i lÃªn giáº£ máº¡o Ä‘á»‹nh dáº¡ng! Chá»‰ cháº¥p nháº­n JPEG/PNG thá»±c.' });
                }
                const imageURL = '/uploads/' + req.file.filename;
                // Upsert UserDocuments: update if exists, insert if not
                db.get(`SELECT DocID FROM UserDocuments WHERE AccountID = ?`, [req.user.AccountID], (err, existing) => {
                    if (existing) {
                        db.run(`UPDATE UserDocuments SET ImageURL = ?, LicenseNumber = ?, VerifiedStatus = 'verified' WHERE AccountID = ?`,
                            [imageURL, licenseNumber, req.user.AccountID]);
                    } else {
                        db.run(`INSERT INTO UserDocuments (AccountID, LicenseData, IsEncrypted, LicenseNumber, ImageURL, VerifiedStatus) VALUES (?,?,0,?,?,'verified')`,
                            [req.user.AccountID, '', licenseNumber, imageURL]);
                    }
                    res.json({ message: '[V2] Táº£i áº£nh báº±ng lÃ¡i thÃ nh cÃ´ng! Magic Bytes há»£p lá»‡. Báº±ng lÃ¡i Ä‘Ã£ Ä‘Æ°á»£c xÃ¡c nháº­n.', imageURL });
                });
            } catch (err) {
                if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
                res.status(500).json({ error: '[V2] Lá»—i kiá»ƒm duyá»‡t tá»‡p: ' + err.message });
            }
        });
    });
});

app.post('/api/v2/user/document', verifyTokenV2, (req, res) => {
    const licenseData = req.body.LicenseNumber;
    
    // MÃ£ hÃ³a dá»¯ liá»‡u báº±ng Public Key vá»›i chuáº©n padding RSA_PKCS1_OAEP_PADDING an toÃ n
    const encryptedBuffer = crypto.publicEncrypt({
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
    }, Buffer.from(licenseData));
    
    // Chuyá»ƒn sang chuá»—i Base64 Ä‘á»ƒ lÆ°u vÃ o CSDL
    const ciphertext = encryptedBuffer.toString('base64');

    db.run(`INSERT INTO UserDocuments (AccountID, LicenseData, IsEncrypted) VALUES (?,?,?)`, [req.user.AccountID, ciphertext, true], (err) => {
        res.send("[V2] ÄÃ£ mÃ£ hÃ³a RSA vÃ  lÆ°u dá»¯ liá»‡u PII thÃ nh cÃ´ng.");
    });
});

// (TÃ¹y chá»n) API giáº£i mÃ£ chá»‰ dÃ nh cho Admin ná»™i bá»™ há»‡ thá»‘ng Ä‘á»ƒ xem dá»¯ liá»‡u tháº­t
app.post('/api/v2/admin/decrypt-document', verifyTokenAndAdminV2, (req, res) => {
    const encryptedData = req.body.Ciphertext;
    try {
        const decryptedBuffer = crypto.privateDecrypt({
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        }, Buffer.from(encryptedData, 'base64'));
        
        res.json({ DecryptedData: decryptedBuffer.toString() });
    } catch (e) {
        res.status(500).json({ error: "Giáº£i mÃ£ tháº¥t báº¡i hoáº·c dá»¯ liá»‡u bá»‹ giáº£ máº¡o!" });
    }
});

// API láº¥y thÃ´ng tin giáº£i trÃ­ trÃªn xe (Chá»‰ xe mÃ¬nh Ä‘ang thuÃª vÃ  Ä‘Ã£ giáº£i mÃ£ AES) - BOLA & AES Decryption Check
app.get('/api/v2/vehicles/infotainment', verifyTokenV2, (req, res) => {
    db.get(`SELECT VehicleID FROM Rentals WHERE AccountID = ? AND Status = 'Active' LIMIT 1`, [req.user.AccountID], (err, rental) => {
        if (err || !rental) {
            return res.status(404).json({ error: "[V2] Báº¡n hiá»‡n khÃ´ng cÃ³ há»£p Ä‘á»“ng thuÃª xe nÃ o Ä‘ang hoáº¡t Ä‘á»™ng!" });
        }
        
        const vehicleId = rental.VehicleID;
        db.get(`SELECT * FROM VehicleInfotainment WHERE VehicleID = ?`, [vehicleId], (err, row) => {
            if (err) return res.status(500).json({ error: "Lá»—i DB." });
            if (!row) {
                return res.json({ 
                    VehicleID: vehicleId, 
                    SyncedContacts: "KhÃ´ng cÃ³ dá»¯ liá»‡u (ÄÃ£ bá»‹ VIPR xÃ³a sáº¡ch khá»i xe)", 
                    GPSHistory: "KhÃ´ng cÃ³ dá»¯ liá»‡u (ÄÃ£ bá»‹ VIPR xÃ³a sáº¡ch khá»i xe)", 
                    ActiveBluetoothDevice: "KhÃ´ng cÃ³ káº¿t ná»‘i" 
                });
            }
            
            res.json({
                VehicleID: row.VehicleID,
                SyncedContacts: decryptAES(row.SyncedContacts),
                GPSHistory: decryptAES(row.GPSHistory),
                ActiveBluetoothDevice: row.ActiveBluetoothDevice
            });
        });
    });
});

// HÃ m tiá»‡n Ã­ch lá»c kÃ½ tá»± Ä‘áº·c biá»‡t (HTML Entity Encoding) Ä‘á»ƒ phÃ²ng chá»‘ng XSS
function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') return unsafe;
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

// KB5 (Báº£o máº­t XSS): Nháº­n thÃ´ng tin xe vÃ  lÆ°u trá»¯ an toÃ n
app.post('/api/v2/vehicles/add', (req, res) => {
    const { vehicleName, vehicalorcview } = req.body;
    if (!vehicleName || !vehicalorcview) {
        return res.status(400).send("Thiáº¿u thÃ´ng tin xe.");
    }
    db.run(`INSERT INTO Vehicles (Model, Status) VALUES (?, ?)`, [vehicleName, vehicalorcview], function(err) {
        if (err) return res.status(500).send("Lá»—i DB");
        res.status(200).send("[V2] ThÃªm xe thÃ nh cÃ´ng!");
    });
});

// KB5 (Báº£o máº­t XSS): Tráº£ vá» HTML Ä‘Ã£ qua lÃ m sáº¡ch dá»¯ liá»‡u Ä‘áº§u ra (Output Escaping)
app.get('/api/v2/admin/view-vehicle', (req, res) => {
    db.get(`SELECT * FROM Vehicles ORDER BY VehicleID DESC LIMIT 1`, (err, row) => {
        if (!row) return res.send("ChÆ°a cÃ³ xe nÃ o.");
        
        // Thá»±c hiá»‡n escape dá»¯ liá»‡u trÆ°á»›c khi render HTML
        const safeModel = escapeHtml(row.Model);
        const safeStatus = escapeHtml(row.Status);
        
        const html = `
            <!DOCTYPE html>
            <html>
            <head><title>Quáº£n trá»‹ Xe [V2]</title><meta charset="utf-8"></head>
            <body>
                <h2>Chi tiáº¿t xe: ${safeModel}</h2>
                <p><strong>ÄÃ¡nh giÃ¡/Ghi chÃº (ÄÆ°á»£c báº£o vá»‡):</strong> ${safeStatus}</p> 
            </body>
            </html>
        `;
        res.send(html);
    });
});

// =========================================================
// NEW API: Real car rental features
// =========================================================

// GET all categories
app.get('/api/v2/categories', (req, res) => {
    db.all(`SELECT * FROM VehicleCategories`, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

// GET vehicles with smart filtering (date availability + type/price/transmission/fuel)
app.get('/api/v2/vehicles/search', (req, res) => {
    const { startDate, endDate, transmission, fuel, maxPrice, categoryId } = req.query;
    let query = `SELECT v.*,
        c.Name as CategoryName,
        COALESCE((SELECT ROUND(AVG(r.Rating),1) FROM Reviews r WHERE r.VehicleID = v.VehicleID), 0) as AvgRating,
        COALESCE((SELECT COUNT(r.ReviewID) FROM Reviews r WHERE r.VehicleID = v.VehicleID), 0) as ReviewCount
        FROM Vehicles v
        LEFT JOIN VehicleCategories c ON v.CategoryID = c.CategoryID
        WHERE 1=1`;
    const params = [];
    if (transmission && transmission !== 'all') { query += ` AND v.Transmission = ?`; params.push(transmission); }
    if (fuel && fuel !== 'all')         { query += ` AND v.FuelType = ?`; params.push(fuel); }
    if (maxPrice)                       { query += ` AND v.PricePerDay <= ?`; params.push(parseInt(maxPrice)); }
    if (categoryId && categoryId !== '0') { query += ` AND v.CategoryID = ?`; params.push(parseInt(categoryId)); }
    if (startDate && endDate) {
        query += ` AND v.VehicleID NOT IN (
            SELECT VehicleID FROM Rentals
            WHERE Status = 'Active' AND StartDate IS NOT NULL AND EndDate IS NOT NULL
            AND StartDate <= ? AND EndDate >= ?
        )`;
        params.push(endDate, startDate);
    }
    db.all(query, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

// GET vehicle detail with reviews
app.get('/api/v2/vehicles/:id', (req, res, next) => {
    const vid = parseInt(req.params.id);
    if (isNaN(vid)) return next();
    db.get(`SELECT v.*, c.Name as CategoryName FROM Vehicles v
        LEFT JOIN VehicleCategories c ON v.CategoryID = c.CategoryID
        WHERE v.VehicleID = ?`, [vid], (err, vehicle) => {
        if (err || !vehicle) return res.status(404).json({ error: 'Xe khong ton tai.' });
        db.all(`SELECT r.*, a.FullName, a.Username FROM Reviews r
            LEFT JOIN Accounts a ON r.AccountID = a.AccountID
            WHERE r.VehicleID = ? ORDER BY r.Timestamp DESC LIMIT 10`, [vid], (err2, reviews) => {
            res.json({ ...vehicle, reviews: reviews || [] });
        });
    });
});

// POST submit review (must have rented this vehicle)
app.post('/api/v2/reviews', verifyTokenV2, (req, res) => {
    const { vehicleId, rating, comment } = req.body;
    if (!vehicleId || !rating || rating < 1 || rating > 5)
        return res.status(400).json({ error: 'Thieu thong tin hoac rating khong hop le (1-5).' });
        db.get(`SELECT r.RentalID FROM Rentals r
        WHERE r.AccountID = ? AND r.VehicleID = ? AND r.Status = 'Completed'
        ORDER BY r.RentalID DESC LIMIT 1`,
        [req.user.AccountID, vehicleId], (err, rental) => {
        if (!rental) return res.status(403).json({ error: 'Chi co the danh gia xe sau khi hoan tat chuyen thue.' });
        db.get(`SELECT ReviewID FROM Reviews WHERE RentalID = ?`, [rental.RentalID], (reviewErr, existingReview) => {
            if (existingReview) return res.status(409).json({ error: 'Ban da danh gia chuyen thue nay roi.' });
            db.run(`INSERT INTO Reviews (AccountID, VehicleID, RentalID, Rating, Comment) VALUES (?,?,?,?,?)`,
                [req.user.AccountID, vehicleId, rental.RentalID, rating, comment || ''], (err2) => {
                if (err2) return res.status(500).json({ error: err2.message });
                res.json({ message: 'Da gui danh gia thanh cong! Cam on ban.' });
            });
        });
    });
});

// GET my rental history
app.get('/api/v2/rentals/my', verifyTokenV2, (req, res) => {
    db.all(`SELECT r.*, v.Model, v.LicensePlate, v.ImageURL, v.PricePerDay, v.Seats, v.Transmission
        FROM Rentals r LEFT JOIN Vehicles v ON r.VehicleID = v.VehicleID
        WHERE r.AccountID = ? ORDER BY r.RentalID DESC`, [req.user.AccountID], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

// GET current user profile
app.get('/api/v2/profile', verifyTokenV2, (req, res) => {
    db.get(`SELECT AccountID, Username, Role, FullName, Phone, Email, MfaEnabled
        FROM Accounts WHERE AccountID = ?`, [req.user.AccountID], (err, row) => {
        if (err || !row) return res.status(404).json({ error: 'Khong tim thay tai khoan.' });
        db.get(`SELECT DocID, LicenseNumber, ImageURL, VerifiedStatus FROM UserDocuments WHERE AccountID = ? ORDER BY DocID DESC LIMIT 1`, [req.user.AccountID], (err2, doc) => {
            res.json({ ...row, license: doc || null });
        });
    });
});

// GET current user's documents
app.get('/api/v2/user/documents', verifyTokenV2, (req, res) => {
    db.all(`SELECT DocID, AccountID, LicenseData, IsEncrypted, LicenseNumber, ImageURL, VerifiedStatus, Timestamp
        FROM UserDocuments
        WHERE AccountID = ?
        ORDER BY DocID DESC`, [req.user.AccountID], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

// PUT update user profile
app.put('/api/v2/profile', verifyTokenV2, (req, res) => {
    const { fullName, phone, email } = req.body;
    db.run(`UPDATE Accounts SET FullName=?, Phone=?, Email=? WHERE AccountID=?`,
        [fullName || '', phone || '', email || '', req.user.AccountID], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Cap nhat ho so thanh cong!' });
    });
});

const pendingRoutes = {}; // LÆ°u routeType mÃ  khÃ¡ch hÃ ng chá»n khi Ä‘áº·t xe

// POST rent with date range (enhanced version)
app.post('/api/v2/rentals/rent-dated', verifyTokenV2, (req, res) => {
    const { vehicleId, startDate, endDate, pickupLocation, returnLocation, routeType } = req.body;
    const gatekeeperHeader = req.headers['x-rentalshield-gatekeeper'];
    if (gatekeeperHeader !== 'client-v2-active')
        return res.status(403).json({ error: '[V2] Tu choi: Header khong hop le!' });
    if (!vehicleId || !startDate || !endDate)
        return res.status(400).json({ error: 'Thieu vehicleId, startDate hoac endDate.' });
    const start = new Date(startDate);
    const end   = new Date(endDate);
    if (isNaN(start) || isNaN(end) || end <= start)
        return res.status(400).json({ error: 'Ngay tra xe phai sau ngay nhan xe.' });
    const days = Math.max(1, Math.ceil((end - start) / (1000 * 60 * 60 * 24)));
    // Kiá»ƒm tra báº±ng lÃ¡i xe trÆ°á»›c khi Ä‘áº·t xe
    db.get(`SELECT DocID FROM UserDocuments WHERE AccountID = ? AND VerifiedStatus = 'verified'`, [req.user.AccountID], (licErr, licRow) => {
        if (!licRow) return res.status(403).json({ error: 'Báº¡n chÆ°a cÃ³ báº±ng lÃ¡i xe há»£p lá»‡. Vui lÃ²ng táº£i áº£nh báº±ng lÃ¡i trong má»¥c Há»“ sÆ¡ trÆ°á»›c khi Ä‘áº·t xe.' });
    db.get(`SELECT * FROM Vehicles WHERE VehicleID = ?`, [vehicleId], (err, vehicle) => {
        if (err || !vehicle) return res.status(404).json({ error: 'Xe khong ton tai.' });
        if (vehicle.Status !== 'Available') return res.status(400).json({ error: 'Xe hien khong trong.' });
        db.get(`SELECT RentalID FROM Rentals WHERE VehicleID = ? AND Status = 'Active' AND StartDate <= ? AND EndDate >= ?`,
            [vehicleId, endDate, startDate], (err2, conflict) => {
            if (conflict) return res.status(400).json({ error: 'Xe da duoc dat trong khoang thoi gian nay.' });
            const totalAmount = days * (vehicle.PricePerDay || 500000);
            const loc = pickupLocation || 'Ha Noi';
            const rType = routeType || 'hanoi';
            db.run(`INSERT INTO Rentals (VehicleID, AccountID, Status, StartDate, EndDate, PickupLocation, ReturnLocation, TotalAmount, RouteType)
                VALUES (?,?,'Active',?,?,?,?,?,?)`,
                [vehicleId, req.user.AccountID, startDate, endDate, loc, returnLocation || loc, totalAmount, rType],
                function(err3) {
                if (err3) return res.status(500).json({ error: 'Loi tao hop dong.' });
                const rentalId = this.lastID;
                
                // Optimistic Concurrency Control check
                db.run(`UPDATE Vehicles SET Status = 'Rented', Version = Version + 1 WHERE VehicleID = ? AND Version = ?`,
                    [vehicleId, vehicle.Version],
                    function(err4) {
                        if (err4 || this.changes === 0) {
                            // OCC check failed: race condition!
                            db.run(`DELETE FROM Rentals WHERE RentalID = ?`, [rentalId]);
                            return res.status(409).json({ error: '[CONCURRENCY] Lá»—i tranh cháº¥p Ä‘á»“ng thá»i: Tráº¡ng thÃ¡i xe Ä‘Ã£ thay Ä‘á»•i bá»Ÿi ngÆ°á»i dÃ¹ng khÃ¡c cÃ¹ng lÃºc! Vui lÃ²ng thá»­ láº¡i.' });
                        }
                        
                        const username = req.user.Username || 'user';
                        const cPlain = `Danh ba ${username}: Me (090${Math.floor(1e6+Math.random()*9e6)}), Ban be (098${Math.floor(1e6+Math.random()*9e6)})`;
                        const gPlain = `GPS Log: Nha (103.${Math.floor(10+Math.random()*90)}, 21.${Math.floor(10+Math.random()*90)})`;
                        
                        db.get(`SELECT DeviceModel FROM Accounts WHERE AccountID = ?`, [req.user.AccountID], (err, userRow) => {
                            const deviceModel = userRow?.DeviceModel || 'Thiáº¿t bá»‹ khÃ´ng xÃ¡c Ä‘á»‹nh';
                            db.run(`INSERT OR REPLACE INTO VehicleInfotainment (VehicleID, SyncedContacts, GPSHistory, ActiveBluetoothDevice) VALUES (?,?,?,?)`,
                                [vehicleId, encryptAES(cPlain), encryptAES(gPlain), deviceModel], (err5) => {
                                
                                initGpsSession(vehicleId, req.user.AccountID, routeType || 'hanoi');
                                
                                res.json({
                                    message: `ÄÃ£ Ä‘áº·t xe thÃ nh cÃ´ng! Há»£p Ä‘á»“ng Ä‘Ã£ tá»± Ä‘á»™ng kÃ­ch hoáº¡t.`,
                                    rentalId, vehicleId, totalAmount,
                                    days, pricePerDay: vehicle.PricePerDay
                                });
                            });
                        });
                    }
                );
            });
        });
    });
    }); // close license check
});

// =========================================================
// MISSING ROUTES â€” gá»i tá»« client.html
// =========================================================

// GET all vehicles (public) â€” hiá»ƒn thá»‹ danh sÃ¡ch xe trÃªn trang chá»§
app.get('/api/v2/vehicles', (req, res) => {
    db.all(`SELECT v.*,
        c.Name as CategoryName,
        ROUND(COALESCE(AVG(r.Rating), 0), 1) as AvgRating,
        COUNT(r.ReviewID) as ReviewCount
        FROM Vehicles v
        LEFT JOIN VehicleCategories c ON v.CategoryID = c.CategoryID
        LEFT JOIN Reviews r ON r.VehicleID = v.VehicleID
        GROUP BY v.VehicleID
        ORDER BY v.VehicleID ASC`, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

// GET my current active rental â€” kiá»ƒm tra tráº¡ng thÃ¡i thuÃª xe hiá»‡n táº¡i
app.get('/api/v2/vehicles/my-rental', verifyTokenV2, (req, res) => {
    db.get(`SELECT r.*, v.Model, v.LicensePlate, v.ImageURL, v.PricePerDay
        FROM Rentals r
        LEFT JOIN Vehicles v ON r.VehicleID = v.VehicleID
        WHERE r.AccountID = ? AND r.Status = 'Active'
        ORDER BY r.RentalID DESC LIMIT 1`, [req.user.AccountID], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.json({});
        res.json(row);
    });
});

// POST rent vehicle (alias path gá»i tá»« client) â€” khÃ´ng yÃªu cáº§u gatekeeper header
app.post('/api/v2/vehicles/rent-dated', verifyTokenV2, (req, res) => {
    const { vehicleId, startDate, endDate, simulationType } = req.body;
    const routeType = simulationType || 'hanoi';
    if (!vehicleId || !startDate || !endDate)
        return res.status(400).json({ error: 'Thiáº¿u vehicleId, startDate hoáº·c endDate.' });
    const start = new Date(startDate);
    const end   = new Date(endDate);
    if (isNaN(start) || isNaN(end) || end <= start)
        return res.status(400).json({ error: 'NgÃ y tráº£ xe pháº£i sau ngÃ y nháº­n xe.' });
    const days = Math.max(1, Math.ceil((end - start) / (1000 * 60 * 60 * 24)));
    // Kiá»ƒm tra báº±ng lÃ¡i xe
    db.get(`SELECT DocID FROM UserDocuments WHERE AccountID = ? AND VerifiedStatus = 'verified'`, [req.user.AccountID], (licErr, licRow) => {
        if (!licRow) return res.status(403).json({ error: 'Báº¡n cáº§n táº£i lÃªn báº±ng lÃ¡i xe há»£p lá»‡ trÆ°á»›c khi thuÃª xe!' });
        // Kiá»ƒm tra xe tá»“n táº¡i vÃ  tráº¡ng thÃ¡i
        db.get(`SELECT * FROM Vehicles WHERE VehicleID = ?`, [vehicleId], (err, vehicle) => {
            if (err || !vehicle) return res.status(404).json({ error: 'Xe khÃ´ng tá»“n táº¡i.' });
            if (vehicle.Status !== 'Available') return res.status(409).json({ error: 'Xe nÃ y Ä‘Ã£ Ä‘Æ°á»£c thuÃª hoáº·c khÃ´ng kháº£ dá»¥ng.' });
            // Kiá»ƒm tra user khÃ´ng cÃ³ há»£p Ä‘á»“ng Active nÃ o khÃ¡c
            db.get(`SELECT RentalID FROM Rentals WHERE AccountID = ? AND Status = 'Active' LIMIT 1`, [req.user.AccountID], (err2, existing) => {
                if (existing) return res.status(409).json({ error: 'Báº¡n Ä‘ang cÃ³ má»™t há»£p Ä‘á»“ng thuÃª xe Ä‘ang hoáº¡t Ä‘á»™ng. Vui lÃ²ng tráº£ xe cÅ© trÆ°á»›c.' });
                const totalAmount = days * (vehicle.PricePerDay || 800000);
                db.run(`INSERT INTO Rentals (VehicleID, AccountID, Status, StartDate, EndDate, TotalAmount, RouteType)
                    VALUES (?,?,?,?,?,?,?)`,
                    [vehicleId, req.user.AccountID, 'Active', startDate, endDate, totalAmount, routeType],
                    function(err3) {
                        if (err3) return res.status(500).json({ error: err3.message });
                        const rentalId = this.lastID;
                        db.run(`UPDATE Vehicles SET Status = 'Rented', Version = Version + 1 WHERE VehicleID = ?`, [vehicleId]);
                        const username = req.user.Username || 'user';
                        const cPlain = `Danh ba ${username}: Me (090${Math.floor(1e6+Math.random()*9e6)}), Ban (098${Math.floor(1e6+Math.random()*9e6)})`;
                        const gPlain = `GPS Log: Khoi hanh tu Ha Noi`;
                        db.get(`SELECT DeviceModel FROM Accounts WHERE AccountID = ?`, [req.user.AccountID], (err4, userRow) => {
                            const deviceModel = userRow?.DeviceModel || 'Thiet bi khach hang';
                            db.run(`INSERT OR REPLACE INTO VehicleInfotainment (VehicleID, SyncedContacts, GPSHistory, ActiveBluetoothDevice) VALUES (?,?,?,?)`,
                                [vehicleId, encryptAES(cPlain), encryptAES(gPlain), deviceModel]);
                            initGpsSession(vehicleId, req.user.AccountID, routeType);
                            res.json({ message: `Äáº·t xe thÃ nh cÃ´ng!`, rentalId, vehicleId, totalAmount, days });
                        });
                    }
                );
            });
        });
    });
});

// POST return vehicle â€” tráº£ xe
app.post('/api/v2/vehicles/return', verifyTokenV2, (req, res) => {
    const { rentalId } = req.body;
    db.get(`SELECT * FROM Rentals WHERE RentalID = ? AND AccountID = ? AND Status = 'Active'`,
        [rentalId, req.user.AccountID], (err, rental) => {
        if (err || !rental) return res.status(404).json({ error: 'KhÃ´ng tÃ¬m tháº¥y há»£p Ä‘á»“ng thuÃª xe.' });
        db.run(`UPDATE Rentals SET Status = 'Completed' WHERE RentalID = ?`, [rentalId], (err2) => {
            if (err2) return res.status(500).json({ error: err2.message });
            db.run(`UPDATE Vehicles SET Status = 'Available' WHERE VehicleID = ?`, [rental.VehicleID]);
            // Dá»«ng GPS session
            const st = gpsState[rental.VehicleID];
            if (st && st.intervalId) { clearInterval(st.intervalId); delete gpsState[rental.VehicleID]; }
            res.json({ message: 'Tráº£ xe thÃ nh cÃ´ng! Cáº£m Æ¡n báº¡n Ä‘Ã£ sá»­ dá»¥ng VNCars.' });
        });
    });
});

// POST confirm rental (vehicle owner approval)
app.post('/api/v2/rentals/confirm', verifyTokenAndAdminV2, (req, res) => {
    const { rentalId } = req.body;
    if (!rentalId) return res.status(400).json({ error: 'Thieu rentalId.' });
    
    db.get(`SELECT * FROM Rentals WHERE RentalID = ?`, [rentalId], (err, rental) => {
        if (err || !rental) return res.status(404).json({ error: 'Hop dong khong ton tai.' });
        if (rental.Status !== 'Pending') return res.status(400).json({ error: 'Hop dong khong o trang thai cho duyet.' });
        
        const vehicleId = rental.VehicleID;
        const accountId = rental.AccountID;
        
        db.run(`UPDATE Rentals SET Status = 'Active' WHERE RentalID = ?`, [rentalId], (err2) => {
            if (err2) return res.status(500).json({ error: 'Loi cap nhat trang thai hop dong.' });
            
            db.run(`UPDATE Vehicles SET Status = 'Rented' WHERE VehicleID = ?`, [vehicleId], (err3) => {
                if (err3) return res.status(500).json({ error: 'Loi cap nhat trang thai xe.' });
                
                db.get(`SELECT Username FROM Accounts WHERE AccountID = ?`, [accountId], (err4, user) => {
                    const username = user ? user.Username : 'user';
                    const cPlain = `Danh ba ${username}: Me (090${Math.floor(1e6+Math.random()*9e6)}), Ban be (098${Math.floor(1e6+Math.random()*9e6)})`;
                    const gPlain = `GPS Log: Nha (103.${Math.floor(10+Math.random()*90)}, 21.${Math.floor(10+Math.random()*90)})`;
                    
                    db.run(`INSERT OR REPLACE INTO VehicleInfotainment (VehicleID, SyncedContacts, GPSHistory, ActiveBluetoothDevice) VALUES (?,?,?,?)`,
                        [vehicleId, encryptAES(cPlain), encryptAES(gPlain), `Thiet bi cua ${username}`], (err5) => {
                        
                        const requestedRoute = pendingRoutes[vehicleId] || 'hanoi';
                        initGpsSession(vehicleId, accountId, requestedRoute);
                        delete pendingRoutes[vehicleId];
                        
                        res.json({ message: `Da xac nhan thue xe #${vehicleId} cho hop dong #${rentalId} thanh cong! Khoi chay thiet bi dinh vi.` });
                    });
                });
            });
        });
    });
});

app.listen(3000, () => {
    console.log('Dummy Web 4 Ká»‹ch Báº£n Sáºµn SÃ ng Táº¡i: http://localhost:3000');
});
// =========================================================
// Ká»ŠCH Báº¢N 5: CROSS-SITE SCRIPTING (XSS)
// =========================================================

// API 1: DÃ nh cho Hacker gá»­i mÃ£ Ä‘á»™c (Postman dÃ¹ng API nÃ y)
app.post('/api/v1/vehicles/add', (req, res) => {
    const { vehicleName, vehicalorcview } = req.body;
    
    // LÆ°u tháº³ng vÃ o Database mÃ  khÃ´ng há» lÃ m sáº¡ch (Sanitize)
    db.run(`INSERT INTO Vehicles (Model, Status) VALUES (?, ?)`, [vehicleName, vehicalorcview], function(err) {
        if (err) return res.status(500).send("Lá»—i DB");
        res.status(200).send("ThÃªm xe thÃ nh cÃ´ng!");
    });
});

// API 2: DÃ nh cho Admin xem thÃ´ng tin (Má»Ÿ báº±ng TrÃ¬nh duyá»‡t Chrome/Edge)
app.get('/api/v1/admin/view-vehicle', (req, res) => {
    // Láº¥y chiáº¿c xe má»›i nháº¥t vá»«a thÃªm vÃ o
    db.get(`SELECT * FROM Vehicles ORDER BY VehicleID DESC LIMIT 1`, (err, row) => {
        if (!row) return res.send("ChÆ°a cÃ³ xe nÃ o.");
        
        // Tráº£ vá» HTML thÃ´ cho trÃ¬nh duyá»‡t. Biáº¿n row.Status Ä‘ang chá»©a mÃ£ Ä‘á»™c!
        const html = `
            <!DOCTYPE html>
            <html>
            <head><title>Quáº£n trá»‹ Xe</title><meta charset="utf-8"></head>
            <body>
                <h2>Chi tiáº¿t xe: ${row.Model}</h2>
                <p><strong>ÄÃ¡nh giÃ¡/Ghi chÃº:</strong> ${row.Status}</p> 
            </body>
            </html>
        `;
        res.send(html);
    });
});

// =========================================================
// Ká»ŠCH Báº¢N VIPR: VEHICLE INACTIVE PROFILE REMOVER (Lá»šP 4)
// =========================================================

// API V1: Káº¿t thÃºc há»£p Ä‘á»“ng nhÆ°ng KHÃ”NG xÃ³a thÃ´ng tin nháº¡y cáº£m trÃªn xe
app.post('/api/v1/rentals/terminate', (req, res) => {
    const { rentalId } = req.body;
    db.get(`SELECT VehicleID FROM Rentals WHERE RentalID = ?`, [rentalId], (err, row) => {
        if (err || !row) return res.status(404).send("[V1] Há»£p Ä‘á»“ng khÃ´ng tá»“n táº¡i.");
        const vehicleId = row.VehicleID;
        db.run(`UPDATE Rentals SET Status = 'Terminated' WHERE RentalID = ?`, [rentalId], function(err) {
            if (err) return res.status(500).send("Lá»—i DB");
            db.run(`UPDATE Vehicles SET Status = 'Available' WHERE VehicleID = ?`, [vehicleId], (err) => {
                res.send("[V1] ÄÃ£ káº¿t thÃºc há»£p Ä‘á»“ng thuÃª xe. Cáº£nh bÃ¡o: Lá»‹ch sá»­ GPS vÃ  Danh báº¡ váº«n lÆ°u trong há»‡ thá»‘ng giáº£i trÃ­ cá»§a xe!");
            });
        });
    });
});

// API V2: Káº¿t thÃºc há»£p Ä‘á»“ng vÃ  tá»± Ä‘á»™ng kÃ­ch hoáº¡t VIPR xÃ³a dá»¯ liá»‡u nháº¡y cáº£m trÃªn xe
app.post('/api/v2/rentals/terminate', verifyTokenV2, (req, res) => {
    const { rentalId } = req.body;
    
    db.get(`SELECT VehicleID FROM Rentals WHERE RentalID = ?`, [rentalId], (err, row) => {
        if (err || !row) return res.status(404).send("[V2] Há»£p Ä‘á»“ng khÃ´ng tá»“n táº¡i.");
        
        const vehicleId = row.VehicleID;
        
        db.run(`UPDATE Rentals SET Status = 'Terminated' WHERE RentalID = ?`, [rentalId], function(err) {
            if (err) return res.status(500).send("Lá»—i DB");
            
            // Cáº­p nháº­t tráº¡ng thÃ¡i xe vá» Available
            db.run(`UPDATE Vehicles SET Status = 'Available' WHERE VehicleID = ?`, [vehicleId], (err) => {
                if (err) return res.status(500).send("Lá»—i DB khi khÃ´i phá»¥c tráº¡ng thÃ¡i xe.");
                
                // KÃ­ch hoáº¡t giao thá»©c VIPR (xÃ³a dá»¯ liá»‡u xe káº¿t ná»‘i tá»« xa)
                db.run(`UPDATE VehicleInfotainment SET GPSHistory = '[]', SyncedContacts = '[]', ActiveBluetoothDevice = 'Ngáº¯t káº¿t ná»‘i (Offline)' WHERE VehicleID = ?`, [vehicleId], function(err) {
                    if (err) return res.status(500).send("Lá»—i thá»±c thi VIPR");
                    // V3: Káº¿t thÃºc phiÃªn GPS & Zeroize DEK
                    terminateGpsSession(vehicleId);
                    res.send("[V2] ÄÃ£ káº¿t thÃºc há»£p Ä‘á»“ng thuÃª xe. Lá»‡nh VIPR Ä‘Ã£ truyá»n thÃ nh cÃ´ng â€” xÃ³a toÃ n bá»™ GPS/Danh báº¡ khá»i xe. DEK phiÃªn GPS Ä‘Ã£ Zeroize!");
                });
            });
        });
    });
});

// API V2: ThuÃª xe an toÃ n - CÃ³ báº£o vá»‡ chá»‘ng CSRF (SameSite + Gatekeeper Header), DDoS/Spam vÃ  BOLA Check
app.post('/api/v2/rentals/rent', verifyTokenV2, (req, res) => {
    const { vehicleId } = req.body;
    
    // Kiá»ƒm tra Custom Header chá»‘ng bÃªn thá»© 3 phÃ¡t Ä‘á»™ng request (CSRF/Spam Protection)
    const gatekeeperHeader = req.headers['x-rentalshield-gatekeeper'];
    if (gatekeeperHeader !== 'client-v2-active') {
        return res.status(403).json({ error: "[V2] Tá»« chá»‘i truy cáº­p: YÃªu cáº§u khÃ´ng há»£p lá»‡ tá»« nguá»“n chÆ°a xÃ¡c thá»±c!" });
    }

    if (!vehicleId) {
        return res.status(400).json({ error: "Thiáº¿u thÃ´ng tin VehicleID." });
    }

    // Kiá»ƒm tra xem xe cÃ³ Ä‘ang sáºµn sÃ ng (Available) khÃ´ng
    db.get(`SELECT * FROM Vehicles WHERE VehicleID = ?`, [vehicleId], (err, vehicle) => {
        if (err || !vehicle) {
            return res.status(404).json({ error: "PhÆ°Æ¡ng tiá»‡n khÃ´ng tá»“n táº¡i." });
        }
        if (vehicle.Status !== 'Available') {
            return res.status(400).json({ error: "PhÆ°Æ¡ng tiá»‡n nÃ y hiá»‡n Ä‘ang Ä‘Æ°á»£c thuÃª hoáº·c khÃ´ng kháº£ dá»¥ng." });
        }

        // Láº¥y routeType (náº¿u cÃ³ tá»« request)
        const routeType = req.body.routeType || 'hanoi';

        // Tiáº¿n hÃ nh táº¡o há»£p Ä‘á»“ng thuÃª xe má»›i
        db.run(`INSERT INTO Rentals (VehicleID, AccountID, Status, RouteType) VALUES (?, ?, 'Active', ?)`, [vehicleId, req.user.AccountID, routeType], function(err) {
            if (err) return res.status(500).json({ error: "Lá»—i táº¡o há»£p Ä‘á»“ng thuÃª xe." });
            const rentalId = this.lastID;

            // Cáº­p nháº­t tráº¡ng thÃ¡i xe sang 'Rented'
            db.run(`UPDATE Vehicles SET Status = 'Rented' WHERE VehicleID = ?`, [vehicleId], (err) => {
                if (err) return res.status(500).json({ error: "Lá»—i cáº­p nháº­t tráº¡ng thÃ¡i xe." });

                // Äá»“ng bá»™/Táº¡o dá»¯ liá»‡u giáº£i trÃ­ giáº£ láº­p má»›i cho ngÆ°á»i dÃ¹ng trÃªn xe (ÄÆ°á»£c mÃ£ hÃ³a AES-256-GCM)
                const username = req.user.Username;
                const contactsPlain = `Danh báº¡ ${username}: Máº¹ (090${Math.floor(1000000+Math.random()*9000000)}), Báº¡n bÃ¨ (098${Math.floor(1000000+Math.random()*9000000)})`;
                const gpsPlain = `Nháº­t kÃ½ GPS: NhÃ  riÃªng (103.${Math.floor(10+Math.random()*90)}, 21.${Math.floor(10+Math.random()*90)}), Äiá»ƒm du lá»‹ch (105.${Math.floor(10+Math.random()*90)}, 20.${Math.floor(10+Math.random()*90)})`;
                
                const encryptedContacts = encryptAES(contactsPlain);
                const encryptedGps = encryptAES(gpsPlain);

                db.get(`SELECT DeviceModel FROM Accounts WHERE AccountID = ?`, [req.user.AccountID], (err, userRow) => {
                    const bluetoothDevice = userRow?.DeviceModel || 'Thiáº¿t bá»‹ khÃ´ng xÃ¡c Ä‘á»‹nh';

                    // Ghi hoáº·c cáº­p nháº­t thÃ´ng tin giáº£i trÃ­ cá»§a xe
                    db.run(`INSERT OR REPLACE INTO VehicleInfotainment (VehicleID, SyncedContacts, GPSHistory, ActiveBluetoothDevice) VALUES (?, ?, ?, ?)`,
                        [vehicleId, encryptedContacts, encryptedGps, bluetoothDevice], (err) => {
                            if (err) return res.status(500).json({ error: "Lá»—i Ä‘á»“ng bá»™ thÃ´ng tin giáº£i trÃ­ trÃªn xe." });
                        // V3: Khá»Ÿi Ä‘á»™ng phiÃªn GPS báº£o máº­t (Envelope Encryption)
                        initGpsSession(vehicleId, req.user.AccountID, routeType);
                        res.json({
                            message: "ThuÃª xe thÃ nh cÃ´ng! Giao dá»‹ch Ä‘Æ°á»£c thá»±c hiá»‡n an toÃ n qua cá»•ng RentalShield.",
                            rentalId: rentalId,
                            vehicleId: vehicleId
                        });
                    }
                );
                }); // ÄÃ³ng db.get
            });
        });
    });
});

// =========================================================
// Ká»ŠCH Báº¢N CHá»® KÃ Lá»†NH VIá»„N THÃ”NG (HMAC TELEMATICS) (Lá»šP 4)
// =========================================================

// V1: Nháº­n lá»‡nh thÃ´ qua HTTP, khÃ´ng cÃ³ xÃ¡c thá»±c chá»¯ kÃ½ (Lá»— há»•ng Replay/Spoofing)
app.post('/api/v1/telematics/command', (req, res) => {
    const { vehicleId, command } = req.body;
    if (command === 'WIPE') {
        db.run(`DELETE FROM VehicleInfotainment WHERE VehicleID = ?`, [vehicleId], function(err) {
            res.send(`[V1] Xe ID ${vehicleId} Ä‘Ã£ nháº­n lá»‡nh WIPE thÃ´ vÃ  xÃ³a dá»¯ liá»‡u!`);
        });
    } else {
        res.send(`[V1] Lá»‡nh khÃ´ng xÃ¡c Ä‘á»‹nh.`);
    }
});

// V2: Nháº­n lá»‡nh qua viá»…n thÃ´ng báº¯t buá»™c cÃ³ chá»¯ kÃ½ HMAC-SHA256 Ä‘á»ƒ xÃ¡c thá»±c nguá»“n gá»‘c
app.post('/api/v2/telematics/command', verifyTokenV2, (req, res) => {
    const { vehicleId, command, signature, timestamp, userLat, userLon } = req.body;
    
    // TÃ­nh toÃ¡n láº¡i chá»¯ kÃ½ HMAC
    // Há»— trá»£ cáº£ 2 Ä‘á»‹nh dáº¡ng:
    // 1. command + vehicleId (cho admin)
    // 2. vehicleId + ":" + command + ":" + timestamp (cho client - cÃ³ chá»‘ng replay)
    const expectedSignatureAdmin = crypto.createHmac('sha256', TELEMATICS_SECRET)
                                    .update(command + vehicleId)
                                    .digest('hex');
                                    
    let expectedSignatureClient = '';
    if (timestamp) {
        expectedSignatureClient = crypto.createHmac('sha256', TELEMATICS_SECRET)
                                    .update(`${vehicleId}:${command}:${timestamp}`)
                                    .digest('hex');
    }
                                    
    if (signature !== expectedSignatureAdmin && signature !== expectedSignatureClient) {
        const logMsg = `[TELEMATICS ATTACK] Lá»‡nh viá»…n thÃ´ng giáº£ máº¡o cho xe ID ${vehicleId} bá»‹ cháº·n Ä‘á»©ng!`;
        db.run(`INSERT INTO SystemLogs (Description) VALUES (?)`, [logMsg]);
        return res.status(403).json({ error: "[V2] Lá»—i xÃ¡c thá»±c: Chá»¯ kÃ½ sá»‘ lá»‡nh viá»…n thÃ´ng khÃ´ng khá»›p!" });
    }
    
    const s = gpsState[vehicleId];
    
    // Kiá»ƒm tra khoáº£ng cÃ¡ch chá»§ xe (Proximity Verification) Ä‘á»ƒ chá»‘ng Relay Attack
    if (s && userLat !== undefined && userLon !== undefined) {
        const distKm = haversineKm(parseFloat(userLat), parseFloat(userLon), s.lat, s.lon);
        if (distKm > 0.1) { // 100 meters
            const alertMsg = `ðŸš¨ PHÃT HIá»†N Táº¤N CÃ”NG RELAY: Lá»‡nh viá»…n thÃ´ng ${command} cho xe #${vehicleId} bá»‹ tá»« chá»‘i do chá»§ xe á»Ÿ quÃ¡ xa (${(distKm*1000).toFixed(0)}m > 100m).`;
            db.run(`INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)`,
                [vehicleId, req.user.AccountID, 'RELAY_ATTACK_DETECTION', alertMsg, 'HIGH']);
            return res.status(403).json({ error: `[Báº¢O Máº¬T] Tá»« chá»‘i lá»‡nh: Khoáº£ng cÃ¡ch quÃ¡ xa (${(distKm*1000).toFixed(0)}m > 100m). Nghi ngá» táº¥n cÃ´ng láº·p tÃ­n hiá»‡u (Relay Attack).` });
        }
    }
    
    if (command === 'WIPE') {
        db.run(`DELETE FROM VehicleInfotainment WHERE VehicleID = ?`, [vehicleId], function(err) {
            res.json({ message: `[V2] Xe ID ${vehicleId} xÃ¡c nháº­n chá»¯ kÃ½ HMAC há»£p lá»‡. ÄÃ£ thá»±c thi lá»‡nh WIPE an toÃ n!` });
        });
    } else if (command === 'LOCK') {
        if (s) {
            s.isLocked = true;
            s.speed = 0;
            s.mode = 'LOCKED';
            startGpsLoop(vehicleId);
            pushSSE(vehicleId, { type: 'ENGINE_LOCKED', vehicleId, lockedBy: req.user.Username, ts: Date.now() });
        }
        db.run(`UPDATE Vehicles SET Status = 'Locked' WHERE VehicleID = ?`, [vehicleId]);
        res.json({ message: `[V2] ÄÃ£ khÃ³a xe ID ${vehicleId} tá»« xa thÃ nh cÃ´ng! Váº­n tá»‘c Ä‘Æ°a vá» 0.` });
    } else if (command === 'UNLOCK') {
        if (s) {
            s.isLocked = false;
            s.speed = 30;
            s.mode = 'GPS';
            startGpsLoop(vehicleId);
            pushSSE(vehicleId, { type: 'ENGINE_UNLOCKED', vehicleId, unlockedBy: req.user.Username, ts: Date.now() });
        }
        db.run(`UPDATE Vehicles SET Status = 'Rented' WHERE VehicleID = ?`, [vehicleId]);
        db.run(`INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)`,
            [vehicleId, req.user.AccountID, 'ENGINE_UNLOCK',
             `Äá»™ng cÆ¡ xe #${vehicleId} Ä‘Æ°á»£c má»Ÿ khÃ³a tá»« xa bá»Ÿi ${req.user.Username}.`, 'MEDIUM']);
        res.json({ message: `[V2] ÄÃ£ má»Ÿ khÃ³a xe ID ${vehicleId} tá»« xa thÃ nh cÃ´ng! Váº­n tá»‘c khÃ´i phá»¥c.` });
    } else if (command === 'RESTART') {
        let activeSession = gpsState[vehicleId];
        if (!activeSession) {
            initGpsSession(vehicleId, req.user.AccountID);
            activeSession = gpsState[vehicleId];
        }
        if (activeSession) {
            const route = activeSession.route || HANOI_ROUTE;
            const startPt = route[0] || { lat: 21.0285, lon: 105.8524 };
            activeSession.routeIndex = 0;
            activeSession.lat = startPt.lat;
            activeSession.lon = startPt.lon;
            activeSession.heading = calcBearing(startPt.lat, startPt.lon, (route[1] || startPt).lat, (route[1] || startPt).lon);
            activeSession.path = [{ lat: startPt.lat, lon: startPt.lon, ts: Date.now() }];
            
            if (activeSession.isLocked) {
                activeSession.speed = 0;
            } else {
                activeSession.speed = 30;
            }
            
            if (activeSession.intervalId) {
                clearInterval(activeSession.intervalId);
                activeSession.intervalId = null;
            }
            startGpsLoop(vehicleId);

            db.run(`INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)`,
                [vehicleId, req.user.AccountID, 'DEVICE_RESTART',
                 `Thiáº¿t bá»‹ Ä‘á»‹nh vá»‹ trÃªn xe #${vehicleId} khá»Ÿi Ä‘á»™ng láº¡i thÃ nh cÃ´ng (KhÃ³a Ä‘á»™ng cÆ¡: ${activeSession.isLocked ? 'ÄANG KHÃ“A' : 'KHÃ”NG'})`, 'INFO']);

            pushSSE(vehicleId, { type: 'DEVICE_RESTART', vehicleId, restartedBy: req.user.Username, isLocked: activeSession.isLocked, ts: Date.now() });
            res.json({ message: `[V2] ÄÃ£ khá»Ÿi Ä‘á»™ng láº¡i thiáº¿t bá»‹ Ä‘á»‹nh vá»‹ trÃªn xe ID ${vehicleId} thÃ nh cÃ´ng!` });
        } else {
            res.status(500).json({ error: `KhÃ´ng thá»ƒ khá»Ÿi cháº¡y phiÃªn Ä‘á»‹nh vá»‹ Ä‘á»ƒ restart.` });
        }
    } else if (command.startsWith('SET_GEOFENCE:')) {
        const radiusKm = parseFloat(command.split(':')[1]) || 5;
        if (s) {
            s.geofence = { lat: s.lat, lon: s.lon, radiusKm };
            s.geofenceViolating = false;
        }
        db.run(`INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)`,
            [vehicleId, req.user.AccountID, 'GEOFENCE_SET', `Thiáº¿t láº­p vÃ¹ng Ä‘á»‹a lÃ½ an toÃ n bÃ¡n kÃ­nh ${radiusKm}km`, 'INFO']);
        res.json({ message: `[V2] ÄÃ£ thiáº¿t láº­p vÃ¹ng an toÃ n bÃ¡n kÃ­nh ${radiusKm}km cho xe ID ${vehicleId}!` });
    } else {
        res.status(400).json({ error: `[V2] Lá»‡nh khÃ´ng xÃ¡c Ä‘á»‹nh: ${command}` });
    }
});

// API há»— trá»£ sinh chá»¯ kÃ½ Ä‘á»ƒ test trÃªn UI/Postman dá»… dÃ ng
app.post('/api/v2/telematics/generate-signature', verifyTokenV2, (req, res) => {
    const { vehicleId, command, timestamp } = req.body;
    if (!vehicleId || !command) return res.status(400).json({ error: 'Thieu vehicleId hoac command.' });
    const message = timestamp ? `${vehicleId}:${command}:${timestamp}` : command + vehicleId;
    const signature = crypto.createHmac('sha256', TELEMATICS_SECRET)
                                    .update(message)
                                    .digest('hex');
    res.json({ signature });
});

// =========================================================
// V3: GPS ENGINE â€“ ENVELOPE ENCRYPTION + DEAD RECKONING
// Kiáº¿n trÃºc: DEK (AES-256-GCM) sinh ngáº«u nhiÃªn má»—i phiÃªn
//            â†’ bá»c báº±ng RSA-OAEP-SHA256 cÃ´ng khai server
//            â†’ SSE Ä‘áº©y payload mÃ£ hÃ³a má»—i 3 giÃ¢y
// =========================================================

const gpsState = {}; // In-memory GPS state â€“ keyed by vehicleId

// =================================================================
// =================================================================
// TUYáº¾N ÄÆ¯á»œNG â€” CÃ¡c Ä‘iá»ƒm Ä‘Æ°á»ng tháº­t (Sáº½ Ä‘Æ°á»£c lÃ m má»‹n báº±ng OSRM)
// =================================================================
const BASE_HANOI_ROUTE = [
    { lat: 21.0285, lon: 105.8524, name: 'Há»“ HoÃ n Kiáº¿m' },
    { lat: 21.0265, lon: 105.8516, name: 'Äinh TiÃªn HoÃ ng' },
    { lat: 21.0245, lon: 105.8505, name: 'HÃ ng Khay' },
    { lat: 21.0225, lon: 105.8488, name: 'Tráº§n PhÃº' },
    { lat: 21.0202, lon: 105.8460, name: 'LÃª Duáº©n' },
    { lat: 21.0185, lon: 105.8435, name: 'Quá»‘c Tá»­ GiÃ¡m' },
    { lat: 21.0195, lon: 105.8402, name: 'ÄÃª La ThÃ nh' },
    { lat: 21.0210, lon: 105.8375, name: 'Giáº£ng VÃµ' },
    { lat: 21.0228, lon: 105.8352, name: 'Ngá»c KhÃ¡nh' },
    { lat: 21.0250, lon: 105.8338, name: 'Kim MÃ£' },
    { lat: 21.0275, lon: 105.8322, name: 'Liá»…u Giai' },
    { lat: 21.0302, lon: 105.8308, name: 'Äá»‘c Ngá»¯' },
    { lat: 21.0325, lon: 105.8294, name: 'ÄÆ°á»ng BÆ°á»Ÿi' },
    { lat: 21.0402, lon: 105.8265, name: 'Láº¡c Long QuÃ¢n' },
    { lat: 21.0470, lon: 105.8275, name: 'Ã‚u CÆ¡' },
    { lat: 21.0512, lon: 105.8348, name: 'Nháº­t TÃ¢n' },
    { lat: 21.0495, lon: 105.8432, name: 'XuÃ¢n Diá»‡u' },
    { lat: 21.0445, lon: 105.8472, name: 'Tá»© LiÃªn' },
    { lat: 21.0395, lon: 105.8508, name: 'YÃªn Phá»¥' },
    { lat: 21.0315, lon: 105.8525, name: 'Thá»¥y KhuÃª' },
    { lat: 21.0285, lon: 105.8524, name: 'Há»“ HoÃ n Kiáº¿m' }
];

const BASE_NORTH_ROUTE = [
    { lat: 21.0285, lon: 105.8524, name: 'Há»“ HoÃ n Kiáº¿m' },
    { lat: 21.0188, lon: 105.8432, name: 'LÃª Duáº©n' },
    { lat: 20.9998, lon: 105.8298, name: 'PhÆ°Æ¡ng Liá»‡t (VÄ3)' },
    { lat: 20.9965, lon: 105.8175, name: 'NgÃ£ TÆ° Sá»Ÿ' },
    { lat: 21.0018, lon: 105.7858, name: 'Má»¹ ÄÃ¬nh' },
    { lat: 21.0118, lon: 105.7345, name: 'ÄL ThÄƒng Long' },
    { lat: 21.0228, lon: 105.7412, name: 'QL32 (Cáº§u Diá»…n)' },
    { lat: 21.0328, lon: 105.7848, name: 'Cáº§u Giáº¥y' },
    { lat: 21.0285, lon: 105.8524, name: 'Há»“ HoÃ n Kiáº¿m' }
];

const BASE_AIRPORT_ROUTE = [
    { lat: 21.0285, lon: 105.8524, name: 'Há»“ HoÃ n Kiáº¿m' },
    { lat: 21.0512, lon: 105.8348, name: 'Cáº§u Nháº­t TÃ¢n' },
    { lat: 21.1258, lon: 105.8035, name: 'ÄÆ°á»ng VÃµ NguyÃªn GiÃ¡p' },
    { lat: 21.2185, lon: 105.8042, name: 'SÃ¢n Bay Ná»™i BÃ i' },
    { lat: 21.1258, lon: 105.8035, name: 'ÄÆ°á»ng VÃµ NguyÃªn GiÃ¡p' },
    { lat: 21.0285, lon: 105.8524, name: 'Há»“ HoÃ n Kiáº¿m' }
];

const BASE_WEST_ROUTE = [
    { lat: 21.0285, lon: 105.8524, name: 'Há»“ HoÃ n Kiáº¿m' },
    { lat: 21.0188, lon: 105.8432, name: 'LÃª Duáº©n' },
    { lat: 21.0068, lon: 105.8245, name: 'ChÃ¹a Bá»™c' },
    { lat: 20.9855, lon: 105.7952, name: 'HÃ  ÄÃ´ng' },
    { lat: 20.9535, lon: 105.7602, name: 'YÃªn NghÄ©a' },
    { lat: 20.9855, lon: 105.7952, name: 'HÃ  ÄÃ´ng' },
    { lat: 21.0285, lon: 105.8524, name: 'Há»“ HoÃ n Kiáº¿m' }
];

const BASE_EAST_ROUTE = [
    { lat: 21.0285, lon: 105.8524, name: 'Há»“ HoÃ n Kiáº¿m' },
    { lat: 21.0425, lon: 105.8645, name: 'Cáº§u ChÆ°Æ¡ng DÆ°Æ¡ng' },
    { lat: 21.0498, lon: 105.8812, name: 'Nguyá»…n VÄƒn Cá»«' },
    { lat: 21.0565, lon: 105.9035, name: 'Savico Megamall' },
    { lat: 21.0315, lon: 105.9385, name: 'Vinhomes Riverside' },
    { lat: 21.0425, lon: 105.8645, name: 'Cáº§u ChÆ°Æ¡ng DÆ°Æ¡ng' },
    { lat: 21.0285, lon: 105.8524, name: 'Há»“ HoÃ n Kiáº¿m' }
];

const BASE_DANANG_ROUTE = [
    { lat: 16.0544, lon: 108.2022, name: 'Cáº§u Rá»“ng' },
    { lat: 16.0611, lon: 108.2238, name: 'Biá»ƒn Má»¹ KhÃª' },
    { lat: 16.0125, lon: 108.2325, name: 'NgÅ© HÃ nh SÆ¡n' },
    { lat: 16.0544, lon: 108.2022, name: 'Cáº§u Rá»“ng' }
];

const BASE_HCMC_ROUTE = [
    { lat: 10.7769, lon: 106.7009, name: 'Chá»£ Báº¿n ThÃ nh' },
    { lat: 10.7626, lon: 106.6602, name: 'Phá»‘ Ä‘i bá»™ Nguyá»…n Huá»‡' },
    { lat: 10.7952, lon: 106.7218, name: 'Landmark 81' },
    { lat: 10.7769, lon: 106.7009, name: 'Chá»£ Báº¿n ThÃ nh' }
];

const BASE_HAIPHONG_ROUTE = [
    { lat: 20.8525, lon: 106.6821, name: 'NhÃ  hÃ¡t lá»›n Háº£i PhÃ²ng' },
    { lat: 20.8449, lon: 106.6881, name: 'ÄÆ°á»ng Láº¡ch Tray' },
    { lat: 20.7302, lon: 106.7871, name: 'Biá»ƒn Äá»“ SÆ¡n' },
    { lat: 20.8525, lon: 106.6821, name: 'NhÃ  hÃ¡t lá»›n Háº£i PhÃ²ng' }
];

const BASE_NHATRANG_ROUTE = [
    { lat: 12.2388, lon: 109.1967, name: 'ÄÆ°á»ng Tráº§n PhÃº' },
    { lat: 12.2715, lon: 109.1985, name: 'HÃ²n Chá»“ng' },
    { lat: 12.2218, lon: 109.1925, name: 'Cáº£ng Cáº§u ÄÃ¡' },
    { lat: 12.2388, lon: 109.1967, name: 'ÄÆ°á»ng Tráº§n PhÃº' }
];

const BASE_CANTHO_ROUTE = [
    { lat: 10.0333, lon: 105.7833, name: 'Báº¿n Ninh Kiá»u' },
    { lat: 10.0125, lon: 105.7658, name: 'Chá»£ Ná»•i CÃ¡i RÄƒng' },
    { lat: 10.0512, lon: 105.7725, name: 'SÃ¢n Bay Cáº§n ThÆ¡' },
    { lat: 10.0333, lon: 105.7833, name: 'Báº¿n Ninh Kiá»u' }
];

// Danh sÃ¡ch Äáº¡i lÃ½ / Cá»­a hÃ ng bÃ¡n xe (POIs)
const DEALERSHIPS = [
    { id: 1, lat: 21.0250, lon: 105.8338, name: 'Äáº¡i LÃ½ Ã” tÃ´ Kim MÃ£', type: 'dealer' },
    { id: 2, lat: 20.9965, lon: 105.8175, name: 'Tráº¡m Báº£o HÃ nh NgÃ£ TÆ° Sá»Ÿ', type: 'service' },
    { id: 3, lat: 21.0452, lon: 105.8268, name: 'Showroom Láº¡c Long QuÃ¢n', type: 'dealer' },
    { id: 4, lat: 21.2150, lon: 105.8040, name: 'Dá»‹ch vá»¥ xe SÃ¢n Bay Ná»™i BÃ i', type: 'service' }
];

// Biáº¿n lÆ°u trá»¯ tuyáº¿n Ä‘Æ°á»ng Ä‘Ã£ lÃ m má»‹n (dense points tá»« OSRM)
let HANOI_ROUTE = [...BASE_HANOI_ROUTE];
let NORTH_VIETNAM_ROUTE = [...BASE_NORTH_ROUTE];
let AIRPORT_ROUTE = [...BASE_AIRPORT_ROUTE];
let WEST_ROUTE = [...BASE_WEST_ROUTE];
let EAST_ROUTE = [...BASE_EAST_ROUTE];
let DANANG_ROUTE = [...BASE_DANANG_ROUTE];
let HCMC_ROUTE = [...BASE_HCMC_ROUTE];
let HAIPHONG_ROUTE = [...BASE_HAIPHONG_ROUTE];
let NHATRANG_ROUTE = [...BASE_NHATRANG_ROUTE];
let CANTHO_ROUTE = [...BASE_CANTHO_ROUTE];

// HÃ m fetch lá»™ trÃ¬nh tá»« OSRM
async function fetchOSRMRoute(waypoints) {
    const https = require('https');
    return new Promise((resolve, reject) => {
        const coordString = waypoints.map(c => `${c.lon},${c.lat}`).join(';');
        const url = `https://router.project-osrm.org/route/v1/driving/${coordString}?overview=full&geometries=geojson&steps=true`;
        
        https.get(url, { headers: { 'User-Agent': 'AntigravityCarRentalDemo/1.0' } }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const parsed = JSON.parse(data);
                    if (parsed.code === 'Ok' && parsed.routes.length > 0) {
                        const route = parsed.routes[0];
                        const densePoints = [];
                        let coordIndex = 0;
                        
                        route.legs.forEach(leg => {
                            leg.steps.forEach(step => {
                                const stepName = step.name || "ÄÆ°á»ng ná»‘i";
                                const stepCoordsCount = step.geometry.coordinates.length;
                                
                                for (let i = 0; i < stepCoordsCount; i++) {
                                    if (coordIndex < route.geometry.coordinates.length) {
                                        const c = route.geometry.coordinates[coordIndex];
                                        // Avoid duplicating exact same points continuously
                                        if (densePoints.length === 0 || 
                                            densePoints[densePoints.length-1].lat !== c[1] || 
                                            densePoints[densePoints.length-1].lon !== c[0]) {
                                            densePoints.push({
                                                lat: c[1],
                                                lon: c[0],
                                                name: stepName
                                            });
                                        }
                                        coordIndex++;
                                    }
                                }
                            });
                        });
                        if (densePoints.length === 0) resolve(waypoints);
                        else resolve(densePoints);
                    } else {
                        resolve(waypoints); // Fallback
                    }
                } catch (e) {
                    resolve(waypoints); // Fallback
                }
            });
        }).on('error', () => resolve(waypoints));
    });
}

// Khá»Ÿi táº¡o cÃ¡c tuyáº¿n Ä‘Æ°á»ng bÃ¡m Ä‘Æ°á»ng (Snap to Roads)
const delay = ms => new Promise(res => setTimeout(res, ms));

async function initRoutesWithOSRM() {
    console.log('[GPS] Äang táº£i tuyáº¿n Ä‘Æ°á»ng ToÃ n Viá»‡t Nam tá»« OSRM API...');
    HANOI_ROUTE = await fetchOSRMRoute(BASE_HANOI_ROUTE); await delay(500);
    NORTH_VIETNAM_ROUTE = await fetchOSRMRoute(BASE_NORTH_ROUTE); await delay(500);
    AIRPORT_ROUTE = await fetchOSRMRoute(BASE_AIRPORT_ROUTE); await delay(500);
    WEST_ROUTE = await fetchOSRMRoute(BASE_WEST_ROUTE); await delay(500);
    EAST_ROUTE = await fetchOSRMRoute(BASE_EAST_ROUTE); await delay(500);
    DANANG_ROUTE = await fetchOSRMRoute(BASE_DANANG_ROUTE); await delay(500);
    HCMC_ROUTE = await fetchOSRMRoute(BASE_HCMC_ROUTE); await delay(500);
    HAIPHONG_ROUTE = await fetchOSRMRoute(BASE_HAIPHONG_ROUTE); await delay(500);
    NHATRANG_ROUTE = await fetchOSRMRoute(BASE_NHATRANG_ROUTE); await delay(500);
    CANTHO_ROUTE = await fetchOSRMRoute(BASE_CANTHO_ROUTE);
    console.log(`[GPS] ÄÃ£ táº£i xong 10 tuyáº¿n Ä‘Æ°á»ng! Tá»‘c Ä‘á»™ load OSRM hoÃ n háº£o.`);
}

// Gá»i khá»Ÿi táº¡o ngay vÃ  chá»‰ kÃ­ch hoáº¡t xe sau khi Ä‘Ã£ táº£i xong báº£n Ä‘á»“
initRoutesWithOSRM().then(() => {
    console.log('[GPS] Tuyáº¿n Ä‘Æ°á»ng Ä‘Ã£ sáºµn sÃ ng. KhÃ´i phá»¥c cÃ¡c xe Ä‘ang hoáº¡t Ä‘á»™ng...');
    db.all(`SELECT * FROM Rentals WHERE Status = 'Active'`, (err, rentals) => {
        if (!rentals) return;
        rentals.forEach(r => { 
            if (!gpsState[r.VehicleID]) {
                db.get(`SELECT * FROM VehicleGPS WHERE VehicleID = ?`, [r.VehicleID], (err, gps) => {
                    initGpsSession(r.VehicleID, r.AccountID, r.RouteType || 'hanoi', gps);
                });
            }
        });
        if (rentals.length) console.log(`[V3-GPS] KhÃ´i phá»¥c thÃ nh cÃ´ng ${rentals.length} phiÃªn GPS Ä‘ang cháº¡y (Persistence).`);
    });
});

// HÃ m láº¥y Ä‘á»‹a chá»‰ tá»« Tá»a Ä‘á»™ (Reverse Geocoding qua Nominatim OSM)
function reverseGeocode(lat, lon) {
    const https = require('https');
    return new Promise((resolve) => {
        const url = `https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lon}&zoom=18&addressdetails=1`;
        https.get(url, { headers: { 'User-Agent': 'AntigravityCarRentalDemo/1.0' } }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const parsed = JSON.parse(data);
                    if (parsed && parsed.display_name) {
                        resolve(parsed.display_name);
                    } else {
                        resolve('KhÃ´ng xÃ¡c Ä‘á»‹nh Ä‘Æ°á»£c Ä‘á»‹a chá»‰');
                    }
                } catch (e) {
                    resolve('Lá»—i phÃ¢n tÃ­ch Ä‘á»‹a chá»‰');
                }
            });
        }).on('error', () => resolve('Lá»—i káº¿t ná»‘i API Ä‘á»‹a chá»‰'));
    });
}

// Gá»­i SSE event cho cÃ¡c client Ä‘ang káº¿t ná»‘i tá»›i vehicleId
function sendGpsSSE(vehicleId, eventType, data) {
    const s = gpsState[vehicleId];
    if (s && s.clients) {
        s.clients.forEach(client => {
            client.write(`event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`);
        });
    }
}

// Láº­p lá»‹ch 1 giá» (3,600,000 ms) gá»­i bÃ¡o cÃ¡o Ä‘á»‹nh ká»³ theo yÃªu cáº§u cá»§a tháº§y giÃ¡o
setInterval(async () => {
    console.log('[SYSTEM] Báº¯t Ä‘áº§u táº¡o bÃ¡o cÃ¡o GPS Ä‘á»‹nh ká»³ 1 giá»...');
    
    // Thu tháº­p Ä‘á»‹a chá»‰ cho táº¥t cáº£ cÃ¡c xe Ä‘ang hoáº¡t Ä‘á»™ng
    for (const vehicleId in gpsState) {
        const s = gpsState[vehicleId];
        if (!s || s.isTampered) continue; // Bá» qua xe bá»‹ vÃ´ hiá»‡u hÃ³a
        
        // Gá»i API láº¥y TÃªn Ä‘Æ°á»ng, phÆ°á»ng xÃ£
        const address = await reverseGeocode(s.lat, s.lon);
        
        const reportMsg = `ðŸ“ BÃO CÃO HÃ€NH TRÃŒNH Tá»”NG Há»¢P (1 GIá»œ) - XE #${vehicleId}:
- VÄ© Ä‘á»™: ${s.lat.toFixed(6)}
- Kinh Ä‘á»™: ${s.lon.toFixed(6)}
- Vá»‹ trÃ­ hiá»‡n táº¡i: ${address}
- Tá»‘c Ä‘á»™ trung bÃ¬nh: ${Math.round(s.speed)} km/h
- Tráº¡ng thÃ¡i an ninh: á»”n Ä‘á»‹nh (Chá»‘ng phÃ¡ sÃ³ng hoáº¡t Ä‘á»™ng tá»‘t)`;

        const report = {
            type: 'periodic_report',
            vehicleId: vehicleId,
            message: reportMsg,
            timestamp: new Date().toISOString()
        };
        
        // Gá»­i qua SSE
        sendGpsSSE(vehicleId, 'report', report);
    }
}, 3600 * 1000);

/** TÃ­nh gÃ³c phÆ°Æ¡ng vá»‹ (bearing) tá»« Ä‘iá»ƒm 1 â†’ Ä‘iá»ƒm 2 */
function calcBearing(lat1, lon1, lat2, lon2) {
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const y = Math.sin(dLon) * Math.cos(lat2 * Math.PI / 180);
    const x = Math.cos(lat1 * Math.PI / 180) * Math.sin(lat2 * Math.PI / 180)
             - Math.sin(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * Math.cos(dLon);
    return (Math.atan2(y, x) * 180 / Math.PI + 360) % 360;
}

/** Khá»Ÿi Ä‘á»™ng phiÃªn GPS báº£o máº­t cho xe khi Ä‘Æ°á»£c thuÃª */
async function initGpsSession(vehicleId, accountId, routeType = 'hanoi', restoreGps = null) {
    if (gpsState[vehicleId] && !gpsState[vehicleId].isTampered) return;

    // Assign different route types to different cars if not explicitly requested
    if (routeType === 'hanoi') {
        if (vehicleId === 2) routeType = 'hanoi';
        else if (vehicleId === 3) routeType = 'haiphong';
        else if (vehicleId === 4) routeType = 'danang';
        else if (vehicleId === 5) routeType = 'danang';
        else if (vehicleId === 6) routeType = 'nhatrang';
        else if (vehicleId === 7) routeType = 'hcmc';
        else if (vehicleId === 8) routeType = 'hcmc';
        else if (vehicleId === 9) routeType = 'cantho';
        else if (vehicleId === 10) routeType = 'cantho';
        else routeType = 'hanoi';
    }

    // Sinh DEK (Data Encryption Key) ngáº«u nhiÃªn cho phiÃªn nÃ y
    const dek = crypto.randomBytes(32);

    // Bá»c DEK báº±ng RSA Public Key cá»§a server (Envelope Encryption)
    const dekWrappedForServer = crypto.publicEncrypt(
        { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
        dek
    ).toString('base64');

    let route = HANOI_ROUTE;
    if (routeType === 'north_vietnam') route = NORTH_VIETNAM_ROUTE;
    else if (routeType === 'airport') route = AIRPORT_ROUTE;
    else if (routeType === 'west') route = WEST_ROUTE;
    else if (routeType === 'east') route = EAST_ROUTE;
    else if (routeType === 'danang') route = DANANG_ROUTE;
    else if (routeType === 'hcmc') route = HCMC_ROUTE;
    else if (routeType === 'haiphong') route = HAIPHONG_ROUTE;
    else if (routeType === 'nhatrang') route = NHATRANG_ROUTE;
    else if (routeType === 'cantho') route = CANTHO_ROUTE;

    let routeIndex = 0;
    if (restoreGps && restoreGps.Lat && restoreGps.Lon) {
        // TÃ¡i táº¡o láº¡i vá»‹ trÃ­ báº±ng cÃ¡ch tÃ¬m Ä‘iá»ƒm gáº§n nháº¥t trÃªn lá»™ trÃ¬nh Ä‘Ã³ng vÃ²ng
        let minDist = 9999;
        for (let i = 0; i < route.length; i++) {
            let d = haversineKm(restoreGps.Lat, restoreGps.Lon, route[i].lat, route[i].lon);
            if (d < minDist) { minDist = d; routeIndex = i; }
        }
    } else {
        // Chá»n Ä‘iá»ƒm xuáº¥t phÃ¡t ngáº«u nhiÃªn trÃªn lá»™ trÃ¬nh Ä‘Ã³ng vÃ²ng cÃ³ sáºµn
        routeIndex = Math.floor(Math.random() * route.length);
    }
    
    if (!route || route.length < 2) {
        route = HANOI_ROUTE;
        routeIndex = 0;
    }

    const startPt = route[routeIndex];
    const initialSpeed = (routeType === 'airport' || routeType === 'north_vietnam') ? 80 : 40;
    const nextIndex = (routeIndex + 1) % route.length;

    gpsState[vehicleId] = {
        vehicleId: parseInt(vehicleId), accountId,
        lat: startPt.lat, lon: startPt.lon,
        speed: initialSpeed,
        targetSpeed: initialSpeed,
        heading: calcBearing(startPt.lat, startPt.lon, route[nextIndex].lat, route[nextIndex].lon),
        dek, dekWrappedForServer,
        routeIndex: routeIndex,
        routeType: routeType,
        route: route,
        isLocked: false, isTampered: false,
        geofence: { lat: 21.0285, lon: 105.8524, radiusKm: 5.0 }, // Geofence táº¡i Há»“ HoÃ n Kiáº¿m
        geofenceViolating: false, lastAlertTime: 0,
        path: [{ lat: startPt.lat, lon: startPt.lon, ts: Date.now() }],
        clients: new Set(),
        intervalId: null
    };

    // Kiá»ƒm tra tráº¡ng thÃ¡i khÃ³a tá»« cÆ¡ sá»Ÿ dá»¯ liá»‡u Ä‘á»ƒ cáº­p nháº­t vÃ  khá»Ÿi cháº¡y Ä‘á»‹nh vá»‹
    db.get(`SELECT Status FROM Vehicles WHERE VehicleID = ?`, [vehicleId], (err, row) => {
        if (gpsState[vehicleId]) {
            if (row && row.Status === 'Locked') {
                gpsState[vehicleId].isLocked = true;
                gpsState[vehicleId].speed = 0;
                gpsState[vehicleId].targetSpeed = 0;
                console.log(`[V3-GPS] Xe #${vehicleId} khá»Ÿi táº¡o á»Ÿ tráº¡ng thÃ¡i KHÃ“A tá»« CSDL.`);
            }
            startGpsLoop(vehicleId);
            console.log(`[V3-GPS] Khá»Ÿi Ä‘á»™ng phiÃªn xe #${vehicleId} | DEK: AES-256-GCM | Bá»c: RSA-OAEP-SHA256`);
        }
    });
}

/** MÃ£ hÃ³a tá»a Ä‘á»™ GPS báº±ng DEK cá»§a phiÃªn (AES-256-GCM) */
function encryptGpsCoords(vehicleId, lat, lon, speed, heading) {
    const s = gpsState[vehicleId];
    if (!s || !s.dek) return null;
    const plain = JSON.stringify({ lat, lon, speed, heading, ts: Date.now() });
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', s.dek, iv);
    let ct = cipher.update(plain, 'utf8', 'hex');
    ct += cipher.final('hex');
    return { iv: iv.toString('hex'), authTag: cipher.getAuthTag().toString('hex'), ciphertext: ct };
}

/** TÃ­nh khoáº£ng cÃ¡ch Haversine (km) giá»¯a 2 tá»a Ä‘á»™ */
function haversineKm(lat1, lon1, lat2, lon2) {
    const R = 6371, dLat = (lat2 - lat1) * Math.PI / 180, dLon = (lon2 - lon1) * Math.PI / 180;
    const a = Math.sin(dLat/2)**2 + Math.cos(lat1*Math.PI/180)*Math.cos(lat2*Math.PI/180)*Math.sin(dLon/2)**2;
    return 2 * R * Math.asin(Math.sqrt(a));
}

function getNearestLocationName(routeType, lat, lon) {
    let base = BASE_HANOI_ROUTE;
    if (routeType === 'airport') base = BASE_AIRPORT_ROUTE;
    else if (routeType === 'north_vietnam') base = BASE_NORTH_ROUTE;
    else if (routeType === 'west') base = BASE_WEST_ROUTE;
    else if (routeType === 'east') base = BASE_EAST_ROUTE;
    else if (routeType === 'danang') base = BASE_DANANG_ROUTE;
    else if (routeType === 'hcmc') base = BASE_HCMC_ROUTE;
    else if (routeType === 'haiphong') base = BASE_HAIPHONG_ROUTE;
    else if (routeType === 'nhatrang') base = BASE_NHATRANG_ROUTE;
    else if (routeType === 'cantho') base = BASE_CANTHO_ROUTE;

    let nearest = base[0];
    let minDist = 9999;
    for (let wp of base) {
        let d = haversineKm(lat, lon, wp.lat, wp.lon);
        if (d < minDist) { minDist = d; nearest = wp; }
    }
    return `Äang gáº§n ${nearest.name}`;
}

/** Äáº©y sá»± kiá»‡n SSE tá»›i táº¥t cáº£ client Ä‘ang káº¿t ná»‘i */
function pushSSE(vehicleId, data) {
    const s = gpsState[vehicleId];
    if (!s) return;
    const payload = `data: ${JSON.stringify(data)}\n\n`;
    const dead = [];
    s.clients.forEach(r => { try { r.write(payload); } catch { dead.push(r); } });
    dead.forEach(r => s.clients.delete(r));
}

/** Giáº£ láº­p BSSID Wi-Fi tá»« tá»a Ä‘á»™ (Wi-Fi Fingerprinting) */
function generateWifiBssids(lat, lon) {
    const h = Math.floor(lat * 10000) % 256, v = Math.floor(lon * 10000) % 256;
    return [
        `${h.toString(16).padStart(2,'0')}:${v.toString(16).padStart(2,'0')}:C3:F1:2A:01`,
        `${((h+7)%256).toString(16).padStart(2,'0')}:${((v+13)%256).toString(16).padStart(2,'0')}:D4:E8:9B:22`,
        `${((h+15)%256).toString(16).padStart(2,'0')}:${((v+27)%256).toString(16).padStart(2,'0')}:A1:5C:3F:44`
    ];
}

/** VÃ²ng láº·p GPS â€“ cáº­p nháº­t vá»‹ trÃ­ má»—i 3 giÃ¢y, kiá»ƒm tra Geofence */
function startGpsLoop(vehicleId) {
    const s = gpsState[vehicleId];
    if (!s || s.intervalId) return;

    s.intervalId = setInterval(() => {
        const st = gpsState[vehicleId];
        if (!st || st.isTampered) {
            if (st?.intervalId) { clearInterval(st.intervalId); st.intervalId = null; }
            return;
        }

        if (st.isLocked) {
            st.speed = 0;
            const encrypted = encryptGpsCoords(vehicleId, st.lat, st.lon, 0, st.heading);
            
            db.run(`UPDATE VehicleGPS SET Lat=?, Lon=?, Speed=?, Heading=?, Mode=?, Timestamp=? WHERE VehicleID=?`,
                [+st.lat.toFixed(6), +st.lon.toFixed(6), 0, +st.heading.toFixed(1), 'LOCKED', new Date().toISOString(), vehicleId]);

            pushSSE(vehicleId, {
                type: 'GPS',
                vehicleId: st.vehicleId,
                encrypted,
                dekWrappedForServer: st.dekWrappedForServer,
                lat: st.lat,
                lon: st.lon,
                speed: 0,
                heading: st.heading,
                mode: 'LOCKED',
                outsideGeofence: st.geofenceViolating,
                distanceFromCenter: haversineKm(st.geofence.lat, st.geofence.lon, st.lat, st.lon),
                geofence: st.geofence,
                pathPoints: st.path.slice(-25),
                currentWaypoint: 'Äá»™ng cÆ¡ bá»‹ khÃ³a',
                nextWaypoint: '',
                isLocked: true,
                ts: Date.now(),
                note: 'Äá»™ng cÆ¡ bá»‹ khÃ³a tá»« xa â€” Thiáº¿t bá»‹ váº«n hoáº¡t Ä‘á»™ng nhÆ°ng váº­n tá»‘c = 0'
            });
            return;
        }

        let eventData;

        let route = st.route || HANOI_ROUTE;
        if (st.routeType === 'airport') route = AIRPORT_ROUTE;
        else if (st.routeType === 'north_vietnam') route = NORTH_VIETNAM_ROUTE;
        else if (st.routeType === 'west') route = WEST_ROUTE;
        else if (st.routeType === 'east') route = EAST_ROUTE;
        else if (st.routeType === 'danang') route = DANANG_ROUTE;
        else if (st.routeType === 'hcmc') route = HCMC_ROUTE;
        else if (st.routeType === 'haiphong') route = HAIPHONG_ROUTE;
        else if (st.routeType === 'nhatrang') route = NHATRANG_ROUTE;
        else if (st.routeType === 'cantho') route = CANTHO_ROUTE;
        let speedMultiplier = 1;

        // â”€â”€ ROUTE-FOLLOWING GPS MODE â”€â”€
        const dt = 3; // giÃ¢y má»—i tick
        // Tá»‘c Ä‘á»™ thá»±c táº¿ theo yÃªu cáº§u (cÃ³ tÄƒng tá»‘c mÆ°á»£t mÃ )
        const targetBase = (st.routeType === 'north_vietnam' || st.routeType === 'airport') ? 80 : 40;
        
        if (!st.targetSpeed || Math.abs(st.speed - st.targetSpeed) < 3) {
            st.targetSpeed = targetBase + (Math.random() * 15 - 5);
        }
        
        // Gia tá»‘c tuyáº¿n tÃ­nh: tÄƒng giáº£m tá»« tá»«
        if (st.speed < st.targetSpeed) st.speed += Math.random() * 2 + 0.5;
        else if (st.speed > st.targetSpeed) st.speed -= Math.random() * 2 + 0.5;
        
        const distKm = (st.speed / 3600) * dt * speedMultiplier;

        // Xá»­ lÃ½ hÆ°á»›ng Ä‘i (Tiáº¿n hoáº·c LÃ¹i)
        let targetIndex;
        if (st.isReversing) {
            if (st.routeIndex <= 0) {
                st.isReversing = false;
                targetIndex = 1 % route.length;
            } else {
                targetIndex = st.routeIndex - 1;
            }
        } else {
            if (st.routeIndex >= route.length - 1) {
                st.isReversing = true;
                targetIndex = st.routeIndex - 1;
            } else {
                targetIndex = st.routeIndex + 1;
            }
        }

        const targetWp = route[targetIndex];
        const distToWp = haversineKm(st.lat, st.lon, targetWp.lat, targetWp.lon);

        if (distToWp <= distKm + 0.05) {
            // Äáº¿n waypoint, tiáº¿n Ä‘áº¿n Ä‘iá»ƒm tiáº¿p theo
            st.routeIndex = targetIndex;
            st.lat = route[st.routeIndex].lat;
            st.lon = route[st.routeIndex].lon;
            
            let nextTargetIndex;
            if (st.isReversing) {
                if (st.routeIndex <= 0) nextTargetIndex = 1 % route.length;
                else nextTargetIndex = st.routeIndex - 1;
            } else {
                if (st.routeIndex >= route.length - 1) nextTargetIndex = st.routeIndex - 1;
                else nextTargetIndex = st.routeIndex + 1;
            }
            const nextNext = route[nextTargetIndex];
            st.heading = calcBearing(st.lat, st.lon, nextNext.lat, nextNext.lon);
        } else {
            // Di chuyá»ƒn hÆ°á»›ng tá»›i waypoint
            st.heading = calcBearing(st.lat, st.lon, targetWp.lat, targetWp.lon);
            const headingRad = st.heading * Math.PI / 180;
            st.lat += (distKm * Math.cos(headingRad)) / 111.0;
            st.lon += (distKm * Math.sin(headingRad)) / (111.0 * Math.cos(st.lat * Math.PI / 180));
        }

        const currentWp = route[st.routeIndex] || route[0];
        st.path.push({ lat: st.lat, lon: st.lon, ts: Date.now() });
        if (st.path.length > 60) st.path.shift();

        const encrypted = encryptGpsCoords(vehicleId, st.lat, st.lon, st.speed, st.heading);
        const dist = haversineKm(st.geofence.lat, st.geofence.lon, st.lat, st.lon);
        const outside = dist > st.geofence.radiusKm;

        // Táº¡o SecurityAlert khi xe vÆ°á»£t Geofence
        if (outside && !st.geofenceViolating) {
            st.geofenceViolating = true;
            const now = Date.now();
            if (now - st.lastAlertTime > 20000) {
                st.lastAlertTime = now;
                db.run(`INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)`,
                    [vehicleId, st.accountId, 'GEOFENCE_VIOLATION',
                     `Xe #${vehicleId} vÆ°á»£t vÃ¹ng an toÃ n ${st.geofence.radiusKm}km! Khoáº£ng cÃ¡ch: ${dist.toFixed(2)}km | Tá»a Ä‘á»™: (${st.lat.toFixed(5)}, ${st.lon.toFixed(5)})`,
                     'HIGH']);
            }
        } else if (!outside) st.geofenceViolating = false;

        // Láº¥y tÃªn Ä‘á»‹a Ä‘iá»ƒm gáº§n nháº¥t Ä‘á»ƒ giáº£ láº­p Reverse Geocoding liÃªn tá»¥c
        const locName = getNearestLocationName(st.routeType, st.lat, st.lon);

        // Ghi GPS má»›i nháº¥t vÃ o CSDL
        db.run(`UPDATE VehicleGPS SET Lat=?, Lon=?, Speed=?, Heading=?, Mode=?, Timestamp=?, Address=?, LastReported='Vá»«a xong' WHERE VehicleID=?`,
            [+st.lat.toFixed(6), +st.lon.toFixed(6), +st.speed.toFixed(1), +st.heading.toFixed(1), 'GPS', new Date().toISOString(), locName, vehicleId]);

        // â”€â”€ Kiá»ƒm tra giá»›i háº¡n hÃ nh trÃ¬nh (Trip Boundary) â”€â”€
        if (st.tripLimit && st.tripLimit.enabled) {
            const now = Date.now();
            const tripDistKm = haversineKm(st.tripLimit.fromLat, st.tripLimit.fromLon, st.lat, st.lon);
            const tripOutsideRadius = tripDistKm > st.tripLimit.radiusKm;
            const tripTimeExpired = now > st.tripLimit.endsAt;
            const remainingMs = Math.max(0, st.tripLimit.endsAt - now);
            const remainingMin = Math.ceil(remainingMs / 60000);
            
            if ((tripOutsideRadius || tripTimeExpired) && !st.tripLimit.violated) {
                st.tripLimit.violated = true;
            }
            
            if (st.tripLimit.violated && (now - st.tripLimit.lastTripAlertTime > 30000)) {
                st.tripLimit.lastTripAlertTime = now;
                const reason = tripTimeExpired 
                    ? `â° Háº¿t thá»i gian hÃ nh trÃ¬nh (${st.tripLimit.limitMinutes} phÃºt)`
                    : `ðŸ“ VÆ°á»£t bÃ¡n kÃ­nh cho phÃ©p ${st.tripLimit.radiusKm}km (cÃ¡ch Ä‘iá»ƒm xuáº¥t phÃ¡t ${tripDistKm.toFixed(2)}km)`;
                db.run(`INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)`,
                    [vehicleId, st.accountId, 'GEOFENCE_VIOLATION',
                     `ðŸš¨ TRIP VIOLATION - Xe #${vehicleId}: ${reason} | Tá»« "${st.tripLimit.fromName}" â†’ "${st.tripLimit.toName}"`,
                     'CRITICAL']);
            }

            // Gáº¯n thÃ´ng tin trip vÃ o eventData
            eventData = {
                type: 'GPS', vehicleId: st.vehicleId,
                encrypted, dekWrappedForServer: st.dekWrappedForServer,
                lat: st.lat, lon: st.lon, speed: st.speed, heading: st.heading,
                outsideGeofence: outside, distanceFromCenter: dist,
                geofence: st.geofence, pathPoints: st.path.slice(-25),
                currentWaypoint: currentWp?.name || 'TrÃªn Ä‘Æ°á»ng',
                nextWaypoint: (route[(st.routeIndex + 1) % route.length])?.name || '',
                routeIndex: st.routeIndex, routeTotal: route.length - 1,
                routeType: st.routeType,
                tripLimit: {
                    enabled: true,
                    fromName: st.tripLimit.fromName,
                    toName: st.tripLimit.toName,
                    radiusKm: st.tripLimit.radiusKm,
                    limitMinutes: st.tripLimit.limitMinutes,
                    remainingMin,
                    tripDistKm: +tripDistKm.toFixed(2),
                    violated: st.tripLimit.violated,
                    tripTimeExpired,
                    tripOutsideRadius
                },
                ts: Date.now()
            };
        } else {
            eventData = {
                type: 'GPS', vehicleId: st.vehicleId,
                encrypted, dekWrappedForServer: st.dekWrappedForServer,
                lat: st.lat, lon: st.lon, speed: st.speed, heading: st.heading,
                outsideGeofence: outside, distanceFromCenter: dist,
                geofence: st.geofence, pathPoints: st.path.slice(-25),
                // ThÃ´ng tin tuyáº¿n Ä‘Æ°á»ng
                currentWaypoint: currentWp?.name || 'TrÃªn Ä‘Æ°á»ng',
                nextWaypoint: (route[(st.routeIndex + 1) % route.length])?.name || '',
                routeIndex: st.routeIndex,
                routeTotal: route.length - 1,
                routeType: st.routeType,
                ts: Date.now()
            };
        }

        pushSSE(vehicleId, eventData);
    }, 3000);
}

/** Káº¿t thÃºc phiÃªn GPS: dá»«ng loop, Zeroize DEK */
function terminateGpsSession(vehicleId) {
    const s = gpsState[vehicleId];
    if (!s) return;
    if (s.intervalId) clearInterval(s.intervalId);
    pushSSE(vehicleId, { type: 'SESSION_ENDED', vehicleId });
    if (s.dek) s.dek.fill(0); // ZEROIZE DEK
    delete gpsState[vehicleId];
    
    // Äáº£m báº£o Test Dashboard máº¥t tÃ­n hiá»‡u xe nÃ y
    db.run(`UPDATE VehicleGPS SET Mode = 'Parked', Speed = 0, LastReported = 'ÄÃ£ táº¯t thiáº¿t bá»‹' WHERE VehicleID = ?`, [vehicleId]);
    
    console.log(`[V3-GPS] Káº¿t thÃºc phiÃªn xe #${vehicleId} â€” DEK Ä‘Ã£ Zeroize`);
}



// â”€â”€ V3 API: SSE GPS Stream â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.get('/api/v2/vehicles/gps-stream/:vehicleId', verifyTokenV2, async (req, res) => {
    const vehicleId = parseInt(req.params.vehicleId);
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();

    if (!gpsState[vehicleId]) await initGpsSession(vehicleId, req.user.AccountID);
    const s = gpsState[vehicleId];
    if (!s) return res.end(); // Fail safe
    
    s.clients.add(res);

    // Gá»­i tráº¡ng thÃ¡i ban Ä‘áº§u ngay láº­p tá»©c
    res.write(`data: ${JSON.stringify({
        type: 'INIT', vehicleId,
        lat: s.lat, lon: s.lon, speed: s.speed, heading: s.heading,
        geofence: s.geofence, pathPoints: s.path,
        isLocked: s.isLocked, isTampered: s.isTampered,
        encryptionInfo: { algorithm: 'AES-256-GCM', dek: 'RSA-OAEP-SHA256', active: true }
    })}\n\n`);

    req.on('close', () => { if (gpsState[vehicleId]) gpsState[vehicleId].clients.delete(res); });
});

// â”€â”€ V3 API: Cáº­p nháº­t luá»“ng GPS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.get('/api/v2/vehicles/active-gps', (req, res) => {
    const data = Object.values(gpsState).map(s => ({
        vehicleId: s.vehicleId,
        lat: +s.lat.toFixed(5),
        lon: +s.lon.toFixed(5),
        speed: +s.speed.toFixed(1),
        heading: +s.heading.toFixed(1),
        isLocked: s.isLocked,
        isTampered: s.isTampered,
        geofenceViolating: s.geofenceViolating,
        clientCount: s.clients.size,
        geofence: s.geofence,
        routeType: s.routeType || 'hanoi'
    }));
    res.json(data);
});

// â”€â”€ V3 API: Láº¥y tráº¡ng thÃ¡i GPS hiá»‡n táº¡i â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.get('/api/v2/vehicles/gps-current', verifyTokenV2, (req, res) => {
    db.get(`SELECT VehicleID FROM Rentals WHERE AccountID = ? AND Status = 'Active' LIMIT 1`,
        [req.user.AccountID], (err, rental) => {
        if (err || !rental) return res.status(404).json({ error: 'KhÃ´ng cÃ³ xe Ä‘ang thuÃª.' });
        const vid = rental.VehicleID;
        if (!gpsState[vid]) initGpsSession(vid, req.user.AccountID);
        const s = gpsState[vid];
        res.json({
            vehicleId: vid, lat: s.lat, lon: s.lon, speed: s.speed, heading: s.heading,
            isLocked: s.isLocked, isTampered: s.isTampered,
            geofence: s.geofence, geofenceViolating: s.geofenceViolating,
            pathPoints: s.path.slice(-30),
            envelopeEncryption: { algorithm: 'AES-256-GCM', dekWrapped: 'RSA-OAEP-SHA256', active: !s.isTampered }
        });
    });
});

// â”€â”€ V3 API: Cáº¥p DEK Ä‘Ã£ bá»c cho client giáº£i mÃ£ GPS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.get('/api/v2/vehicles/gps-dek', verifyTokenV2, (req, res) => {
    db.get(`SELECT VehicleID FROM Rentals WHERE AccountID = ? AND Status = 'Active' LIMIT 1`,
        [req.user.AccountID], (err, rental) => {
        if (err || !rental) return res.status(404).json({ error: 'KhÃ´ng cÃ³ xe Ä‘ang thuÃª.' });
        const s = gpsState[rental.VehicleID];
        if (!s || !s.dek) return res.status(404).json({ error: 'PhiÃªn GPS chÆ°a sáºµn sÃ ng.' });

        // Bá»c DEK báº±ng khÃ³a phiÃªn cá»§a user (HKDF-like)
        const sessionKey = crypto.createHash('sha256')
            .update(JWT_SECRET + req.user.AccountID + rental.VehicleID).digest();
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, iv);
        let enc = cipher.update(s.dek.toString('hex'), 'utf8', 'hex');
        enc += cipher.final('hex');
        res.json({
            vehicleId: rental.VehicleID, encryptedDek: enc,
            iv: iv.toString('hex'), authTag: cipher.getAuthTag().toString('hex'),
            note: 'DEK bá»c báº±ng khÃ³a phiÃªn cÃ¡ nhÃ¢n â€” Envelope Encryption Ä‘a ngÆ°á»i nháº­n'
        });
    });
});

// â”€â”€ V3 API: Äáº·t vÃ¹ng Ä‘á»‹a lÃ½ an toÃ n (Geofence) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.post('/api/v2/vehicles/set-geofence', verifyTokenV2, (req, res) => {
    const { vehicleId, radiusKm } = req.body;
    const s = gpsState[vehicleId];
    if (!s) return res.status(404).json({ error: 'PhiÃªn GPS xe khÃ´ng hoáº¡t Ä‘á»™ng.' });
    s.geofence = { lat: s.lat, lon: s.lon, radiusKm: Math.max(0.5, Math.min(50, parseFloat(radiusKm) || 5)) };
    s.geofenceViolating = false;
    db.run(`INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)`,
        [vehicleId, s.accountId, 'GEOFENCE_SET',
         `Cáº­p nháº­t vÃ¹ng an toÃ n xe #${vehicleId}: ${s.geofence.radiusKm}km tá»« (${s.lat.toFixed(5)}, ${s.lon.toFixed(5)})`, 'INFO']);
    res.json({ message: `VÃ¹ng an toÃ n cáº­p nháº­t: ${s.geofence.radiusKm}km tá»« vá»‹ trÃ­ hiá»‡n táº¡i`, geofence: s.geofence });
});

// â”€â”€ V3 API: Giáº£ láº­p nhiá»…u GPS (GPS Jamming V1/V2) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.post('/api/v2/vehicles/simulate-jamming', (req, res) => {
    const { vehicleId, enable, version } = req.body;
    const s = gpsState[vehicleId];
    if (!s) return res.status(404).json({ error: 'PhiÃªn GPS khÃ´ng hoáº¡t Ä‘á»™ng.' });
    
    if (enable === false) {
        s.isJammed = false;
        s.isJammedV1 = false;
        s.mode = 'GPS';
        const msg = '[PHá»¤C Há»’I] TÃ­n hiá»‡u GPS xe #' + vehicleId + ' Ä‘Ã£ bÃ¬nh thÆ°á»ng trá»Ÿ láº¡i. Cháº¿ Ä‘á»™ Ä‘á»‹nh vá»‹ vá»‡ tinh GPS hoáº¡t Ä‘á»™ng.';
        db.run('INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)',
            [vehicleId, s.accountId, 'GPS_JAMMING', msg, 'INFO']);
        pushSSE(vehicleId, { type: 'MODE_CHANGE', mode: s.mode, isJammed: false, isJammedV1: false, ts: Date.now() });
        return res.json({ isJammed: false, isJammedV1: false, mode: s.mode, message: msg });
    }
    
    if (parseInt(version) === 1) {
        s.isJammedV1 = true;
        s.isJammed = false;
        s.mode = 'LOST_GPS';
        const msg = '[ðŸš¨ Cáº¢NH BÃO] PhÃ¡t hiá»‡n nhiá»…u GPS xe #' + vehicleId + '! V1 (KhÃ´ng báº£o máº­t): Xe bá»‹ máº¥t Ä‘á»‹nh vá»‹ hoÃ n toÃ n do khÃ´ng cÃ³ cáº£m biáº¿n há»— trá»£.';
        db.run('INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)',
            [vehicleId, s.accountId, 'GPS_JAMMING', msg, 'HIGH']);
        pushSSE(vehicleId, { type: 'MODE_CHANGE', mode: s.mode, isJammed: false, isJammedV1: true, ts: Date.now() });
        res.json({ isJammed: false, isJammedV1: true, mode: s.mode, message: msg });
    } else {
        s.isJammed = true;
        s.isJammedV1 = false;
        s.mode = 'DEAD_RECKONING';
        s.jammedSince = Date.now();
        const msg = '[Cáº¢NH BÃO] PhÃ¡t hiá»‡n nhiá»…u GPS xe #' + vehicleId + '! V2 (CÃ³ báº£o máº­t): Äang dÃ¹ng Dead Reckoning + Wi-Fi Fingerprinting Ä‘á»ƒ tiáº¿p tá»¥c theo dÃµi an toÃ n.';
        db.run('INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)',
            [vehicleId, s.accountId, 'GPS_JAMMING', msg, 'MEDIUM']);
        pushSSE(vehicleId, { type: 'MODE_CHANGE', mode: s.mode, isJammed: true, isJammedV1: false, ts: Date.now() });
        res.json({ isJammed: true, isJammedV1: false, mode: s.mode, message: msg });
    }
});

// â”€â”€ V3 API: Giáº£ láº­p cáº¡y phÃ¡ pháº§n cá»©ng + Zeroization â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.post('/api/v2/vehicles/simulate-tampering', (req, res) => {
    const { vehicleId } = req.body;
    const s = gpsState[vehicleId];
    if (!s) return res.status(404).json({ error: 'PhiÃªn GPS khÃ´ng hoáº¡t Ä‘á»™ng.' });

    const tamperPayload = JSON.stringify({ vehicleId, event: 'HARDWARE_TAMPER', ts: Date.now() });
    const tamperHmac = crypto.createHmac('sha256', TELEMATICS_SECRET).update(tamperPayload).digest('hex');

    // === ZEROIZATION: XÃ³a tráº¯ng toÃ n bá»™ khÃ³a máº­t mÃ£ trong bá»™ nhá»› ===
    if (s.dek) { s.dek.fill(0); s.dek = null; }
    s.dekWrappedForServer = null;
    s.isTampered = true; s.isLocked = true;
    if (s.intervalId) { clearInterval(s.intervalId); s.intervalId = null; }

    pushSSE(vehicleId, {
        type: 'HARDWARE_TAMPER', vehicleId,
        message: 'ðŸš¨ PHÃT HIá»†N XÃ‚M NHáº¬P PHáº¦N Cá»¨NG! Zeroization thá»±c thi â€” DEK vÃ  khÃ³a RSA Ä‘Ã£ xÃ³a tráº¯ng. Xe bá»‹ khÃ³a vÄ©nh viá»…n.',
        hmac: tamperHmac, zeroized: true, ts: Date.now()
    });

    const alertMsg = `[ðŸš¨ KHáº¨N Cáº¤P] Cáº¡y phÃ¡ pháº§n cá»©ng xe #${vehicleId}! Zeroization: DEK xÃ³a tráº¯ng. HMAC cáº£nh bÃ¡o: ${tamperHmac.slice(0,16)}...`;
    db.run(`INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)`,
        [vehicleId, s.accountId, 'HARDWARE_TAMPER', alertMsg, 'CRITICAL']);
    db.run(`UPDATE Rentals SET Status = 'Emergency_Terminated' WHERE VehicleID = ? AND Status = 'Active'`, [vehicleId]);
    db.run(`UPDATE Vehicles SET Status = 'Lockout' WHERE VehicleID = ?`, [vehicleId]);

    res.json({ zeroized: true, vehicleLocked: true, hmac: tamperHmac, message: alertMsg });
});

// â”€â”€ V3 API: KhÃ³a Ä‘á»™ng cÆ¡ tá»« xa (HMAC + Timestamp chá»‘ng Replay) â”€â”€
app.post('/api/v2/vehicles/lock-engine', verifyTokenV2, (req, res) => {
    const { vehicleId, timestamp, signature, userLat, userLon } = req.body;
    const now = Date.now();

    // [1] Kiá»ƒm tra tÃ­nh má»›i cá»§a lá»‡nh (chá»‘ng táº¥n cÃ´ng phÃ¡t láº¡i)
    if (!timestamp || Math.abs(now - parseInt(timestamp)) > 30000) {
        db.run(`INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)`,
            [vehicleId, req.user.AccountID, 'REPLAY_ATTACK',
             `Táº¥n cÃ´ng phÃ¡t láº¡i lá»‡nh khÃ³a xe #${vehicleId}! Äá»™ lá»‡ch: ${Math.abs(now - parseInt(timestamp))}ms > 30000ms`, 'HIGH']);
        return res.status(400).json({ error: '[V3-REPLAY] Tá»« chá»‘i: Timestamp lá»‡nh quÃ¡ cÅ© â€” táº¥n cÃ´ng phÃ¡t láº¡i (Replay Attack). Lá»‡nh pháº£i trong vÃ²ng 30 giÃ¢y.' });
    }

    // [2] XÃ¡c thá»±c chá»¯ kÃ½ HMAC-SHA256
    const expected = crypto.createHmac('sha256', TELEMATICS_SECRET)
        .update(`LOCK_ENGINE:${vehicleId}:${timestamp}`).digest('hex');
    if (signature !== expected) return res.status(403).json({ error: '[V3] Chá»¯ kÃ½ HMAC lá»‡nh khÃ³a Ä‘á»™ng cÆ¡ khÃ´ng há»£p lá»‡!' });

    const s = gpsState[vehicleId];

    // Kiá»ƒm tra khoáº£ng cÃ¡ch chá»§ xe (Proximity Verification) Ä‘á»ƒ chá»‘ng Relay Attack
    if (s && userLat !== undefined && userLon !== undefined) {
        const distKm = haversineKm(parseFloat(userLat), parseFloat(userLon), s.lat, s.lon);
        if (distKm > 0.1) { // 100 meters
            const alertMsg = `ðŸš¨ PHÃT HIá»†N Táº¤N CÃ”NG RELAY: YÃªu cáº§u khÃ³a Ä‘á»™ng cÆ¡ kháº©n cáº¥p xe #${vehicleId} bá»‹ tá»« chá»‘i do chá»§ xe á»Ÿ quÃ¡ xa (${(distKm*1000).toFixed(0)}m > 100m).`;
            db.run(`INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)`,
                [vehicleId, req.user.AccountID, 'RELAY_ATTACK_DETECTION', alertMsg, 'HIGH']);
            return res.status(403).json({ error: `[Báº¢O Máº¬T] Tá»« chá»‘i lá»‡nh: Khoáº£ng cÃ¡ch quÃ¡ xa (${(distKm*1000).toFixed(0)}m > 100m). Nghi ngá» táº¥n cÃ´ng láº·p tÃ­n hiá»‡u (Relay Attack).` });
        }
    }

    // [3] Thá»±c thi khÃ³a Ä‘á»™ng cÆ¡
    if (s) {
        s.isLocked = true;
        s.speed = 0;
        s.mode = 'LOCKED';
        startGpsLoop(vehicleId);
        pushSSE(vehicleId, { type: 'ENGINE_LOCKED', vehicleId, lockedBy: req.user.Username, ts: now });
    }

    db.run(`UPDATE Vehicles SET Status = 'Locked' WHERE VehicleID = ?`, [vehicleId]);
    db.run(`INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)`,
        [vehicleId, req.user.AccountID, 'ENGINE_LOCK',
         `Äá»™ng cÆ¡ xe #${vehicleId} bá»‹ khÃ³a tá»« xa bá»Ÿi ${req.user.Username}. Timestamp: ${timestamp}. Chá»‘ng Replay: âœ…`, 'MEDIUM']);

    res.json({ message: `Xe #${vehicleId} Ä‘Ã£ bá»‹ khÃ³a Ä‘á»™ng cÆ¡ tá»« xa thÃ nh cÃ´ng! Váº­n tá»‘c Ä‘Æ°a vá» 0.`, lockedAt: now, lockedBy: req.user.Username });
});

// â”€â”€ V3 API: Sinh chá»¯ kÃ½ lá»‡nh khÃ³a Ä‘á»™ng cÆ¡ (UI helper) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.post('/api/v2/vehicles/generate-lock-signature', verifyTokenV2, (req, res) => {
    const { vehicleId } = req.body;
    const timestamp = Date.now();
    const signature = crypto.createHmac('sha256', TELEMATICS_SECRET)
        .update(`LOCK_ENGINE:${vehicleId}:${timestamp}`).digest('hex');
    res.json({ vehicleId, timestamp, signature, expiresInMs: 30000, note: 'Chá»¯ kÃ½ háº¿t háº¡n sau 30 giÃ¢y â€” chá»‘ng táº¥n cÃ´ng phÃ¡t láº¡i' });
});

// â”€â”€ V3 API: Xem táº¥t cáº£ cáº£nh bÃ¡o báº£o máº­t â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.get('/api/v2/security/alerts', verifyTokenV2, (req, res) => {
    db.all(`SELECT * FROM SecurityAlerts ORDER BY AlertID DESC LIMIT 50`, (err, rows) => {
        res.json(rows || []);
    });
});

// â”€â”€ V3 API: Tráº¡ng thÃ¡i GPS táº¥t cáº£ xe (Admin Dashboard) â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.get('/api/v2/vehicles/gps-all', (req, res) => {
    res.json(Object.values(gpsState).map(s => ({
        vehicleId: s.vehicleId,
        lat: s.isJammedV1 ? null : +s.lat.toFixed(5),
        lon: s.isJammedV1 ? null : +s.lon.toFixed(5),
        speed: s.isJammedV1 ? 0 : +s.speed.toFixed(1),
        heading: s.isJammedV1 ? 0 : +s.heading.toFixed(1),
        mode: s.isJammedV1 ? 'LOST_GPS' : s.mode,
        isJammed: s.isJammed || false,
        isJammedV1: s.isJammedV1 || false,
        isLocked: s.isLocked,
        isTampered: s.isTampered,
        geofenceViolating: s.isJammedV1 ? false : s.geofenceViolating,
        clientCount: s.clients.size,
        geofence: s.geofence,
        routeType: s.routeType || 'hanoi'
    })));
});

// â”€â”€ V3 DB API: Xem báº£ng SecurityAlerts â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.get('/api/db/alerts', (req, res) => {
    db.all(`SELECT * FROM SecurityAlerts ORDER BY AlertID DESC LIMIT 50`, (err, rows) => {
        res.json(rows || []);
    });
});

// â”€â”€ V3 API: Tuyáº¿n Ä‘Æ°á»ng vÃ  Äiá»ƒm Æ°u tiÃªn (POIs) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.get('/api/v2/vehicles/route', (req, res) => {
    const { vehicleId } = req.query;
    let activeRoute = HANOI_ROUTE;
    
    if (vehicleId && gpsState[vehicleId]) {
        activeRoute = gpsState[vehicleId].route;
    }
    
    res.json({ 
        hanoiRoute: HANOI_ROUTE,
        northVietnamRoute: NORTH_VIETNAM_ROUTE,
        airportRoute: AIRPORT_ROUTE,
        route: activeRoute, 
        center: { lat: 21.028, lon: 105.834 }, 
        name: 'HÃ  Ná»™i â€” VÃ²ng Trung TÃ¢m',
        pois: DEALERSHIPS
    });
});

// Endpoint thay Ä‘á»•i tuyáº¿n Ä‘Æ°á»ng cho xe
app.post('/api/v2/vehicles/change-route', (req, res) => {
    const { vehicleId, routeType } = req.body;
    const s = gpsState[vehicleId];
    if (!s) return res.status(404).json({ error: 'PhiÃªn GPS khÃ´ng hoáº¡t Ä‘á»™ng cho xe nÃ y.' });

    s.routeType = routeType || 'hanoi';
    if (s.routeType === 'north_vietnam') {
        s.route = NORTH_VIETNAM_ROUTE;
    } else if (s.routeType === 'airport') {
        s.route = AIRPORT_ROUTE;
    } else {
        s.route = HANOI_ROUTE;
    }
    
    // Äáº·t láº¡i Ä‘iá»ƒm xuáº¥t phÃ¡t ngáº«u nhiÃªn trÃªn tuyáº¿n má»›i
    const startIdx = Math.floor(Math.random() * (s.route.length - 1));
    s.routeIndex = startIdx;
    s.lat = s.route[startIdx].lat;
    s.lon = s.route[startIdx].lon;
    s.path = [{ lat: s.lat, lon: s.lon, ts: Date.now() }];
    s.heading = calcBearing(s.lat, s.lon, s.route[startIdx+1].lat, s.route[startIdx+1].lon);
    
    // Ghi nháº­n cáº£nh bÃ¡o an ninh vá» viá»‡c Ä‘á»•i tuyáº¿n Ä‘Æ°á»ng
    db.run('INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)',
        [vehicleId, s.accountId, 'GEOFENCE_SET', 'Thay Ä‘á»•i lá»™ trÃ¬nh Xe #' + vehicleId + ' sang ' + (s.routeType === 'north_vietnam' ? 'VÃ²ng Quanh Miá»n Báº¯c' : s.routeType === 'airport' ? 'SÃ¢n Bay Ná»™i BÃ i' : 'HÃ  Ná»™i VÃ²ng Trung TÃ¢m'), 'INFO']);
    
    // Gá»­i bÃ¡o cÃ¡o Ä‘á»•i tuyáº¿n qua SSE
    const report = {
        type: 'periodic_report',
        message: `Xe #${vehicleId} Ä‘Ã£ chuyá»ƒn sang lá»™ trÃ¬nh: ${s.routeType === 'airport' ? 'SÃ¢n Bay Ná»™i BÃ i' : s.routeType === 'north_vietnam' ? 'VÃ nh Äai 3' : 'Ná»™i ThÃ nh HÃ  Ná»™i'}.`,
        timestamp: new Date().toISOString()
    };
    sendGpsSSE(vehicleId, 'report', report);
    
    res.json({ 
        success: true, 
        routeType: s.routeType, 
        message: 'ÄÃ£ Ä‘á»•i lá»™ trÃ¬nh Xe #' + vehicleId + ' thÃ nh cÃ´ng.' 
    });
});

// Endpoint Ä‘á»ƒ GiÃ¡o viÃªn/Admin test tÃ­nh nÄƒng gá»­i bÃ¡o cÃ¡o 1 giá» ngay láº­p tá»©c
app.post('/api/v2/vehicles/force-report', async (req, res) => {
    const { vehicleId } = req.body;
    const s = gpsState[vehicleId];
    if (!s || s.isTampered) return res.status(404).json({ error: 'Xe khÃ´ng hoáº¡t Ä‘á»™ng.' });
    
    const address = await reverseGeocode(s.lat, s.lon);
    const reportMsg = `ðŸ“ BÃO CÃO HÃ€NH TRÃŒNH Tá»”NG Há»¢P (1 GIá»œ) - XE #${vehicleId}:
- VÄ© Ä‘á»™: ${s.lat.toFixed(6)}
- Kinh Ä‘á»™: ${s.lon.toFixed(6)}
- Vá»‹ trÃ­ hiá»‡n táº¡i: ${address}
- Tá»‘c Ä‘á»™ trung bÃ¬nh: ${Math.round(s.speed)} km/h
- Tráº¡ng thÃ¡i an ninh: á»”n Ä‘á»‹nh (Chá»‘ng phÃ¡ sÃ³ng hoáº¡t Ä‘á»™ng tá»‘t)`;

    const report = {
        type: 'periodic_report',
        vehicleId: vehicleId,
        message: reportMsg,
        timestamp: new Date().toISOString()
    };
    sendGpsSSE(vehicleId, 'report', report);
    
    res.json({ success: true, message: 'ÄÃ£ gá»­i bÃ¡o cÃ¡o thá»§ cÃ´ng qua SSE thÃ nh cÃ´ng!' });
});

// â”€â”€ V3 API: Äáº·t giá»›i háº¡n hÃ nh trÃ¬nh (Route Boundary) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Giá»›i háº¡n xe chá»‰ Ä‘Æ°á»£c di chuyá»ƒn tá»« Ä‘iá»ƒm xuáº¥t phÃ¡t Ä‘áº¿n bÃ¡n kÃ­nh nháº¥t Ä‘á»‹nh trong thá»i gian X phÃºt
app.post('/api/v2/vehicles/set-trip-limit', (req, res) => {
    const { vehicleId, fromLat, fromLon, fromName, toLat, toLon, toName, limitMinutes, radiusKm } = req.body;
    const s = gpsState[vehicleId];
    if (!s) return res.status(404).json({ error: 'PhiÃªn GPS khÃ´ng hoáº¡t Ä‘á»™ng cho xe nÃ y.' });
    if (!limitMinutes || limitMinutes <= 0) return res.status(400).json({ error: 'Thá»i gian giá»›i háº¡n khÃ´ng há»£p lá»‡.' });

    const now = Date.now();
    s.tripLimit = {
        enabled: true,
        fromLat: fromLat || s.lat,
        fromLon: fromLon || s.lon,
        fromName: fromName || 'Äiá»ƒm xuáº¥t phÃ¡t',
        toLat: toLat || null,
        toLon: toLon || null,
        toName: toName || 'Äiá»ƒm Ä‘áº¿n',
        limitMinutes: parseInt(limitMinutes),
        radiusKm: parseFloat(radiusKm) || 15,  // BÃ¡n kÃ­nh vÃ¹ng hÃ nh trÃ¬nh cho phÃ©p (km)
        startedAt: now,
        endsAt: now + parseInt(limitMinutes) * 60 * 1000,
        violated: false,
        lastTripAlertTime: 0
    };

    db.run('INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)',
        [vehicleId, s.accountId, 'GEOFENCE_SET',
         `Äáº·t giá»›i háº¡n hÃ nh trÃ¬nh Xe #${vehicleId}: Tá»« "${s.tripLimit.fromName}" â†’ "${s.tripLimit.toName}" | BÃ¡n kÃ­nh: ${s.tripLimit.radiusKm}km | Thá»i gian: ${limitMinutes} phÃºt`,
         'INFO']);

    res.json({
        success: true,
        vehicleId,
        tripLimit: {
            fromName: s.tripLimit.fromName,
            toName: s.tripLimit.toName,
            limitMinutes: s.tripLimit.limitMinutes,
            radiusKm: s.tripLimit.radiusKm,
            endsAt: s.tripLimit.endsAt
        },
        message: `ÄÃ£ Ä‘áº·t giá»›i háº¡n hÃ nh trÃ¬nh thÃ nh cÃ´ng cho Xe #${vehicleId}.`
    });
});

// â”€â”€ V3 API: XÃ³a giá»›i háº¡n hÃ nh trÃ¬nh â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.post('/api/v2/vehicles/clear-trip-limit', (req, res) => {
    const { vehicleId } = req.body;
    const s = gpsState[vehicleId];
    if (!s) return res.status(404).json({ error: 'PhiÃªn GPS khÃ´ng hoáº¡t Ä‘á»™ng cho xe nÃ y.' });

    s.tripLimit = null;
    db.run('INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)',
        [vehicleId, s.accountId, 'GEOFENCE_SET',
         `XÃ³a giá»›i háº¡n hÃ nh trÃ¬nh Xe #${vehicleId} â€” Xe Ä‘Æ°á»£c di chuyá»ƒn tá»± do.`,
         'INFO']);

    res.json({ success: true, vehicleId, message: `ÄÃ£ xÃ³a giá»›i háº¡n hÃ nh trÃ¬nh Xe #${vehicleId}.` });
});

// â”€â”€ V3 API: Tráº¡ng thÃ¡i GPS táº¥t cáº£ xe kÃ¨m thÃ´ng tin giá»›i háº¡n hÃ nh trÃ¬nh â”€â”€
// (Cáº­p nháº­t láº¡i endpoint gps-all cÅ©)

// =========================================================
// PHáº¦N 4: API DÃ€NH RIÃŠNG CHO TRANG TEST (ChÆ°Æ¡ng 3 Demo)

// 5. API Lá»˜ TRÃŒNH VÃ€ Cáº¢NH BÃO ÄI NGÆ¯á»¢C
app.get('/api/test/routes', (req, res) => {
    let routesData = [];
    for (let vid in gpsState) {
        if (gpsState[vid] && !gpsState[vid].isTampered) {
            routesData.push({
                vehicleId: vid,
                route: gpsState[vid].route
            });
        }
    }
    res.json(routesData);
});

app.post('/api/test/reverse-car', (req, res) => {
    const vid = req.body.vehicleId;
    const st = gpsState[vid];
    if (!st) return res.status(404).json({ error: "Xe khÃ´ng hoáº¡t Ä‘á»™ng hoáº·c khÃ´ng tÃ¬m tháº¥y." });
    
    st.isReversing = !st.isReversing;
    
    if (st.isReversing) {
        // Láº¥y thÃ´ng tin chá»§ xe
        db.get(`SELECT FullName FROM Accounts WHERE AccountID = ?`, [st.accountId], (err, user) => {
            const ownerName = user ? user.FullName : 'KhÃ´ng rÃµ';
            const logMsg = `[Cáº¢NH BÃO AN NINH - CRITICAL] PhÃ¡t hiá»‡n Xe ID: ${vid} di chuyá»ƒn NGÆ¯á»¢C CHIá»€U vá»›i lá»™ trÃ¬nh Ä‘Äƒng kÃ½! ÄÃ£ gá»­i SMS cáº£nh bÃ¡o Ä‘áº¿n chá»§ xe (${ownerName}) vÃ  trung tÃ¢m Ä‘iá»u hÃ nh.`;
            db.run(`INSERT INTO SystemLogs (Description) VALUES (?)`, [logMsg]);
            res.json({ message: `ÄÃ£ kÃ­ch hoáº¡t cháº¿ Ä‘á»™ Ä‘i lÃ¹i (Reverse) cho xe ${vid}. ÄÃ£ gá»­i cáº£nh bÃ¡o.`, isReversing: true });
        });
    } else {
        const logMsg = `[THÃ”NG BÃO] Xe ID: ${vid} Ä‘Ã£ quay láº¡i lá»™ trÃ¬nh bÃ¬nh thÆ°á»ng.`;
        db.run(`INSERT INTO SystemLogs (Description) VALUES (?)`, [logMsg]);
        res.json({ message: `ÄÃ£ táº¯t cháº¿ Ä‘á»™ Ä‘i lÃ¹i cho xe ${vid}. Xe hoáº¡t Ä‘á»™ng bÃ¬nh thÆ°á»ng.`, isReversing: false });
    }
});


app.post('/api/test/restore', async (req, res) => {
    try {
        await resetDatabase();
        res.json({ message: "ÄÃ£ khÃ´i phá»¥c toÃ n bá»™ dá»¯ liá»‡u há»‡ thá»‘ng (Database & GPS) thÃ nh cÃ´ng!" });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/test/live-gps', (req, res) => {
    db.all(`SELECT * FROM VehicleGPS`, (err, rows) => {
        res.json(rows || []);
    });
});

// =========================================================

// 1. Ká»ŠCH Báº¢N IDOR (Turo)
app.get('/api/v1/test/rental/:id', (req, res) => {
    // V1: Lá»—i IDOR - KhÃ´ng kiá»ƒm tra quyá»n, truyá»n ID nÃ o xem ID Ä‘Ã³
    db.get(`SELECT * FROM Rentals WHERE RentalID = ?`, [req.params.id], (err, row) => {
        if (!row) return res.status(404).json({ error: "KhÃ´ng tÃ¬m tháº¥y há»£p Ä‘á»“ng" });
        db.get(`SELECT Username, FullName, Phone, Email FROM Accounts WHERE AccountID = ?`, [row.AccountID], (err, user) => {
            res.json({ message: "[V1] Lá»— há»•ng IDOR khai thÃ¡c thÃ nh cÃ´ng! ÄÃ£ láº¥y cáº¯p PII ngÆ°á»i khÃ¡c.", data: { rental: row, pii: user } });
        });
    });
});

app.get('/api/v2/test/rental/:id', (req, res) => {
    // V2: Báº­t RBAC (MÃ´ phá»ng check quyá»n, á»Ÿ Ä‘Ã¢y ta fake tÃ i khoáº£n khÃ¡ch lÃ  ID 99)
    const currentUserId = 99; // Mock user Ä‘ang Ä‘Äƒng nháº­p
    db.get(`SELECT * FROM Rentals WHERE RentalID = ?`, [req.params.id], (err, row) => {
        if (!row) return res.status(404).json({ error: "KhÃ´ng tÃ¬m tháº¥y há»£p Ä‘á»“ng" });
        if (row.AccountID !== currentUserId) {
            const logMsg = `[CVSS v4.0 Score: 8.7 - CRITICAL] Cháº·n Ä‘á»©ng táº¥n cÃ´ng IDOR! NgÆ°á»i dÃ¹ng ${currentUserId} cá»‘ gáº¯ng truy cáº­p há»£p Ä‘á»“ng ${req.params.id} trÃ¡i phÃ©p.`;
            db.run(`INSERT INTO SystemLogs (Description) VALUES (?)`, [logMsg]);
            return res.status(403).json({ error: "Access Denied: Bá»‹ cháº·n bá»Ÿi RBAC. Báº¡n khÃ´ng pháº£i chá»§ sá»Ÿ há»¯u há»£p Ä‘á»“ng nÃ y.", cvss: "Score: 8.7 - CRITICAL" });
        }
        res.json({ data: row });
    });
});

// 2. Ká»ŠCH Báº¢N SQL INJECTION
app.post('/api/v1/test/sqli', (req, res) => {
    // V1: Lá»—i SQLi ná»‘i chuá»—i (Dump Ä‘Æ°á»£c cáº£ PasswordHash Ä‘á»ƒ tÄƒng tÃ­nh chÃ¢n thá»±c)
    const username = req.body.username || '';
    const query = `SELECT Username, PasswordHash, Role FROM Accounts WHERE Username = '${username}'`;
    db.all(query, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ 
            message: "[V1] Khai thÃ¡c SQL Injection (Auth Bypass) thÃ nh cÃ´ng!", 
            action_taken: "ChÃ¨n payload ' OR 1=1 -- Ä‘á»ƒ thay Ä‘á»•i logic xÃ¡c thá»±c cá»§a CSDL.",
            impact: "Bypass cÆ¡ cháº¿ Ä‘Äƒng nháº­p, Dump Ä‘Æ°á»£c toÃ n bá»™ thÃ´ng tin tÃ i khoáº£n bao gá»“m cáº£ Hash máº­t kháº©u.",
            data_exfiltrated: rows 
        });
    });
});

app.post('/api/v2/test/sqli', (req, res) => {
    // V2: WAF cháº·n mÃ£ Ä‘á»™c trÆ°á»›c khi vÃ o DB
    const username = req.body.username || '';
    if (username.toUpperCase().includes('OR 1=1') || username.includes('--')) {
        const logMsg = `[CVSS v4.0 Score: 9.8 - CRITICAL] WAF cháº·n Ä‘á»©ng SQL Injection vá»›i payload: ${username}`;
        db.run(`INSERT INTO SystemLogs (Description) VALUES (?)`, [logMsg]);
        return res.status(403).json({ error: "WAF Blocked: PhÃ¡t hiá»‡n dáº¥u hiá»‡u SQL Injection.", cvss: "Score: 9.8 - CRITICAL" });
    }
    db.get(`SELECT Username, Role FROM Accounts WHERE Username = ?`, [username], (err, row) => {
        res.json({ data: row || "User not found" });
    });
});


// 3. Ká»ŠCH Báº¢N UPLOAD MÃƒ Äá»˜C
app.post('/api/v1/test/upload', (req, res) => {
    // V1: KhÃ´ng kiá»ƒm tra Ä‘á»‹nh dáº¡ng tá»‡p (Magic Bytes), thá»±c sá»± táº¡o ra má»™t file mÃ£ Ä‘á»™c
    const fs = require('fs');
    const path = require('path');
    const uploadDir = path.join(__dirname, 'uploads');
    
    // Äáº£m báº£o thÆ° má»¥c uploads tá»“n táº¡i
    if (!fs.existsSync(uploadDir)){
        fs.mkdirSync(uploadDir);
    }
    
    const shellFile = path.join(uploadDir, 'shell.php');
    const maliciousCode = '<?php echo "HACKED BY ANONYMOUS"; system($_GET["cmd"]); ?>';
    
    fs.writeFileSync(shellFile, maliciousCode);
    
    res.json({ 
        message: "[V1] Táº£i tá»‡p shell.php lÃªn mÃ¡y chá»§ thÃ nh cÃ´ng! Há»‡ thá»‘ng Ä‘Ã£ bá»‹ chiáº¿m quyá»n Ä‘iá»u khiá»ƒn (RCE).",
        file_path: "/uploads/shell.php",
        note: "Báº¡n cÃ³ thá»ƒ kiá»ƒm tra thÆ° má»¥c 'uploads' trong dá»± Ã¡n, file shell.php Ä‘Ã£ thá»±c sá»± Ä‘Æ°á»£c táº¡o ra!"
    });
});

app.post('/api/v2/test/upload', (req, res) => {
    // V2: QuÃ©t Magic Bytes / TÆ°á»ng lá»­a WAF
    const logMsg = `[CVSS v4.0 Score: 9.8 - CRITICAL] WAF cháº·n Ä‘á»©ng ná»— lá»±c táº£i lÃªn mÃ£ Ä‘á»™c (shell.php). Tá»‡p khÃ´ng pháº£i lÃ  hÃ¬nh áº£nh há»£p lá»‡ (Sai Magic Bytes).`;
    db.run(`INSERT INTO SystemLogs (Description) VALUES (?)`, [logMsg]);
    res.status(403).json({ 
        error: "WAF Blocked: Tá»‡p táº£i lÃªn bá»‹ tá»« chá»‘i do chá»©a mÃ£ Ä‘á»™c hoáº·c sai Ä‘á»‹nh dáº¡ng (Magic Bytes khÃ´ng khá»›p).", 
        cvss: "Score: 9.8 - CRITICAL"
    });
});

// 4. Ká»ŠCH Báº¢N BRUTE-FORCE
app.post('/api/v1/test/bruteforce', (req, res) => {
    // V1: KhÃ´ng cÃ³ Rate Limiting, cho phÃ©p dÃ² máº­t kháº©u thoáº£i mÃ¡i
    // Láº¥y thá»­ 1 user tá»« DB Ä‘á»ƒ show ra cho ngáº§u
    db.get(`SELECT Username, PasswordHash FROM Accounts LIMIT 1`, (err, row) => {
        const hash = row ? row.PasswordHash : "$2b$10$w.../dummy";
        const user = row ? row.Username : "admin";
        
        res.json({ 
            message: `[V1] Táº¥n cÃ´ng Brute-force thÃ nh cÃ´ng! ÄÃ£ gá»­i 50,000 requests trong 2.5s. Há»‡ thá»‘ng khÃ´ng cÃ³ Rate Limiting.`,
            cracked_account: {
                username: user,
                found_password: "password123",
                original_hash: hash.substring(0, 30) + "..."
            },
            server_impact: "CPU Usage Spiked to 99%"
        });
    });
});

app.post('/api/v2/test/bruteforce', (req, res) => {
    // V2: Báº­t Rate Limiting
    const logMsg = `[CVSS v4.0 Score: 5.3 - MEDIUM] Há»‡ thá»‘ng cháº·n Ä‘á»‹a chá»‰ IP 192.168.1.100 do gá»­i quÃ¡ nhiá»u yÃªu cáº§u Ä‘Äƒng nháº­p (Rate Limit Exceeded).`;
    db.run(`INSERT INTO SystemLogs (Description) VALUES (?)`, [logMsg]);
    res.status(429).json({ 
        error: "429 Too Many Requests: Báº¡n Ä‘Ã£ gá»­i quÃ¡ nhiá»u yÃªu cáº§u trong thá»i gian ngáº¯n. Äá»‹a chá»‰ IP Ä‘Ã£ bá»‹ khÃ³a táº¡m thá»i.", 
        cvss: "Score: 5.3 - MEDIUM"
    });
});

// 3. Ká»ŠCH Báº¢N VIPR WIPE (Há»™p Ä‘en)
app.post('/api/v1/test/vipr-wipe', (req, res) => {
    // V1: KhÃ´ng xÃ¡c thá»±c
    const vid = req.body.vehicleId || 2;
    const command = req.body.command || "WIPE_ALL";
    const bypassMode = req.body.bypassMode || "CAN_INJECTION";

    db.run(`UPDATE VehicleInfotainment SET GPSHistory = '[]', SyncedContacts = '[]', ActiveBluetoothDevice = 'Ngáº¯t káº¿t ná»‘i (Offline)' WHERE VehicleID = ?`, [vid], (err) => {
        // Láº¥y vá»‹ trÃ­ vÃ  tá»‘c Ä‘á»™ hiá»‡n táº¡i cá»§a xe Ä‘á»ƒ bÃ¡o cÃ¡o lÃªn frontend cho chá»§ xe
        db.get(`SELECT Address, Speed FROM VehicleGPS WHERE VehicleID = ?`, [vid], (err, row) => {
            const address = row ? row.Address : "KhÃ´ng xÃ¡c Ä‘á»‹nh";
            const speed = row ? row.Speed : 0;
            const alertMsg = `Xe bá»‹ táº¥n cÃ´ng. Vá»‹ trÃ­ hiá»‡n táº¡i: ${address}. Tá»‘c Ä‘á»™: ${speed} km/h.`;
            
            db.run(`INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?, ?, ?, ?, ?)`, 
                [vid, 1, 'SYSTEM_ALERT', alertMsg, 'HIGH']);
        });
            
        res.json({ 
            message: `[V1] Khai thÃ¡c Unauthenticated Remote Command Execution thÃ nh cÃ´ng trÃªn xe #${vid}!`,
            action_taken: `Gá»­i gÃ³i tin giáº£ máº¡o qua giao thá»©c ${bypassMode} vá»›i lá»‡nh ${command}.`,
            impact: "Bypass cÆ¡ cháº¿ xÃ¡c thá»±c TCU. ToÃ n bá»™ Danh báº¡, Lá»‹ch sá»­ GPS vÃ  Káº¿t ná»‘i Bluetooth hiá»‡n táº¡i Ä‘Ã£ bá»‹ XÃ“A TRáº®NG.",
            tcu_status: "WIPED"
        });
    });
});

app.post('/api/v2/test/vipr-wipe', (req, res) => {
    // V2: Check chá»¯ kÃ½ sá»‘ VIPR
    const sig = req.body.signature;
    if (!sig || sig === 'invalid') {
        const logMsg = `[CVSS v4.0 Score: 8.2 - HIGH] Há»‡ thá»‘ng VIPR cháº·n lá»‡nh Ä‘iá»u khiá»ƒn xe giáº£ máº¡o do sai Chá»¯ kÃ½ sá»‘ (Digital Signature).`;
        db.run(`INSERT INTO SystemLogs (Description) VALUES (?)`, [logMsg]);
        return res.status(401).json({ error: "VIPR System: Lá»‡nh bá»‹ tá»« chá»‘i do khÃ´ng cÃ³ chá»¯ kÃ½ mÃ£ hÃ³a há»£p lá»‡.", cvss: "Score: 8.2 - HIGH" });
    }
    res.json({ message: "Lá»‡nh há»£p lá»‡." });
});

// 4. Ká»ŠCH Báº¢N FIRMWARE DUMP (Há»™p Ä‘en)
app.get('/api/v1/test/firmware-dump', (req, res) => {
    // V1: Dump Firmware Plaintext
    const fs = require('fs');
    const path = require('path');
    
    // Äá»c Private Key thá»±c táº¿ Ä‘ang sá»­ dá»¥ng
    let privateKeyContent = "BEGIN RSA PRIVATE KEY... [KhÃ³a cá»©ng bá»‹ lá»™]";
    try {
        const keyPath = path.join(__dirname, 'private.pem');
        if (fs.existsSync(keyPath)) {
            privateKeyContent = fs.readFileSync(keyPath, 'utf-8');
            // Ghi ra thÆ° má»¥c gá»‘c file dump_firmware_extracted_keys.txt
            fs.writeFileSync(path.join(__dirname, 'dump_firmware_extracted_keys.txt'), privateKeyContent);
        }
    } catch(e) {}
    
    res.json({ 
        message: "[V1] Dump qua JTAG thÃ nh cÃ´ng! Hacker Ä‘Ã£ trÃ­ch xuáº¥t Ä‘Æ°á»£c Firmware tá»« bá»™ nhá»› Flash.", 
        firmware_bytes: "0x4A 0x4D 0x50...",
        hardcoded_keys: { rsa_private_key: privateKeyContent.substring(0, 100) + "..." },
        note: "Má»™t file 'dump_firmware_extracted_keys.txt' chá»©a Private Key tháº­t cá»§a mÃ¡y chá»§ Ä‘Ã£ Ä‘Æ°á»£c táº¡o ra á»Ÿ thÆ° má»¥c dá»± Ã¡n Ä‘á»ƒ chá»©ng minh cuá»™c táº¥n cÃ´ng thÃ nh cÃ´ng!"
    });
});

app.get('/api/v2/test/firmware-dump', (req, res) => {
    // V2: Firmware bá»‹ mÃ£ hÃ³a (Secure Boot)
    const logMsg = `[CVSS v4.0 Score: 7.9 - HIGH] Cháº·n Ä‘á»©ng ná»— lá»±c dump JTAG. Bá»™ nhá»› Flash Ä‘Ã£ Ä‘Æ°á»£c mÃ£ hÃ³a AES-256.`;
    db.run(`INSERT INTO SystemLogs (Description) VALUES (?)`, [logMsg]);
    res.status(403).json({ 
        error: "Secure Flash Error: Dá»¯ liá»‡u Ä‘Ã£ bá»‹ mÃ£ hÃ³a pháº§n cá»©ng. Cáº§n Key Ä‘á»ƒ giáº£i mÃ£.", 
        cvss: "Score: 7.9 - HIGH",
        firmware_bytes: "0x8F 0x9A 0x22... (ENCRYPTED)"
    });
});

// 8. Ká»ŠCH Báº¢N GPS V1 vs V2 (KhÃ´ng mÃ£ hÃ³a vs AES-256-GCM)
app.get('/api/v1/test/gps-stream', (req, res) => {
    // V1: GPS plaintext â€” khÃ´ng mÃ£ hÃ³a, khÃ´ng xÃ¡c thá»±c
    const vehicleId = parseInt(req.query.vehicleId) || 2;
    db.get(`SELECT * FROM VehicleGPS WHERE VehicleID = ?`, [vehicleId], (err, gps) => {
        if (!gps) return res.status(404).json({ error: 'KhÃ´ng tÃ¬m tháº¥y xe' });

        const logMsg = `[CVSS 9.1 CRITICAL] GPS V1: Dá»¯ liá»‡u vá»‹ trÃ­ xe #${vehicleId} bá»‹ lá»™ plaintext â€” khÃ´ng mÃ£ hÃ³a, khÃ´ng xÃ¡c thá»±c.`;
        db.run(`INSERT INTO SystemLogs (Description) VALUES (?)`, [logMsg]);

        res.json({
            message: "[V1] GPS KHÃ”NG MÃƒ HÃ“A â€” Dá»¯ liá»‡u truyá»n plaintext qua HTTP!",
            vehicle_id: vehicleId,
            protocol: "HTTP/1.1 â€” PLAINTEXT",
            encryption: "NONE âŒ",
            auth: "NONE âŒ",
            cvss: "9.1 CRITICAL",
            // Lá»™ toÃ n bá»™ dá»¯ liá»‡u thÃ´
            raw_gps_packet: {
                lat: gps.Lat,
                lon: gps.Lon,
                speed: gps.Speed,
                heading: gps.Heading,
                address: gps.Address,
                timestamp: gps.Timestamp
            },
            warning: "âš ï¸ Báº¥t ká»³ káº» táº¥n cÃ´ng nÃ o nghe lÃ©n máº¡ng (MITM) Ä‘á»u tháº¥y toÃ n bá»™ vá»‹ trÃ­ vÃ  tá»‘c Ä‘á»™ cá»§a xe theo thá»i gian thá»±c!"
        });
    });
});

app.get('/api/v2/test/gps-stream', (req, res) => {
    // V2: GPS AES-256-GCM Envelope Encryption
    const vehicleId = parseInt(req.query.vehicleId) || 2;
    db.get(`SELECT * FROM VehicleGPS WHERE VehicleID = ?`, [vehicleId], (err, gps) => {
        if (!gps) return res.status(404).json({ error: 'KhÃ´ng tÃ¬m tháº¥y xe' });

        const crypto = require('crypto');

        // Sinh DEK ngáº«u nhiÃªn cho phiÃªn nÃ y (giá»‘ng V3 GPS engine thá»±c)
        const dek = crypto.randomBytes(32);
        const iv  = crypto.randomBytes(12);

        // MÃ£ hÃ³a gÃ³i tin GPS báº±ng AES-256-GCM
        const plaintext = JSON.stringify({ lat: gps.Lat, lon: gps.Lon, speed: gps.Speed, heading: gps.Heading, address: gps.Address });
        const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv);
        let encrypted = cipher.update(plaintext, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag().toString('hex');

        // Bá»c DEK báº±ng RSA Public Key (Envelope Encryption)
        const wrappedDek = crypto.publicEncrypt(
            { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
            dek
        ).toString('base64').substring(0, 40) + '...[RSA-OAEP-SHA256]';

        dek.fill(0); // Zeroize DEK sau khi dÃ¹ng

        const logMsg = `[PROTECTED] GPS V2: Vá»‹ trÃ­ xe #${vehicleId} Ä‘Æ°á»£c mÃ£ hÃ³a AES-256-GCM + DEK bá»c RSA.`;
        db.run(`INSERT INTO SystemLogs (Description) VALUES (?)`, [logMsg]);

        res.json({
            message: "[V2] GPS MÃƒ HÃ“A â€” Envelope Encryption AES-256-GCM + RSA-OAEP-SHA256",
            vehicle_id: vehicleId,
            protocol: "HTTPS/TLS 1.3 â€” ENCRYPTED",
            encryption: "AES-256-GCM âœ…",
            auth: "JWT HttpOnly Cookie + DEK Envelope âœ…",
            key_management: "Envelope Encryption (DEK bá»c báº±ng RSA-OAEP-SHA256)",
            security: {
                wrapped_dek: wrappedDek,
                iv: iv.toString('hex'),
                auth_tag: authTag,
                encrypted_gps_payload: encrypted.substring(0, 60) + "...[ENCRYPTED]"
            },
            note: "ðŸ” Káº» táº¥n cÃ´ng MITM chá»‰ tháº¥y chuá»—i hex vÃ´ nghÄ©a. Chá»‰ owner cÃ³ Private Key má»›i giáº£i mÃ£ Ä‘Æ°á»£c. DEK Ä‘Ã£ bá»‹ Zeroize sau khi dÃ¹ng (Forward Secrecy)."
        });
    });
});

