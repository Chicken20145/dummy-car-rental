const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto'); 

const app = express();
app.use(express.json());

// =========================================================
// TẠO CẶP KHÓA RSA (Cho Kịch bản 4)
// =========================================================
// Tạo khóa công khai (Public Key) và khóa bí mật (Private Key) độ dài 2048-bit
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

// =========================================================
// PHẦN 1: KHỞI TẠO CƠ SỞ DỮ LIỆU SQLITE
// =========================================================
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) console.error(err.message);
    console.log('Đã kết nối với CSDL SQLite.');
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS Accounts (AccountID INTEGER PRIMARY KEY AUTOINCREMENT, Username TEXT, PasswordHash TEXT, Role TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS Vehicles (VehicleID INTEGER PRIMARY KEY AUTOINCREMENT, LicensePlate TEXT, Model TEXT, Status TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS SystemLogs (LogID INTEGER PRIMARY KEY AUTOINCREMENT, Description TEXT, Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)`);
    // Bảng mới cho Kịch bản 4
    db.run(`CREATE TABLE IF NOT EXISTS UserDocuments (DocID INTEGER PRIMARY KEY AUTOINCREMENT, AccountID INTEGER, LicenseData TEXT, IsEncrypted BOOLEAN)`);

    db.run(`DELETE FROM Accounts`);
    db.run(`DELETE FROM Vehicles`);
    db.run(`DELETE FROM SystemLogs`);
    db.run(`DELETE FROM UserDocuments`);
    
    db.run(`INSERT INTO Accounts (Username, PasswordHash, Role) VALUES ('admin', 'hashed_pass_1', 'Admin'), ('user1', 'hashed_pass_2', 'User')`);
    db.run(`INSERT INTO Vehicles (LicensePlate, Model, Status) VALUES ('29A-12345', 'Toyota Vios', 'Available')`);
    db.run(`INSERT INTO SystemLogs (Description) VALUES ('Hệ thống khởi động thành công')`);
});

// =========================================================
// API XEM DATABASE DÙNG ĐỂ ĐỐI CHỨNG
// =========================================================
app.get('/api/db/accounts', (req, res) => { db.all(`SELECT * FROM Accounts`, (err, rows) => res.json(rows)); });
app.get('/api/db/vehicles', (req, res) => { db.all(`SELECT * FROM Vehicles`, (err, rows) => res.json(rows)); });
app.get('/api/db/logs', (req, res) => { db.all(`SELECT * FROM SystemLogs`, (err, rows) => res.json(rows)); });
app.get('/api/db/documents', (req, res) => { db.all(`SELECT * FROM UserDocuments`, (err, rows) => res.json(rows)); });


// =========================================================
// PHẦN 2: CÁC API PHIÊN BẢN V1 - LỖI (VULNERABLE)
// =========================================================

// KB1 (Lỗi SQLi): Nối chuỗi trực tiếp
app.post('/api/v1/messages/admin', (req, res) => {
    const userMessage = req.body.Message;
    const query = `SELECT * FROM SystemLogs WHERE Description LIKE '%${userMessage}%'`;
    db.all(query, (err, rows) => { res.json(rows); });
});

// KB2 (Lỗi Phân quyền): Không kiểm tra Role Admin
const verifyTokenV1 = (req, res, next) => {
    req.user = { AccountID: 2, Username: 'user1', Role: 'User' }; 
    next();
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
app.use('/api/v2/', helmet());
app.use('/api/v2/', rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

// KB1 (Bảo mật SQLi): Dùng Parameterized Queries
app.post('/api/v2/messages/admin', (req, res) => {
    const userMessage = req.body.Message;
    const query = `SELECT * FROM SystemLogs WHERE Description LIKE?`;
    db.all(query, [`%${userMessage}%`], (err, rows) => { res.json(rows); });
});

// KB2 (Bảo mật Phân quyền): Kiểm tra Role Admin
const verifyTokenAndAdminV2 = (req, res, next) => {
    req.user = { AccountID: 2, Username: 'user1', Role: 'User' };
    if (req.user.Role!== 'Admin') {
        return res.status(403).json({ error: "[V2] Bị từ chối: Cần quyền Admin." });
    }
    next();
};
app.delete('/api/v2/admin/vehicles/delete', verifyTokenAndAdminV2, (req, res) => {
    db.run(`DELETE FROM Vehicles WHERE VehicleID =?`, (err) => {
        res.send(`[V2] Đã xóa an toàn.`);
    });
});

// KB3 (Bảo mật Upload): Lọc đuôi tệp bằng Regex và đổi tên ngẫu nhiên
const storageV2 = multer.diskStorage({
  destination: (req, file, cb) => { cb(null, 'uploads/') },
  filename: (req, file, cb) => { 
      const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
      cb(null, "V2_" + uniqueSuffix + path.extname(file.originalname));
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
app.post('/api/v2/upload-license', uploadSecure.single('license_image'), (req, res) => {
  res.send("[V2] Tải ảnh lên an toàn!");
});

// KB4 (Bảo mật PII): Mã hóa dữ liệu (Encryption) bằng RSA-2048 trước khi lưu
app.post('/api/v2/user/document', (req, res) => {
    const licenseData = req.body.LicenseNumber;
    
    // Mã hóa dữ liệu bằng Public Key với chuẩn padding RSA_PKCS1_OAEP_PADDING an toàn
    const encryptedBuffer = crypto.publicEncrypt({
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
    }, Buffer.from(licenseData));
    
    // Chuyển sang chuỗi Base64 để lưu vào CSDL
    const ciphertext = encryptedBuffer.toString('base64');

    db.run(`INSERT INTO UserDocuments (AccountID, LicenseData, IsEncrypted) VALUES (?,?,?)`, [2, ciphertext, true], (err) => {
        res.send("[V2] Đã mã hóa RSA và lưu dữ liệu PII thành công.");
    });
});

// (Tùy chọn) API giải mã chỉ dành cho Admin nội bộ hệ thống để xem dữ liệu thật
app.post('/api/v2/admin/decrypt-document', (req, res) => {
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