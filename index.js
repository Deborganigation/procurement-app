// ================== DEPENDENCIES ==================
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const xlsx = require('xlsx');
const fs = require('fs');
const sgMail = require('@sendgrid/mail');
require('dotenv').config();

// ================== INITIALIZATION ==================
const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// ===== FIX: Serve index.html for the root URL ('Cannot GET /' error) =====
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ================== DATABASE POOL ==================
const dbPool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    port: process.env.DB_PORT,
    waitForConnections: true,
    connectionLimit: 20,
    queueLimit: 0,
    dateStrings: true,
    ssl: {
        rejectUnauthorized: false
    }
});

// ================== FILE STORAGE ==================
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = 'uploads/';
        if (!fs.existsSync(dir)){ fs.mkdirSync(dir, { recursive: true }); }
        cb(null, dir);
    },
    filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname.replace(/\s/g, '_')}`)
});
const upload = multer({ storage });
const excelUpload = multer({ storage: multer.memoryStorage() });

// ================== AUTH MIDDLEWARE ==================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.status(401).json({ success: false, message: 'Unauthorized: No token provided' });
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, message: 'Forbidden: Invalid token' });
        req.user = user;
        next();
    });
};
const isAdmin = (req, res, next) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ success: false, message: 'Forbidden: Admin access required' });
    next();
};

// ================== API ROUTES ==================

// --- 1. AUTH & USER MANAGEMENT ---
app.post('/api/login', async (req, res, next) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password are required.' });
        
        const [rows] = await dbPool.query('SELECT * FROM users WHERE email = ? AND is_active = 1', [email]);
        if (rows.length === 0) return res.status(401).json({ success: false, message: 'Invalid credentials or account inactive.' });
        
        const user = rows[0];
        if (!user.password_hash) {
            return res.status(500).json({ success: false, message: 'Server configuration error. Please contact admin.' });
        }

        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) return res.status(401).json({ success: false, message: 'Invalid credentials.' });

        const payload = { userId: user.user_id, role: user.role, fullName: user.full_name, email: user.email };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '8h' });
        
        const forceReset = !!user.force_password_reset;
        
        delete user.password_hash;
        res.json({ success: true, token, user, forceReset });
    } catch (error) {
        console.error("LOGIN_ERROR_DETAIL:", error); // For debugging
        next(error);
    }
});

app.post('/api/register', async (req, res, next) => {
    try {
        const { FullName, Email, Password, Role, CompanyName, ContactNumber, GSTIN } = req.body;
        const hashedPassword = await bcrypt.hash(Password, 10);
        await dbPool.query('INSERT INTO pending_users (full_name, email, password, role, company_name, contact_number, gstin) VALUES (?, ?, ?, ?, ?, ?, ?)', [FullName, Email, hashedPassword, Role, CompanyName, ContactNumber, GSTIN]);
        res.status(201).json({ success: true, message: 'Registration successful! Awaiting admin approval.' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') return res.status(400).json({ success: false, message: 'This email is already registered.' });
        next(error);
    }
});

// --- 2. REQUISITIONS & FILE UPLOADS ---
app.get('/api/dropdowns/locations', authenticateToken, (req, res) => {
    res.json({ success: true, data: ["Dhulaghar", "Kharagpur", "Dankuni", "Kolkata"] });
});

const anyUpload = upload.any();
app.post('/api/requisitions', authenticateToken, anyUpload, async (req, res, next) => {
    const connection = await dbPool.getConnection();
    try {
        const { vendorIds, items } = req.body;
        if (!items) return res.status(400).json({ success: false, message: 'No items provided in the requisition.' });

        const parsedItems = JSON.parse(items);
        const parsedVendorIds = JSON.parse(vendorIds);
        
        await connection.beginTransaction();
        const [reqResult] = await connection.query('INSERT INTO requisitions (created_by, status) VALUES (?, ?)', [req.user.userId, 'Pending Approval']);
        const reqId = reqResult.insertId;

        for (const [i, item] of parsedItems.entries()) {
            const drawingFile = req.files.find(f => f.fieldname === `drawing_${i}`);
            const specimenFile = req.files.find(f => f.fieldname === `specimen_${i}`);
            const drawingUrl = drawingFile ? `/uploads/${drawingFile.filename}` : null;
            const specimenUrl = specimenFile ? `/uploads/${specimenFile.filename}` : null;

            await connection.query('INSERT INTO requisition_items (requisition_id, item_sl_no, item_name, item_code, description, quantity, unit, freight_required, delivery_location, drawing_url, specimen_url, status, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', 
            [reqId, i + 1, item.ItemName, item.ItemCode, item.Description, item.Quantity, item.Unit, item.FreightRequired, item.DeliveryLocation, drawingUrl, specimenUrl, 'Pending Approval', req.user.userId]);
        }

        if (parsedVendorIds && parsedVendorIds.length > 0) {
            for (const vId of parsedVendorIds) await connection.query('INSERT INTO requisition_assignments (requisition_id, vendor_id) VALUES (?, ?)', [reqId, vId]);
        }
        await connection.commit();
        res.status(201).json({ success: true, message: 'Requisition submitted successfully!' });
    } catch (error) {
        await connection.rollback();
        next(error);
    } finally {
        connection.release();
    }
});

app.get('/api/requisitions/my-status', authenticateToken, async (req, res, next) => {
    try {
        const [myReqs] = await dbPool.query('SELECT * FROM requisitions WHERE created_by = ? ORDER BY requisition_id DESC', [req.user.userId]);
        if (myReqs.length === 0) return res.json({ success: true, data: [] });

        const reqIds = myReqs.map(r => r.requisition_id);
        const [items] = await dbPool.query(
            `SELECT ri.*, ac.awarded_amount, u.full_name as awarded_vendor 
             FROM requisition_items ri 
             LEFT JOIN awarded_contracts ac ON ri.item_id = ac.item_id 
             LEFT JOIN users u ON ac.vendor_id = u.user_id 
             WHERE ri.requisition_id IN (?) ORDER BY ri.item_sl_no ASC`, [reqIds]
        );
        
        const finalData = myReqs.map(req => ({
            ...req,
            items: items.filter(item => item.requisition_id === req.requisition_id)
        }));
        res.json({ success: true, data: finalData });
    } catch (error) {
        next(error);
    }
});

// --- 3. VENDOR FEATURES ---
app.get('/api/requirements/assigned', authenticateToken, async (req, res, next) => {
    try {
        const query = `
            SELECT 
                ri.*, 
                b.bid_status AS my_bid_status, 
                b.bid_amount AS my_bid_amount,
                b.ex_works_rate AS my_ex_works_rate,
                b.freight_rate AS my_freight_rate,
                (SELECT COUNT(*) + 1 FROM bids WHERE item_id = ri.item_id AND bid_amount < b.bid_amount) AS my_rank
            FROM requisition_items ri
            JOIN requisition_assignments ra ON ri.requisition_id = ra.requisition_id
            LEFT JOIN bids b ON ri.item_id = b.item_id AND b.vendor_id = ?
            WHERE ra.vendor_id = ? AND ri.status = 'Active'
            ORDER BY ri.requisition_id DESC, ri.item_sl_no ASC`;
        const [items] = await dbPool.query(query, [req.user.userId, req.user.userId]);
        res.json({ success: true, data: items });
    } catch(error) {
        next(error);
    }
});

app.post('/api/bids', authenticateToken, async (req, res, next) => {
    if (req.user.role !== 'Vendor') return res.status(403).json({ success: false, message: 'Forbidden' });
    
    const { bids } = req.body;
    const connection = await dbPool.getConnection();
    try {
        await connection.beginTransaction();
        for (const bid of bids) {
            const [[countResult]] = await connection.query('SELECT COUNT(*) as count FROM bidding_history_log WHERE item_id = ? AND vendor_id = ?', [bid.item_id, req.user.userId]);
            if (countResult.count >= 3) {
                 await connection.rollback();
                 return res.status(403).json({ success: false, message: `You have reached the maximum of 3 bids for this item.` });
            }

            await connection.query('DELETE FROM bids WHERE item_id = ? AND vendor_id = ?', [bid.item_id, req.user.userId]);
            const [result] = await connection.query('INSERT INTO bids (item_id, vendor_id, bid_amount, ex_works_rate, freight_rate, comments, bid_status) VALUES (?, ?, ?, ?, ?, ?, ?)', [bid.item_id, req.user.userId, bid.bid_amount, bid.ex_works_rate, bid.freight_rate, bid.comments, 'Submitted']);
            
            await connection.query('INSERT INTO bidding_history_log (bid_id, item_id, vendor_id, bid_amount, ex_works_rate, freight_rate, bid_status) VALUES (?, ?, ?, ?, ?, ?, ?)', [result.insertId, bid.item_id, req.user.userId, bid.bid_amount, bid.ex_works_rate, bid.freight_rate, 'Submitted']);
        }
        await connection.commit();
        res.json({ success: true, message: 'Bids submitted successfully!' });
    } catch (error) {
        await connection.rollback();
        next(error);
    } finally {
        connection.release();
    }
});

app.get('/api/vendor/dashboard-stats', authenticateToken, async (req, res, next) => {
    try {
        const [[assigned]] = await dbPool.query("SELECT COUNT(DISTINCT ri.item_id) as count FROM requisition_items ri JOIN requisition_assignments ra ON ri.requisition_id = ra.requisition_id WHERE ra.vendor_id = ? AND ri.status = 'Active'", [req.user.userId]);
        const [[submitted]] = await dbPool.query("SELECT COUNT(*) as count FROM bids WHERE vendor_id = ?", [req.user.userId]);
        const [[won]] = await dbPool.query("SELECT COUNT(*) as count FROM awarded_contracts WHERE vendor_id = ?", [req.user.userId]);
        res.json({
            success: true,
            data: {
                assignedItems: assigned.count,
                submittedBids: submitted.count,
                contractsWon: won.count
            }
        });
    } catch (error) {
        next(error);
    }
});

app.get('/api/vendor/my-bids', authenticateToken, async (req, res, next) => {
    try {
        const query = `
            SELECT b.*, ri.item_name, ri.requisition_id, ri.item_sl_no, 
                   (SELECT COUNT(*) + 1 FROM bids live_bids WHERE live_bids.item_id = b.item_id AND live_bids.bid_amount < b.bid_amount) AS 'rank' 
            FROM bids b 
            JOIN requisition_items ri ON b.item_id = ri.item_id 
            WHERE b.vendor_id = ? 
            ORDER BY b.submitted_at DESC`;
        const [bids] = await dbPool.query(query, [req.user.userId]);
        res.json({ success: true, data: bids });
    } catch (error) {
        next(error);
    }
});

app.get('/api/vendor/my-awarded-contracts', authenticateToken, async (req, res, next) => {
    try {
        const [contracts] = await dbPool.query(
            'SELECT ac.*, ri.item_name, ri.requisition_id, ri.item_sl_no FROM awarded_contracts ac JOIN requisition_items ri ON ac.item_id = ri.item_id WHERE ac.vendor_id = ? ORDER BY ac.awarded_date DESC', [req.user.userId]
        );
        res.json({ success: true, data: contracts });
    } catch (error) {
        next(error);
    }
});


// --- 4. ADMIN FEATURES ---
app.get('/api/admin/dashboard-stats', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const [[activeItems]] = await dbPool.query("SELECT COUNT(*) as count FROM requisition_items WHERE status = 'Active'");
        const [[pendingUsers]] = await dbPool.query("SELECT COUNT(*) as count FROM pending_users");
        const [[submittedBids]] = await dbPool.query("SELECT COUNT(*) as count FROM bids WHERE bid_status = 'Submitted'");
        const [[awarded]] = await dbPool.query("SELECT COUNT(*) as count FROM awarded_contracts");
        const [pendingReqs] = await dbPool.query("SELECT ri.item_name, ri.requisition_id, ri.item_sl_no, ri.created_at, u.full_name FROM requisition_items ri JOIN users u ON ri.created_by = u.user_id WHERE ri.status = 'Pending Approval' ORDER BY ri.item_id DESC LIMIT 5");
        const [recentBids] = await dbPool.query("SELECT b.bid_amount, u.full_name as vendor_name, ri.item_name, b.submitted_at FROM bids b JOIN users u ON b.vendor_id = u.user_id JOIN requisition_items ri ON b.item_id = ri.item_id ORDER BY b.submitted_at DESC LIMIT 5");

        res.json({
            success: true,
            data: { activeItems: activeItems.count, pendingUsers: pendingUsers.count, submittedBids: submittedBids.count, awardedContracts: awarded.count, pendingRequisitions: pendingReqs, recentBids: recentBids }
        });
    } catch (error) {
        next(error);
    }
});

app.get('/api/requirements/pending', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const query = `
          SELECT r.requisition_id, r.created_at, u.full_name as creator,
          (SELECT GROUP_CONCAT(u2.user_id, ':', u2.full_name SEPARATOR '||') FROM requisition_assignments ra JOIN users u2 ON ra.vendor_id = u2.user_id WHERE ra.requisition_id = r.requisition_id) as suggested_vendors
          FROM requisitions r JOIN users u ON r.created_by = u.user_id WHERE r.status = 'Pending Approval' GROUP BY r.requisition_id ORDER BY r.requisition_id DESC`;
        const [groupedReqs] = await dbPool.query(query);
        const [pendingItems] = await dbPool.query("SELECT * FROM requisition_items WHERE status = 'Pending Approval'");
        const [allVendors] = await dbPool.query("SELECT user_id, full_name FROM users WHERE role = 'Vendor' AND is_active = 1");
        res.json({ success: true, data: { groupedReqs, pendingItems, allVendors } });
    } catch (error) {
        next(error);
    }
});

app.post('/api/requisitions/approve', authenticateToken, isAdmin, async (req, res, next) => {
    const { approvedItemIds, vendorAssignments, requisitionId } = req.body;
    const connection = await dbPool.getConnection();
    try {
        await connection.beginTransaction();
        if (approvedItemIds && approvedItemIds.length > 0) {
            await connection.query('UPDATE requisition_items SET status = "Active" WHERE item_id IN (?)', [approvedItemIds]);
        }
        await connection.query('UPDATE requisitions SET status = "Processed" WHERE requisition_id = ?', [requisitionId]);
        if (vendorAssignments) {
            await connection.query('DELETE FROM requisition_assignments WHERE requisition_id = ?', [requisitionId]);
            if(vendorAssignments.length > 0) {
                for(const vendorId of vendorAssignments) {
                    await connection.query('INSERT INTO requisition_assignments (requisition_id, vendor_id) VALUES (?, ?)', [requisitionId, vendorId]);
                }
            }
        }
        await connection.commit();
        res.json({ success: true, message: 'Requisition items processed!' });
    } catch(error) {
        await connection.rollback();
        next(error);
    } finally {
        connection.release();
    }
});

app.get('/api/requirements/active', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const query = `
            SELECT 
                ri.*, 
                (SELECT MIN(b.bid_amount) FROM bids b WHERE b.item_id = ri.item_id) as l1_rate, 
                (SELECT u.full_name FROM bids b JOIN users u ON b.vendor_id = u.user_id WHERE b.item_id = ri.item_id ORDER BY b.bid_amount ASC LIMIT 1) as l1_vendor,
                (SELECT GROUP_CONCAT(u_assign.full_name SEPARATOR ', ') 
                 FROM requisition_assignments ra 
                 JOIN users u_assign ON ra.vendor_id = u_assign.user_id 
                 WHERE ra.requisition_id = ri.requisition_id) as assigned_vendors
            FROM requisition_items ri 
            WHERE ri.status IN ('Active', 'Bidding Closed') 
            ORDER BY ri.requisition_id DESC, ri.item_sl_no ASC`;
        const [items] = await dbPool.query(query);
        res.json({ success: true, data: items });
    } catch (error) {
        next(error);
    }
});

app.get('/api/items/:id/bids', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const [bids] = await dbPool.query(`SELECT b.*, u.full_name as vendor_name, u.email as vendor_email FROM bids b JOIN users u ON b.vendor_id = u.user_id WHERE b.item_id = ? ORDER BY b.bid_amount ASC`, [req.params.id]);
        const [[itemDetails]] = await dbPool.query('SELECT requisition_id, item_sl_no FROM requisition_items WHERE item_id = ?', [req.params.id]);
        res.json({ success: true, data: { bids, ...itemDetails } });
    } catch (error) {
        next(error);
    }
});

app.post('/api/admin/bids-for-items', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const { itemIds } = req.body;
        if (!itemIds || itemIds.length === 0) return res.status(400).json({ success: false, message: "No item IDs provided" });
        
        const [items] = await dbPool.query(`SELECT item_id, item_name, requisition_id, item_sl_no FROM requisition_items WHERE item_id IN (?)`, [itemIds]);
        const [bids] = await dbPool.query(`SELECT b.*, u.full_name as vendor_name, u.email as vendor_email FROM bids b JOIN users u ON b.vendor_id = u.user_id WHERE b.item_id IN (?) AND b.bid_status = 'Submitted' ORDER BY b.item_id, b.bid_amount ASC`, [itemIds]);
        
        const responseData = items.map(item => ({
            ...item,
            bids: bids.filter(bid => bid.item_id === item.item_id)
        }));

        res.json({ success: true, data: responseData });
    } catch (error) {
        next(error);
    }
});

app.post('/api/contracts/award', authenticateToken, isAdmin, async (req, res, next) => {
    const { bids } = req.body;
    const connection = await dbPool.getConnection();
    try {
        await connection.beginTransaction();
        for (const bid of bids) {
            await connection.query('UPDATE requisition_items SET status = ? WHERE item_id = ?', ['Awarded', bid.item_id]);
            await connection.query('UPDATE bids SET bid_status = ? WHERE bid_id = ?', ['Awarded', bid.bid_id]);
            await connection.query('UPDATE bids SET bid_status = ? WHERE item_id = ? AND bid_id != ?', ['Rejected', bid.item_id, bid.bid_id]);
            
            await connection.query(
                'INSERT INTO awarded_contracts (item_id, requisition_id, vendor_id, awarded_amount, remarks) VALUES (?, ?, ?, ?, ?)', 
                [bid.item_id, bid.requisition_id, bid.vendor_id, bid.bid_amount, bid.remarks]
            );
        }
        await connection.commit();
        res.json({ success: true, message: 'Contracts awarded successfully!' });
    } catch (error) {
        await connection.rollback();
        next(error);
    } finally {
        connection.release();
    }
});

app.get('/api/admin/awarded-contracts', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const query = `
            SELECT ac.*, ri.item_name, ri.item_code, ri.quantity, ri.unit, ri.item_sl_no, u.full_name as vendor_name
            FROM awarded_contracts ac
            JOIN requisition_items ri ON ac.item_id = ri.item_id
            JOIN users u ON ac.vendor_id = u.user_id
            ORDER BY ac.awarded_date DESC`;
        const [contracts] = await dbPool.query(query);
        res.json({ success: true, data: contracts });
    } catch (error) {
        next(error);
    }
});

app.post('/api/admin/reports-data', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const { startDate, endDate } = req.body;
        let dateFilter = '';
        const params = [];

        if (startDate && endDate) {
            dateFilter = ' WHERE ac.awarded_date BETWEEN ? AND ?';
            params.push(startDate, endDate);
        }

        const kpiQuery = `
            SELECT
                SUM(ac.awarded_amount) AS totalSpend,
                (SELECT SUM(l2.bid_amount - ac_inner.awarded_amount)
                    FROM awarded_contracts ac_inner
                    JOIN (
                        SELECT item_id, bid_amount
                        FROM (
                            SELECT item_id, bid_amount, ROW_NUMBER() OVER(PARTITION BY item_id ORDER BY bid_amount ASC) as rn
                            FROM bids
                        ) ranked_bids
                        WHERE rn = 2
                    ) l2 ON ac_inner.item_id = l2.item_id
                    ${startDate && endDate ? 'WHERE ac_inner.awarded_date BETWEEN ? AND ?' : ''}
                ) AS costSavings,
                AVG(DATEDIFF(ac.awarded_date, ri.created_at)) as avgCycleTime,
                (SELECT AVG(bid_counts.num_bids) FROM (SELECT COUNT(bid_id) as num_bids FROM bids GROUP BY item_id) bid_counts) as avgBids
            FROM awarded_contracts ac
            JOIN requisition_items ri ON ac.item_id = ri.item_id
            ${dateFilter}`;
        
        const kpiParams = (startDate && endDate) ? [startDate, endDate, ...params] : [...params];

        const vendorSpendQuery = `
            SELECT u.full_name, SUM(ac.awarded_amount) as total
            FROM awarded_contracts ac
            JOIN users u ON ac.vendor_id = u.user_id
            ${dateFilter}
            GROUP BY u.full_name
            ORDER BY total DESC`;

        const itemStatusQuery = `SELECT status, COUNT(*) as count FROM requisition_items GROUP BY status`;
        
        const [kpiResult, vendorSpendResult, itemStatusResult] = await Promise.all([
            dbPool.query(kpiQuery, kpiParams),
            dbPool.query(vendorSpendQuery, params),
            dbPool.query(itemStatusQuery)
        ]);

        const kpis = kpiResult[0][0];

        res.json({
            success: true,
            data: {
                kpis: {
                    totalSpend: kpis.totalSpend || 0,
                    costSavings: kpis.costSavings || 0,
                    avgCycleTime: kpis.avgCycleTime || 0,
                    avgBids: kpis.avgBids || 0
                },
                spendByVendor: {
                    labels: vendorSpendResult[0].map(v => v.full_name),
                    data: vendorSpendResult[0].map(v => v.total)
                },
                itemStatusCounts: {
                    labels: itemStatusResult[0].map(s => s.status),
                    data: itemStatusResult[0].map(s => s.count)
                }
            }
        });

    } catch (error) {
        next(error);
    }
});

app.post('/api/items/reopen-bidding', authenticateToken, isAdmin, async (req, res, next) => {
    const { itemIds, vendorIds, remarks } = req.body;
    const connection = await dbPool.getConnection();
    try {
        await connection.beginTransaction();
        await connection.query('UPDATE requisition_items SET status = "Active" WHERE item_id IN (?)', [itemIds]);
        await connection.query('UPDATE awarded_contracts SET remarks = CONCAT(IFNULL(remarks, ""), ?) WHERE item_id IN (?)', [`\nRe-opened: ${remarks}`, itemIds]);
        
        const [items] = await connection.query('SELECT DISTINCT requisition_id FROM requisition_items WHERE item_id IN (?)', [itemIds]);
        const requisitionIds = items.map(i => i.requisition_id);

        for (const reqId of requisitionIds) {
            await connection.query('DELETE FROM requisition_assignments WHERE requisition_id = ?', [reqId]);
            if (vendorIds && vendorIds.length > 0) {
                for(const vendorId of vendorIds) {
                    await connection.query('INSERT INTO requisition_assignments (requisition_id, vendor_id) VALUES (?, ?)', [reqId, vendorId]);
                }
            }
        }
        await connection.commit();
        res.json({ success: true, message: 'Bidding re-opened successfully.' });
    } catch(error) {
        await connection.rollback();
        next(error);
    } finally {
        connection.release();
    }
});

app.post('/api/requisitions/bulk-upload', authenticateToken, isAdmin, excelUpload.single('bulkFile'), async (req, res, next) => {
    if (!req.file) return res.status(400).json({ success: false, message: 'No Excel file uploaded.' });
    
    let parsedVendorIds = [];
    try {
        if (req.body.vendorIds) parsedVendorIds = JSON.parse(req.body.vendorIds);
    } catch (e) {
        return res.status(400).json({ success: false, message: 'Invalid vendor data.' });
    }

    const connection = await dbPool.getConnection();
    try {
        const workbook = xlsx.read(req.file.buffer, { type: 'buffer' });
        const items = xlsx.utils.sheet_to_json(workbook.Sheets[workbook.SheetNames[0]]);
        if (items.length === 0) return res.status(400).json({ success: false, message: 'Excel file is empty or invalid.' });

        await connection.beginTransaction();
        const [reqResult] = await connection.query('INSERT INTO requisitions (created_by, status) VALUES (?, ?)', [req.user.userId, 'Pending Approval']);
        const reqId = reqResult.insertId;

        for (const [i, item] of items.entries()) {
            await connection.query(
                'INSERT INTO requisition_items (requisition_id, item_sl_no, item_name, item_code, description, quantity, unit, freight_required, delivery_location, status, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [reqId, i + 1, item.ItemName, item.ItemCode, item.Description, item.Quantity, item.Unit, (String(item.FreightRequired).toLowerCase() === 'yes'), item.DeliveryLocation, 'Pending Approval', req.user.userId]
            );
        }

        if (parsedVendorIds && parsedVendorIds.length > 0) {
            for (const vId of parsedVendorIds) await connection.query('INSERT INTO requisition_assignments (requisition_id, vendor_id) VALUES (?, ?)', [reqId, vId]);
        }
        await connection.commit();
        res.status(201).json({ success: true, message: `${items.length} items uploaded and submitted successfully!` });

    } catch (error) {
        await connection.rollback();
        next(error);
    } finally {
        connection.release();
    }
});

app.get('/api/admin/bidding-history', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const [bids] = await dbPool.query(`
            SELECT bhl.*, u.full_name as vendor_name, ri.item_name, ri.requisition_id, ri.item_sl_no
            FROM bidding_history_log bhl
            JOIN users u ON bhl.vendor_id = u.user_id
            JOIN requisition_items ri ON bhl.item_id = ri.item_id
            ORDER BY bhl.submitted_at DESC
        `);
        res.json({ success: true, data: bids });
    } catch (error) {
        next(error);
    }
});

app.get('/api/requisitions/:id/assignments', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const { id } = req.params;
        const [allVendors] = await dbPool.query("SELECT user_id, full_name FROM users WHERE role = 'Vendor' AND is_active = 1 ORDER BY full_name");
        const [assignedResult] = await dbPool.query("SELECT vendor_id FROM requisition_assignments WHERE requisition_id = ?", [id]);
        const assignedVendorIds = assignedResult.map(a => a.vendor_id);
        res.json({ success: true, data: { allVendors, assignedVendorIds } });
    } catch (error) {
        next(error);
    }
});

app.put('/api/requisitions/:id/assignments', authenticateToken, isAdmin, async (req, res, next) => {
    const connection = await dbPool.getConnection();
    try {
        const { id } = req.params;
        const { vendorIds } = req.body;
        
        await connection.beginTransaction();
        await connection.query('DELETE FROM requisition_assignments WHERE requisition_id = ?', [id]);
        if (vendorIds && vendorIds.length > 0) {
            const values = vendorIds.map(vId => [id, vId]);
            await connection.query('INSERT INTO requisition_assignments (requisition_id, vendor_id) VALUES ?', [values]);
        }
        await connection.commit();
        res.json({ success: true, message: 'Vendor assignments updated successfully.' });
    } catch (error) {
        await connection.rollback();
        next(error);
    } finally {
        connection.release();
    }
});

// --- 5. USER MANAGEMENT & UTILITIES ---
app.get('/api/users/pending', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const [rows] = await dbPool.query(`SELECT * FROM pending_users ORDER BY temp_id DESC`);
        res.json({ success: true, data: rows });
    } catch (error) {
        next(error);
    }
});

app.post('/api/users/approve', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const { temp_id } = req.body;
        const [[pendingUser]] = await dbPool.query('SELECT * FROM pending_users WHERE temp_id = ?', [temp_id]);
        if (!pendingUser) return res.status(404).json({ success: false, message: 'User not found' });
        await dbPool.query('INSERT INTO users (full_name, email, password_hash, role, company_name, contact_number, gstin) VALUES (?, ?, ?, ?, ?, ?, ?)', [pendingUser.full_name, pendingUser.email, pendingUser.password, pendingUser.role, pendingUser.company_name, pendingUser.contact_number, pendingUser.gstin]);
        await dbPool.query('DELETE FROM pending_users WHERE temp_id = ?', [temp_id]);
        res.json({ success: true, message: 'User approved!' });
    } catch (error) {
        next(error);
    }
});

app.get('/api/users', authenticateToken, async (req, res, next) => {
    try {
        const [rows] = await dbPool.query(`SELECT user_id, full_name, email, role, company_name, contact_number, gstin, is_active FROM users ORDER BY full_name`);
        res.json({ success: true, data: rows });
    } catch (error) {
        next(error);
    }
});

app.get('/api/users/vendors', authenticateToken, async (req, res, next) => {
    try {
        const [vendors] = await dbPool.query("SELECT user_id, full_name FROM users WHERE role = 'Vendor' AND is_active = 1");
        res.json({ success: true, data: vendors });
    } catch (error) {
        next(error);
    }
});

app.put('/api/users/:id', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const { id } = req.params;
        const { full_name, email, role, company_name, contact_number, gstin, password } = req.body;
        let query = 'UPDATE users SET full_name=?, email=?, role=?, company_name=?, contact_number=?, gstin=?';
        let params = [full_name, email, role, company_name, contact_number, gstin];
        
        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            query += ', password_hash=?, force_password_reset=?';
            params.push(hashedPassword, true);
        }
        
        query += ' WHERE user_id=?';
        params.push(id);
        
        await dbPool.query(query, params);
        res.json({ success: true, message: 'User updated successfully' });
    } catch (error) {
        next(error);
    }
});

app.post('/api/users/add', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const { full_name, email, password, role, company_name, contact_number, gstin } = req.body;
        if (!full_name || !email || !password || !role) {
            return res.status(400).json({ success: false, message: 'Name, email, password, and role are required.'});
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        await dbPool.query(
            'INSERT INTO users (full_name, email, password_hash, role, company_name, contact_number, gstin, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [full_name, email, hashedPassword, role, company_name, contact_number, gstin, 1]
        );
        res.status(201).json({ success: true, message: 'User created successfully.' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') return res.status(400).json({ success: false, message: 'This email is already registered.' });
        next(error);
    }
});

app.post('/api/users/set-password', authenticateToken, async (req, res, next) => {
    try {
        const { newPassword } = req.body;
        if (!newPassword || newPassword.length < 4) {
             return res.status(400).json({ success: false, message: 'Password is too short.' });
        }
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await dbPool.query(
            'UPDATE users SET password_hash = ?, force_password_reset = ? WHERE user_id = ?',
            [hashedPassword, false, req.user.userId]
        );
        res.json({ success: true, message: 'Password updated successfully.' });
    } catch(error) {
        next(error);
    }
});

// --- 6. MESSAGING API ---
app.post('/api/messages', authenticateToken, async (req, res, next) => {
    try {
        const { recipientId, messageBody } = req.body;
        await dbPool.query('INSERT INTO messages (sender_id, recipient_id, message_body) VALUES (?, ?, ?)', [req.user.userId, recipientId, messageBody]);
        res.status(201).json({ success: true, message: 'Message sent' });
    } catch(error) {
        next(error);
    }
});

app.get('/api/users/chattable', authenticateToken, async (req, res, next) => {
    try {
        const { userId, role } = req.user;
        let query;
        let params = [userId];

        if (role === 'Vendor') {
            // Vendors can only chat with Admins and Users
            query = "SELECT user_id, full_name, role FROM users WHERE role IN ('Admin', 'User') AND is_active = 1";
        } else {
            // Admins and Users can chat with anyone except themselves
            query = "SELECT user_id, full_name, role FROM users WHERE user_id != ? AND is_active = 1";
        }
        
        const [users] = await dbPool.query(query, params);
        res.json({ success: true, data: users });
    } catch(error) {
        next(error);
    }
});

app.get('/api/conversations', authenticateToken, async (req, res, next) => {
    try {
        const myId = req.user.userId;
        const query = `
            SELECT
                u.user_id,
                u.full_name,
                u.role,
                LastMessages.last_message_body as lastMessage,
                LastMessages.last_timestamp as lastMessageTimestamp,
                IFNULL(UnreadCounts.unread_count, 0) as unreadCount
            FROM users u
            INNER JOIN (
                SELECT
                    CASE WHEN sender_id = ? THEN recipient_id ELSE sender_id END as other_user_id,
                    MAX(timestamp) as last_timestamp,
                    (SELECT message_body FROM messages m2 
                     WHERE (m2.sender_id = m.sender_id AND m2.recipient_id = m.recipient_id) OR (m2.sender_id = m.recipient_id AND m2.recipient_id = m.sender_id) 
                     ORDER BY m2.timestamp DESC LIMIT 1) as last_message_body
                FROM messages m
                WHERE sender_id = ? OR recipient_id = ?
                GROUP BY other_user_id
            ) as LastMessages ON u.user_id = LastMessages.other_user_id
            LEFT JOIN (
                SELECT sender_id, COUNT(*) as unread_count
                FROM messages
                WHERE recipient_id = ? AND is_read = 0
                GROUP BY sender_id
            ) as UnreadCounts ON u.user_id = UnreadCounts.sender_id
            ORDER BY LastMessages.last_timestamp DESC
        `;
        const [conversations] = await dbPool.query(query, [myId, myId, myId, myId]);
        res.json({ success: true, data: conversations });
    } catch (error) {
        next(error);
    }
});

app.get('/api/messages/:otherUserId', authenticateToken, async (req, res, next) => {
    const connection = await dbPool.getConnection();
    try {
        const { otherUserId } = req.params;
        const myId = req.user.userId;

        await connection.beginTransaction();

        const [messages] = await connection.query(
            `SELECT * FROM messages WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?) ORDER BY timestamp ASC`, 
            [myId, otherUserId, otherUserId, myId]
        );
        
        await connection.query(
            `UPDATE messages SET is_read = 1 WHERE recipient_id = ? AND sender_id = ? AND is_read = 0`,
            [myId, otherUserId]
        );
        
        await connection.commit();
        res.json({ success: true, data: messages });
    } catch(error) {
        await connection.rollback();
        next(error);
    } finally {
        connection.release();
    }
});

// --- 7. MISC & EMAIL ---
app.post('/api/send-email', authenticateToken, async (req, res, next) => {
    if (!process.env.SENDGRID_API_KEY || !process.env.SENDGRID_API_KEY.startsWith('SG.')) {
        console.error("====== INVALID SENDGRID CONFIGURATION ======");
        console.error("CRITICAL: SENDGRID_API_KEY is missing from .env or does not start with 'SG.'.");
        return res.status(500).json({ success: false, message: 'Email service is not configured correctly on the server.' });
    }

    const { recipient, subject, htmlBody } = req.body;
    const msg = {
        to: recipient,
        from: process.env.FROM_EMAIL,
        subject: subject,
        html: htmlBody,
    };
    try {
        await sgMail.send(msg);
        res.json({ success: true, message: 'Email sent successfully.' });
    } catch (error) {
        console.error("====== SENDGRID ERROR ======");
        console.error("Timestamp:", new Date().toISOString());
        console.error("Failed to send email to:", recipient);
        if (error.response) {
            console.error("SendGrid Response Body:", error.response.body);
        }
        console.error("==========================");
        res.status(500).json({ success: false, message: 'Failed to send email.' });
    }
});

// ================== GLOBAL ERROR HANDLER ==================
app.use((err, req, res, next) => {
    console.error("====== GLOBAL ERROR HANDLER CAUGHT AN ERROR ======");
    // ===== DEBUGGING CHANGE =====
    console.error("FULL_ERROR_OBJECT:", err);
    res.status(500).send({
        success: false,
        message: err.message || 'Something went wrong on the server!',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// ================== SERVER START ==================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server is running on http://localhost:${PORT}`));
