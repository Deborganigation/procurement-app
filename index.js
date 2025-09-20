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
const { v2: cloudinary } = require('cloudinary');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
require('dotenv').config();

// ================== INITIALIZATION ==================
const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
if (process.env.SENDGRID_API_KEY) {
    sgMail.setApiKey(process.env.SENDGRID_API_KEY);
}

// ===== CLOUDINARY CONFIGURATION =====
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// ===== Serve static files (like index.html) =====
app.use(express.static(path.join(__dirname)));
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ================== DATABASE POOL ==================
const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    port: process.env.DB_PORT,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    connectTimeout: 20000,
    dateStrings: true,
    timezone: '+05:30' 
};

if (process.env.DB_CA_CERT_CONTENT) {
    dbConfig.ssl = {
        ca: process.env.DB_CA_CERT_CONTENT.replace(/\\n/g, '\n')
    };
    console.log("SSL Configuration loaded from Environment Variable.");
} else {
    console.warn("WARNING: DB_CA_CERT_CONTENT is not set. SSL connection might fail in production.");
}
const dbPool = mysql.createPool(dbConfig);


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
app.post('/api/login', async (req, res, next) => { try { const { email, password } = req.body; if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password are required.' }); const [rows] = await dbPool.query('SELECT * FROM users WHERE email = ? AND is_active = 1', [email]); if (rows.length === 0) return res.status(401).json({ success: false, message: 'Invalid credentials or account inactive.' }); const user = rows[0]; if (!user.password_hash) return res.status(500).json({ success: false, message: 'Server configuration error.' }); const match = await bcrypt.compare(password, user.password_hash); if (!match) return res.status(401).json({ success: false, message: 'Invalid credentials.' }); const payload = { userId: user.user_id, role: user.role, fullName: user.full_name, email: user.email }; const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '8h' }); const forceReset = !!user.force_password_reset; delete user.password_hash; res.json({ success: true, token, user, forceReset }); } catch (error) { next(error); }});
app.post('/api/register', async (req, res, next) => { try { const { FullName, Email, Password, Role, CompanyName, ContactNumber, GSTIN } = req.body; const hashedPassword = await bcrypt.hash(Password, 10); await dbPool.query('INSERT INTO pending_users (full_name, email, password, role, company_name, contact_number, gstin, submitted_at) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())', [FullName, Email, hashedPassword, Role, CompanyName, ContactNumber, GSTIN]); res.status(201).json({ success: true, message: 'Registration successful! Awaiting admin approval.' }); } catch (error) { if (error.code === 'ER_DUP_ENTRY') return res.status(400).json({ success: false, message: 'This email is already registered.' }); next(error); }});

// --- 2. REQUISITIONS & FILE UPLOADS ---
const storage = new CloudinaryStorage({ cloudinary: cloudinary, params: { folder: 'procurement_uploads', resource_type: 'auto', public_id: (req, file) => `${Date.now()}-${file.originalname.replace(/\s/g, '_')}` } });
const upload = multer({ storage });
const excelUpload = multer({ storage: multer.memoryStorage() });
app.get('/api/dropdowns/locations', authenticateToken, (req, res) => { res.json({ success: true, data: ["Dhulaghar", "Kharagpur", "Dankuni", "Kolkata"] }); });
app.post('/api/requisitions', authenticateToken, upload.any(), async (req, res, next) => { let connection; try { connection = await dbPool.getConnection(); const { vendorIds, items } = req.body; if (!items) return res.status(400).json({ success: false, message: 'No items provided.' }); const parsedItems = JSON.parse(items); const parsedVendorIds = JSON.parse(vendorIds); await connection.beginTransaction(); const [reqResult] = await connection.query("INSERT INTO requisitions (created_by, status, created_at) VALUES (?, 'Pending Approval', NOW())", [req.user.userId]); const reqId = reqResult.insertId; for (const [i, item] of parsedItems.entries()) { const drawingFile = req.files.find(f => f.fieldname === `drawing_${i}`); const specimenFile = req.files.find(f => f.fieldname === `specimen_${i}`); const drawingUrl = drawingFile ? drawingFile.path : null; const specimenUrl = specimenFile ? specimenFile.path : null; await connection.query("INSERT INTO requisition_items (requisition_id, item_sl_no, item_name, item_code, description, quantity, unit, freight_required, delivery_location, drawing_url, specimen_url, status, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())", [reqId, i + 1, item.ItemName, item.ItemCode, item.Description, item.Quantity, item.Unit, item.FreightRequired, item.DeliveryLocation, drawingUrl, specimenUrl, 'Pending Approval', req.user.userId]); } if (parsedVendorIds && parsedVendorIds.length > 0) { const assignmentValues = parsedVendorIds.map(vId => [reqId, vId, new Date()]); await connection.query('INSERT INTO requisition_assignments (requisition_id, vendor_id, assigned_at) VALUES ?', [assignmentValues]); } await connection.commit(); res.status(201).json({ success: true, message: 'Requisition submitted successfully!' }); } catch (error) { if (connection) await connection.rollback(); next(error); } finally { if (connection) connection.release(); }});
app.get('/api/requisitions/my-status', authenticateToken, async (req, res, next) => { try { const [myReqs] = await dbPool.query('SELECT * FROM requisitions WHERE created_by = ? ORDER BY requisition_id DESC', [req.user.userId]); if (myReqs.length === 0) return res.json({ success: true, data: [] }); const reqIds = myReqs.map(r => r.requisition_id); const [items] = await dbPool.query(`SELECT ri.*, ac.awarded_amount, u.full_name as awarded_vendor FROM requisition_items ri LEFT JOIN awarded_contracts ac ON ri.item_id = ac.item_id LEFT JOIN users u ON ac.vendor_id = u.user_id WHERE ri.requisition_id IN (?) ORDER BY ri.item_sl_no ASC`, [reqIds]); const finalData = myReqs.map(req => ({ ...req, items: items.filter(item => item.requisition_id === req.requisition_id) })); res.json({ success: true, data: finalData }); } catch (error) { next(error); }});

// --- 3. VENDOR FEATURES ---
app.get('/api/requirements/assigned', authenticateToken, async (req, res, next) => { try { const vendorId = req.user.userId; const query = ` SELECT ri.item_id, ri.item_name, ri.item_code, ri.unit, ri.quantity, ri.freight_required, ri.requisition_id, ri.item_sl_no, ri.delivery_location, ri.drawing_url, ri.specimen_url, b.bid_status AS my_bid_status, b.ex_works_rate AS my_ex_works_rate, b.freight_rate AS my_freight_rate, b.bid_amount AS my_bid_amount, (SELECT COUNT(*) FROM bidding_history_log WHERE item_id = ri.item_id AND vendor_id = ?) as bid_attempts, (SELECT COUNT(DISTINCT b2.vendor_id) + 1 FROM bids b2 WHERE b2.item_id = ri.item_id AND b2.bid_amount < b.bid_amount) AS my_rank FROM requisition_items ri JOIN requisition_assignments ra ON ri.requisition_id = ra.requisition_id LEFT JOIN bids b ON ri.item_id = b.item_id AND b.vendor_id = ? WHERE ra.vendor_id = ? AND ri.status = 'Active' ORDER BY ri.requisition_id DESC, ri.item_sl_no ASC; `; const [items] = await dbPool.query(query, [vendorId, vendorId, vendorId]); res.json({ success: true, data: items }); } catch (error) { next(error); }});
app.post('/api/bids/bulk', authenticateToken, async (req, res, next) => { if (req.user.role !== 'Vendor') return res.status(403).json({ success: false, message: 'Forbidden' }); let connection; try { connection = await dbPool.getConnection(); const { bids } = req.body; if (!bids || bids.length === 0) return res.status(400).json({ success: false, message: 'No bids to submit.' }); await connection.beginTransaction(); let submittedCount = 0; const skippedBids = []; for (const bid of bids) { const { itemId, ex_works_rate, freight_rate, comments } = bid; const vendorId = req.user.userId; try { const [[countResult]] = await connection.query('SELECT COUNT(*) as count FROM bidding_history_log WHERE item_id = ? AND vendor_id = ?', [itemId, vendorId]); if (countResult.count >= 3) { const [[itemDetails]] = await connection.query('SELECT item_name FROM requisition_items WHERE item_id = ?', [itemId]); skippedBids.push(itemDetails ? itemDetails.item_name : `Item ID ${itemId}`); continue; } const [[itemDetails]] = await connection.query('SELECT quantity, item_name FROM requisition_items WHERE item_id = ?', [itemId]); if (!itemDetails) { skippedBids.push(`Item ID ${itemId} (Not Found)`); continue; } const totalBidAmount = (parseFloat(ex_works_rate) + parseFloat(freight_rate || 0)) * parseFloat(itemDetails.quantity); await connection.query('DELETE FROM bids WHERE item_id = ? AND vendor_id = ?', [itemId, vendorId]); const [result] = await connection.query("INSERT INTO bids (item_id, vendor_id, bid_amount, ex_works_rate, freight_rate, comments, bid_status, submitted_at) VALUES (?, ?, ?, ?, ?, ?, 'Submitted', NOW())", [itemId, vendorId, totalBidAmount, ex_works_rate, freight_rate || 0, comments]); await connection.query("INSERT INTO bidding_history_log (bid_id, item_id, vendor_id, bid_amount, ex_works_rate, freight_rate, bid_status, submitted_at) VALUES (?, ?, ?, ?, ?, ?, 'Submitted', NOW())", [result.insertId, itemId, vendorId, totalBidAmount, ex_works_rate, freight_rate || 0]); submittedCount++; } catch (itemError) { console.error(`Error processing bid for item ID ${itemId}:`, itemError); const [[itemInfo]] = await connection.query('SELECT item_name FROM requisition_items WHERE item_id = ?', [itemId]).catch(() => [[{item_name: `ID ${itemId}`}]]); skippedBids.push(`${itemInfo.item_name} (processing error)`); } } await connection.commit(); let message = `${submittedCount} bid(s) submitted successfully.`; if (skippedBids.length > 0) { message += ` The following items were skipped (limit reached or error): ${skippedBids.join(', ')}.`; } res.json({ success: true, message }); } catch (error) { if (connection) await connection.rollback(); next(error); } finally { if (connection) connection.release(); }});
app.get('/api/vendor/my-bids', authenticateToken, async (req, res, next) => { try { const query = ` SELECT bhl.*, COALESCE(ri.item_name, 'Item Deleted') as item_name, ri.requisition_id, ri.item_sl_no, (SELECT COUNT(DISTINCT b2.vendor_id) + 1 FROM bids b2 WHERE b2.item_id = bhl.item_id AND b2.bid_amount < bhl.bid_amount) AS \`rank\` FROM bidding_history_log bhl LEFT JOIN requisition_items ri ON bhl.item_id = ri.item_id WHERE bhl.vendor_id = ? ORDER BY bhl.submitted_at DESC `; const [bids] = await dbPool.query(query, [req.user.userId]); res.json({ success: true, data: bids }); } catch (error) { next(error); }});
app.get('/api/vendor/my-awarded-contracts', authenticateToken, async (req, res, next) => { try { const [contracts] = await dbPool.query(`SELECT ac.*, ri.item_name, ri.requisition_id, ri.item_sl_no FROM awarded_contracts ac JOIN requisition_items ri ON ac.item_id = ri.item_id WHERE ac.vendor_id = ? AND ri.status = 'Awarded' ORDER BY ac.awarded_date DESC`, [req.user.userId]); res.json({ success: true, data: contracts }); } catch (error) { next(error); }});

// --- VENDOR DASHBOARD ---
app.get('/api/vendor/dashboard-stats', authenticateToken, async (req, res, next) => {
    try {
        const vendorId = req.user.userId;
        const queries = {
            assignedItems: "SELECT COUNT(*) as count FROM requisition_items ri JOIN requisition_assignments ra ON ri.requisition_id = ra.requisition_id WHERE ra.vendor_id = ? AND ri.status = 'Active'",
            submittedBids: "SELECT COUNT(DISTINCT item_id) as count FROM bidding_history_log WHERE vendor_id = ?",
            contractsWon: "SELECT COUNT(*) as count, SUM(awarded_amount) as totalValue FROM awarded_contracts WHERE vendor_id = ?",
            needsBid: "SELECT COUNT(*) as count FROM requisition_items ri JOIN requisition_assignments ra ON ri.requisition_id = ra.requisition_id WHERE ra.vendor_id = ? AND ri.status = 'Active' AND ri.item_id NOT IN (SELECT item_id FROM bids WHERE vendor_id = ?)",
            l1Bids: "SELECT COUNT(*) as count FROM (SELECT item_id FROM bids WHERE vendor_id = ? AND bid_amount = (SELECT MIN(bid_amount) FROM bids b2 WHERE b2.item_id = bids.item_id) GROUP BY item_id) as l1_bids",
            recentBids: `SELECT bhl.bid_amount, bhl.bid_status, bhl.submitted_at, COALESCE(ri.item_name, 'Item Deleted') as item_name FROM bidding_history_log bhl LEFT JOIN requisition_items ri ON bhl.item_id = ri.item_id WHERE bhl.vendor_id = ? ORDER BY bhl.submitted_at DESC LIMIT 5`,
            avgRank: `SELECT AVG(t.rank) as avg_rank FROM (SELECT (SELECT COUNT(DISTINCT b2.vendor_id) + 1 FROM bids b2 WHERE b2.item_id = b.item_id AND b2.bid_amount < b.bid_amount) as \`rank\` FROM bids b WHERE b.vendor_id = ?) as t`
        };
        const [
            [[assignedResult]], [[submittedResult]], [[wonResult]], [[needsBidResult]], [[l1BidsResult]], recentBids, [[avgRankResult]]
        ] = await Promise.all([
            dbPool.query(queries.assignedItems, [vendorId]), dbPool.query(queries.submittedBids, [vendorId]),
            dbPool.query(queries.contractsWon, [vendorId]), dbPool.query(queries.needsBid, [vendorId, vendorId]),
            dbPool.query(queries.l1Bids, [vendorId]), dbPool.query(queries.recentBids, [vendorId]),
            dbPool.query(queries.avgRank, [vendorId]),
        ]);
        const totalBids = submittedResult.count;
        const contractsWonCount = wonResult.count;
        const winRate = totalBids > 0 ? (contractsWonCount / totalBids) * 100 : 0;
        res.json({ success: true, data: { assignedItems: assignedResult.count || 0, submittedBids: totalBids || 0, contractsWon: contractsWonCount || 0, totalWonValue: wonResult.totalValue || 0, needsBid: needsBidResult.count || 0, l1Bids: l1BidsResult.count || 0, recentBids: recentBids, avgRank: avgRankResult.avg_rank || 0, winRate: winRate } });
    } catch (error) { next(error); }
});

// --- 4. ADMIN FEATURES ---
// ===== NEW: Rewrote the Admin Dashboard logic to be more reliable =====
app.get('/api/admin/dashboard-stats', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const queries = {
            notifications: `(SELECT CONCAT(COUNT(*), ' new user(s) awaiting approval.') as text, 'admin-pending-users-view' as view FROM pending_users HAVING COUNT(*) > 0) UNION (SELECT CONCAT(COUNT(DISTINCT requisition_id), ' new requisition(s) to approve.') as text, 'admin-pending-reqs-view' as view FROM requisitions WHERE status = 'Pending Approval' HAVING COUNT(DISTINCT requisition_id) > 0)`,
            reqTrends: `SELECT DATE_FORMAT(created_at, '%Y-%m') as month, COUNT(*) as count FROM requisitions GROUP BY month ORDER BY month ASC`,
            biddingActivity: `SELECT u.full_name, COUNT(b.bid_id) as bid_count FROM bids b JOIN users u ON b.vendor_id = u.user_id WHERE u.role = 'Vendor' AND u.full_name IS NOT NULL AND u.full_name != '' GROUP BY u.user_id, u.full_name ORDER BY bid_count DESC LIMIT 5`
        };

        // Step 1: Run all simple/reliable queries together
        const [
            [[activeItems]], [[pendingUsers]], [[awardedContracts]], [[pendingRequisitions]],
            notifications, reqTrends, biddingActivity
        ] = await Promise.all([
            dbPool.query("SELECT COUNT(*) as count FROM requisition_items WHERE status = 'Active'"),
            dbPool.query("SELECT COUNT(*) as count FROM pending_users"),
            dbPool.query("SELECT COUNT(*) as count FROM awarded_contracts"),
            dbPool.query("SELECT COUNT(DISTINCT requisition_id) as count FROM requisitions WHERE status = 'Pending Approval'"),
            dbPool.query(queries.notifications),
            dbPool.query(queries.reqTrends),
            dbPool.query(queries.biddingActivity)
        ]);

        // Step 2: Fetch latest requisitions separately (this was the problematic query)
        const [latestRequisitionsRaw] = await dbPool.query(`
            SELECT r.requisition_id, r.status, r.created_at, COALESCE(u.full_name, 'Unknown User') as creator_name
            FROM requisitions r
            LEFT JOIN users u ON r.created_by = u.user_id
            ORDER BY r.created_at DESC
            LIMIT 5
        `);
        
        // Step 3: If requisitions are found, fetch their item counts efficiently
        let latestRequisitions = [];
        if (latestRequisitionsRaw.length > 0) {
            const reqIds = latestRequisitionsRaw.map(r => r.requisition_id);
            const [itemCounts] = await dbPool.query(`
                SELECT requisition_id, COUNT(*) as item_count
                FROM requisition_items
                WHERE requisition_id IN (?)
                GROUP BY requisition_id
            `, [reqIds]);
            const countsMap = new Map(itemCounts.map(item => [item.requisition_id, item.item_count]));
            latestRequisitions = latestRequisitionsRaw.map(req => ({
                ...req,
                item_count: countsMap.get(req.requisition_id) || 0
            }));
        }

        // Step 4: Combine all data and send the response
        res.json({
            success: true,
            data: {
                activeItems: activeItems.count || 0,
                pendingUsers: pendingUsers.count || 0,
                awardedContracts: awardedContracts.count || 0,
                pendingRequisitionsCount: pendingRequisitions.count || 0,
                latestRequisitions,
                notifications,
                charts: {
                    reqTrends: { labels: reqTrends.map(r => r.month), data: reqTrends.map(r => r.count) },
                    biddingActivity: { labels: biddingActivity.map(r => r.full_name), data: biddingActivity.map(r => r.bid_count) }
                }
            }
        });

    } catch (error) {
        console.error("====== ERROR IN [Admin Dashboard] ENDPOINT ======", error);
        next(error);
    }
});

app.get('/api/requirements/pending', authenticateToken, isAdmin, async (req, res, next) => { try { const query = `SELECT r.requisition_id, r.created_at, u.full_name as creator, (SELECT GROUP_CONCAT(u2.user_id, ':', u2.full_name SEPARATOR '||') FROM requisition_assignments ra JOIN users u2 ON ra.vendor_id = u2.user_id WHERE ra.requisition_id = r.requisition_id) as suggested_vendors FROM requisitions r LEFT JOIN users u ON r.created_by = u.user_id WHERE r.status = 'Pending Approval' GROUP BY r.requisition_id, r.created_at, u.full_name ORDER BY r.requisition_id DESC`; const [groupedReqs] = await dbPool.query(query); const [pendingItems] = await dbPool.query("SELECT * FROM requisition_items WHERE status = 'Pending Approval'"); const [allVendors] = await dbPool.query("SELECT user_id, full_name FROM users WHERE role = 'Vendor' AND is_active = 1"); res.json({ success: true, data: { groupedReqs, pendingItems, allVendors } }); } catch (error) { next(error); }});
app.post('/api/requisitions/approve', authenticateToken, isAdmin, async (req, res, next) => { let connection; try { connection = await dbPool.getConnection(); const { approvedItemIds, vendorAssignments, requisitionId } = req.body; await connection.beginTransaction(); if (approvedItemIds && approvedItemIds.length > 0) { await connection.query("UPDATE requisition_items SET status = 'Active' WHERE item_id IN (?)", [approvedItemIds]); } await connection.query("UPDATE requisitions SET status = 'Processed', approved_at = NOW() WHERE requisition_id = ?", [requisitionId]); if (vendorAssignments) { await connection.query('DELETE FROM requisition_assignments WHERE requisition_id = ?', [requisitionId]); if(vendorAssignments.length > 0) { const values = vendorAssignments.map(vId => [requisitionId, vId, new Date()]); await connection.query('INSERT INTO requisition_assignments (requisition_id, vendor_id, assigned_at) VALUES ?', [values]); } } await connection.commit(); res.json({ success: true, message: 'Requisition items processed!' }); } catch(error) { if(connection) await connection.rollback(); next(error); } finally { if(connection) connection.release(); }});
app.get('/api/requirements/active', authenticateToken, isAdmin, async (req, res, next) => { try { const query = `SELECT ri.*, (SELECT MIN(b.bid_amount) FROM bids b WHERE b.item_id = ri.item_id) as l1_rate, (SELECT u.full_name FROM bids b JOIN users u ON b.vendor_id = u.user_id WHERE b.item_id = ri.item_id ORDER BY b.bid_amount ASC LIMIT 1) as l1_vendor, (SELECT GROUP_CONCAT(u_assign.full_name SEPARATOR ', ') FROM requisition_assignments ra JOIN users u_assign ON ra.vendor_id = u_assign.user_id WHERE ra.requisition_id = ri.requisition_id) as assigned_vendors FROM requisition_items ri WHERE ri.status IN ('Active', 'Bidding Closed') ORDER BY ri.requisition_id DESC, ri.item_sl_no ASC`; const [items] = await dbPool.query(query); res.json({ success: true, data: items }); } catch (error) { next(error); }});
app.get('/api/items/:id/bids', authenticateToken, isAdmin, async (req, res, next) => { try { const [bids] = await dbPool.query(`SELECT b.*, u.full_name as vendor_name, u.email as vendor_email FROM bids b JOIN users u ON b.vendor_id = u.user_id WHERE b.item_id = ? ORDER BY b.bid_amount ASC`, [req.params.id]); const [[itemDetails]] = await dbPool.query('SELECT * FROM requisition_items WHERE item_id = ?', [req.params.id]); res.json({ success: true, data: { bids, itemDetails } }); } catch (error) { next(error); }});
app.post('/api/admin/bids-for-items', authenticateToken, isAdmin, async (req, res, next) => { try { const { itemIds } = req.body; if (!itemIds || itemIds.length === 0) return res.status(400).json({ success: false, message: "No item IDs provided" }); const [items] = await dbPool.query(`SELECT item_id, item_name, requisition_id, item_sl_no, quantity, unit FROM requisition_items WHERE item_id IN (?)`, [itemIds]); const [bids] = await dbPool.query(`SELECT b.*, u.full_name as vendor_name, u.email as vendor_email FROM bids b JOIN users u ON b.vendor_id = u.user_id WHERE b.item_id IN (?) AND b.bid_status = 'Submitted' ORDER BY b.item_id, b.bid_amount ASC`, [itemIds]); const responseData = items.map(item => ({ ...item, bids: bids.filter(bid => bid.item_id === item.item_id) })); res.json({ success: true, data: responseData }); } catch (error) { next(error); }});
app.post('/api/contracts/award', authenticateToken, isAdmin, async (req, res, next) => { const { bids } = req.body; let connection; try { connection = await dbPool.getConnection(); await connection.beginTransaction(); for (const bid of bids) { const [[itemDetails]] = await connection.query('SELECT * FROM requisition_items WHERE item_id = ?', [bid.item_id]); if (!itemDetails) throw new Error(`Item with ID ${bid.item_id} not found.`); await connection.query("UPDATE requisition_items SET status = 'Awarded' WHERE item_id = ?", [bid.item_id]); await connection.query("UPDATE bids SET bid_status = 'Awarded' WHERE bid_id = ?", [bid.bid_id]); await connection.query("UPDATE bids SET bid_status = 'Rejected' WHERE item_id = ? AND bid_id != ?", [bid.item_id, bid.bid_id]); await connection.query('DELETE FROM awarded_contracts WHERE item_id = ?', [bid.item_id]); const insertQuery = `INSERT INTO awarded_contracts (item_id, requisition_id, item_name, item_code, quantity, unit, vendor_id, vendor_name, awarded_amount, ex_works_rate, freight_rate, winning_bid_id, remarks, awarded_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`; await connection.query(insertQuery, [ bid.item_id, itemDetails.requisition_id, itemDetails.item_name, itemDetails.item_code, itemDetails.quantity, itemDetails.unit, bid.vendor_id, bid.vendor_name, bid.bid_amount, bid.ex_works_rate, bid.freight_rate, bid.bid_id, bid.remarks ]); } await connection.commit(); res.json({ success: true, message: 'Contracts awarded successfully!' }); } catch (error) { if (connection) await connection.rollback(); next(error); } finally { if (connection) connection.release(); }});
app.get('/api/admin/awarded-contracts', authenticateToken, isAdmin, async (req, res, next) => { try { const query = `SELECT ac.*, ri.item_sl_no, ri.item_name, u.full_name as vendor_name FROM awarded_contracts ac JOIN users u ON ac.vendor_id = u.user_id LEFT JOIN requisition_items ri ON ac.item_id = ri.item_id ORDER BY ac.awarded_date DESC`; const [contracts] = await dbPool.query(query); res.json({ success: true, data: contracts }); } catch (error) { next(error); }});
app.post('/api/admin/reports-data', authenticateToken, isAdmin, async (req, res, next) => { try { const { startDate, endDate } = req.body; let baseKpisQuery = ` SELECT COALESCE(SUM(ac.awarded_amount), 0) AS totalSpend, COUNT(ac.item_id) as awardedItemsCount, COALESCE(SUM(CASE WHEN ac.awarded_amount <= (SELECT MIN(b.bid_amount) FROM bids b WHERE b.item_id = ac.item_id) THEN 1 ELSE 0 END), 0) as l1AwardsCount, AVG(DATEDIFF(r.approved_at, r.created_at)) as avgApprovalTime, COALESCE(SUM((SELECT bid_amount FROM bids b WHERE b.item_id = ac.item_id ORDER BY b.bid_amount ASC LIMIT 1 OFFSET 1) - ac.awarded_amount), 0) as costSavings FROM awarded_contracts ac LEFT JOIN requisition_items ri ON ac.item_id = ri.item_id LEFT JOIN requisitions r ON ri.requisition_id = r.requisition_id `; let baseDetailedReportQuery = `SELECT ac.awarded_amount, DATE_FORMAT(ac.awarded_date, '%Y-%m-%d') as awarded_date, ri.requisition_id, ri.item_sl_no, ri.item_name, u.full_name as vendor_name FROM awarded_contracts ac LEFT JOIN requisition_items ri ON ac.item_id = ri.item_id JOIN users u ON ac.vendor_id = u.user_id`; let baseVendorSpendQuery = `SELECT u.full_name as vendor, SUM(ac.awarded_amount) as total_spend FROM awarded_contracts ac JOIN users u ON ac.vendor_id = u.user_id`; let baseAwardedValueQuery = `SELECT DATE_FORMAT(ac.awarded_date, '%Y-%m') as month, SUM(ac.awarded_amount) as total_awarded FROM awarded_contracts ac`; let baseItemSpendQuery = `SELECT ri.item_name, SUM(ac.awarded_amount) as total_spend FROM awarded_contracts ac JOIN requisition_items ri ON ac.item_id = ri.item_id`; let baseItemFrequencyQuery = `SELECT item_name, COUNT(*) as frequency FROM awarded_contracts`; const params = []; let whereClause = ''; if (startDate && endDate) { whereClause = ' WHERE ac.awarded_date BETWEEN ? AND ?'; params.push(startDate, `${endDate} 23:59:59`); } const [kpisResult, detailedReport, vendorSpend, awardedValue, itemSpend, itemFrequency] = await Promise.all([ dbPool.query(baseKpisQuery + whereClause, params), dbPool.query(baseDetailedReportQuery + whereClause + ' ORDER BY ac.awarded_date DESC', params), dbPool.query(baseVendorSpendQuery + whereClause + ' GROUP BY u.full_name ORDER BY total_spend DESC LIMIT 5', params), dbPool.query(baseAwardedValueQuery + whereClause + ' GROUP BY month ORDER BY month ASC', params), dbPool.query(baseItemSpendQuery + whereClause.replace('ac.','ri.') + ' GROUP BY ri.item_name ORDER BY total_spend DESC LIMIT 5', params), dbPool.query(baseItemFrequencyQuery + whereClause + ' GROUP BY item_name ORDER BY frequency DESC LIMIT 5', params) ]); const kpis = kpisResult[0][0]; const totalAwarded = kpis.awardedItemsCount; const l1AwardRate = totalAwarded > 0 ? (kpis.l1AwardsCount / totalAwarded) * 100 : 0; res.json({ success: true, data: { detailedReport: detailedReport[0], kpis: { totalSpend: kpis.totalSpend, l1AwardRate, awardedItemsCount: totalAwarded, avgApprovalTime: kpis.avgApprovalTime || 0, costSavings: kpis.costSavings || 0 }, charts: { vendorSpend: Object.fromEntries(vendorSpend[0].map(row => [row.vendor, parseFloat(row.total_spend)])), awardedValue: Object.fromEntries(awardedValue[0].map(row => [row.month, parseFloat(row.total_awarded)])), itemSpend: { labels: itemSpend[0].map(i => i.item_name), data: itemSpend[0].map(i => i.total_spend) }, itemFrequency: { labels: itemFrequency[0].map(i => i.item_name), data: itemFrequency[0].map(i => i.frequency) } } } }); } catch (error) { next(error); }});
app.post('/api/items/reopen-bidding', authenticateToken, isAdmin, async (req, res, next) => { let connection; try { connection = await dbPool.getConnection(); const { itemIds } = req.body; await connection.beginTransaction(); await connection.query('DELETE FROM awarded_contracts WHERE item_id IN (?)', [itemIds]); await connection.query("UPDATE requisition_items SET status = 'Active' WHERE item_id IN (?)", [itemIds]); await connection.query("UPDATE bids SET bid_status = 'Submitted' WHERE item_id IN (?)", [itemIds]); await connection.commit(); res.json({ success: true, message: 'Bidding re-opened successfully.' }); } catch(error) { if(connection) await connection.rollback(); next(error); } finally { if(connection) connection.release(); }});
app.post('/api/requisitions/bulk-upload', authenticateToken, isAdmin, excelUpload.single('bulkFile'), async (req, res, next) => { if (!req.file) return res.status(400).json({ success: false, message: 'No Excel file uploaded.' }); let parsedVendorIds = []; try { if (req.body.vendorIds) parsedVendorIds = JSON.parse(req.body.vendorIds); } catch (e) { return res.status(400).json({ success: false, message: 'Invalid vendor data.' }); } let connection; try { connection = await dbPool.getConnection(); const workbook = xlsx.read(req.file.buffer, { type: 'buffer' }); const items = xlsx.utils.sheet_to_json(workbook.Sheets[workbook.SheetNames[0]]); if (items.length === 0) return res.status(400).json({ success: false, message: 'Excel file is empty or invalid.' }); await connection.beginTransaction(); const [reqResult] = await connection.query("INSERT INTO requisitions (created_by, status, created_at) VALUES (?, 'Pending Approval', NOW())", [req.user.userId]); const reqId = reqResult.insertId; for (const [i, item] of items.entries()) { await connection.query( "INSERT INTO requisition_items (requisition_id, item_sl_no, item_name, item_code, description, quantity, unit, freight_required, delivery_location, status, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())", [reqId, i + 1, item.ItemName, item.ItemCode, item.Description, item.Quantity, item.Unit, (String(item.FreightRequired).toLowerCase() === 'yes'), item.DeliveryLocation, 'Pending Approval', req.user.userId] ); } if (parsedVendorIds && parsedVendorIds.length > 0) { const values = parsedVendorIds.map(vId => [reqId, vId, new Date()]); await connection.query('INSERT INTO requisition_assignments (requisition_id, vendor_id, assigned_at) VALUES ?', [values]); } await connection.commit(); res.status(201).json({ success: true, message: `${items.length} items uploaded and submitted successfully!` }); } catch (error) { if(connection) await connection.rollback(); next(error); } finally { if(connection) connection.release(); }});
app.get('/api/admin/bidding-history', authenticateToken, isAdmin, async (req, res, next) => { try { const [bids] = await dbPool.query(`SELECT bhl.*, u.full_name as vendor_name, ri.item_name, ri.requisition_id, ri.item_sl_no FROM bidding_history_log bhl JOIN users u ON bhl.vendor_id = u.user_id JOIN requisition_items ri ON bhl.item_id = ri.item_id ORDER BY bhl.submitted_at DESC`); res.json({ success: true, data: bids }); } catch (error) { next(error); }});
app.get('/api/requisitions/:id/assignments', authenticateToken, isAdmin, async (req, res, next) => { try { const { id } = req.params; const [allVendors] = await dbPool.query("SELECT user_id, full_name FROM users WHERE role = 'Vendor' AND is_active = 1 ORDER BY full_name"); const [assignedResult] = await dbPool.query("SELECT vendor_id FROM requisition_assignments WHERE requisition_id = ?", [id]); const assignedVendorIds = assignedResult.map(a => a.vendor_id); res.json({ success: true, data: { allVendors, assignedVendorIds } }); } catch (error) { next(error); }});
app.put('/api/requisitions/:id/assignments', authenticateToken, isAdmin, async (req, res, next) => { let connection; try { connection = await dbPool.getConnection(); const { id } = req.params; const { vendorIds } = req.body; await connection.beginTransaction(); await connection.query('DELETE FROM requisition_assignments WHERE requisition_id = ?', [id]); if (vendorIds && vendorIds.length > 0) { const values = vendorIds.map(vId => [id, vId, new Date()]); await connection.query('INSERT INTO requisition_assignments (requisition_id, vendor_id, assigned_at) VALUES ?', [values]); } await connection.commit(); res.json({ success: true, message: 'Vendor assignments updated successfully.' }); } catch (error) { if(connection) await connection.rollback(); next(error); } finally { if(connection) connection.release(); }});

// --- USER MANAGEMENT & UTILITIES ---
app.get('/api/users/pending', authenticateToken, isAdmin, async (req, res, next) => { try { const [rows] = await dbPool.query(`SELECT * FROM pending_users ORDER BY temp_id DESC`); res.json({ success: true, data: rows }); } catch (error) { next(error); }});
app.post('/api/users/approve', authenticateToken, isAdmin, async (req, res, next) => { try { const { temp_id } = req.body; const [[pendingUser]] = await dbPool.query('SELECT * FROM pending_users WHERE temp_id = ?', [temp_id]); if (!pendingUser) return res.status(404).json({ success: false, message: 'User not found' }); await dbPool.query('INSERT INTO users (full_name, email, password_hash, role, company_name, contact_number, gstin) VALUES (?, ?, ?, ?, ?, ?, ?)', [pendingUser.full_name, pendingUser.email, pendingUser.password, pendingUser.role, pendingUser.company_name, pendingUser.contact_number, pendingUser.gstin]); await dbPool.query('DELETE FROM pending_users WHERE temp_id = ?', [temp_id]); res.json({ success: true, message: 'User approved!' }); } catch (error) { next(error); }});
app.get('/api/users', authenticateToken, async (req, res, next) => { try { const [rows] = await dbPool.query(`SELECT user_id, full_name, email, role, company_name, contact_number, gstin, is_active FROM users ORDER BY full_name`); res.json({ success: true, data: rows }); } catch (error) { next(error); }});
app.get('/api/users/vendors', authenticateToken, async (req, res, next) => { try { const [vendors] = await dbPool.query("SELECT user_id, full_name FROM users WHERE role = 'Vendor' AND is_active = 1"); res.json({ success: true, data: vendors }); } catch (error) { next(error); }});
app.get('/api/users/admins', authenticateToken, async (req, res, next) => { try { const [admins] = await dbPool.query("SELECT email FROM users WHERE role = 'Admin' AND is_active = 1"); res.json({ success: true, data: admins.map(a => a.email) }); } catch (error) { next(error); }});
app.put('/api/users/:id', authenticateToken, isAdmin, async (req, res, next) => { try { const { id } = req.params; const { full_name, email, role, company_name, contact_number, gstin, password } = req.body; let query = 'UPDATE users SET full_name=?, email=?, role=?, company_name=?, contact_number=?, gstin=?'; let params = [full_name, email, role, company_name, contact_number, gstin]; if (password) { const hashedPassword = await bcrypt.hash(password, 10); query += ', password_hash=?, force_password_reset=?'; params.push(hashedPassword, true); } query += ' WHERE user_id=?'; params.push(id); await dbPool.query(query, params); res.json({ success: true, message: 'User updated successfully.' }); } catch (error) { next(error); }});
app.post('/api/users/add', authenticateToken, isAdmin, async (req, res, next) => { try { const { full_name, email, password, role, company_name, contact_number, gstin } = req.body; if (!full_name || !email || !password || !role) { return res.status(400).json({ success: false, message: 'Name, email, password, and role are required.'}); } const hashedPassword = await bcrypt.hash(password, 10); await dbPool.query( 'INSERT INTO users (full_name, email, password_hash, role, company_name, contact_number, gstin, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [full_name, email, hashedPassword, role, company_name, contact_number, gstin, 1] ); res.status(201).json({ success: true, message: 'User created successfully.' }); } catch (error) { if (error.code === 'ER_DUP_ENTRY') return res.status(400).json({ success: false, message: 'This email is already registered.' }); next(error); }});
app.post('/api/users/set-password', authenticateToken, async (req, res, next) => { try { const { newPassword } = req.body; if (!newPassword || newPassword.length < 4) { return res.status(400).json({ success: false, message: 'Password is too short.' }); } const hashedPassword = await bcrypt.hash(newPassword, 10); await dbPool.query( 'UPDATE users SET password_hash = ?, force_password_reset = ? WHERE user_id = ?', [hashedPassword, false, req.user.userId] ); res.json({ success: true, message: 'Password updated successfully.' }); } catch(error) { next(error); }});

// --- 6. MESSAGING & NOTIFICATIONS API ---
app.post('/api/messages', authenticateToken, async (req, res, next) => { try { const { recipientId, messageBody } = req.body; await dbPool.query('INSERT INTO messages (sender_id, recipient_id, message_body) VALUES (?, ?, ?)', [req.user.userId, recipientId, messageBody]); res.status(201).json({ success: true, message: 'Message sent' }); } catch (error) { next(error); }});
app.get('/api/conversations/list', authenticateToken, async (req, res, next) => { try { const myId = req.user.userId; let chattableUsersQuery; if (req.user.role === 'Vendor') { chattableUsersQuery = "SELECT user_id, full_name, role FROM users WHERE role IN ('Admin', 'User') AND is_active = 1"; } else { chattableUsersQuery = "SELECT user_id, full_name, role FROM users WHERE user_id != ? AND is_active = 1"; } const [users] = await dbPool.query(chattableUsersQuery, [myId]); if (users.length === 0) return res.json({ success: true, data: [] }); const userMap = new Map(users.map(u => [u.user_id, { ...u, lastMessage: null, lastMessageTimestamp: null, unreadCount: 0 }])); const otherUserIds = Array.from(userMap.keys()); if (otherUserIds.length > 0) { const lastMessagesQuery = ` SELECT CASE WHEN sender_id = ? THEN recipient_id ELSE sender_id END as other_user_id, message_body, timestamp FROM messages WHERE message_id IN ( SELECT MAX(message_id) FROM messages WHERE (sender_id = ? AND recipient_id IN (?)) OR (recipient_id = ? AND sender_id IN (?)) GROUP BY LEAST(sender_id, recipient_id), GREATEST(sender_id, recipient_id) )`; const [lastMessages] = await dbPool.query(lastMessagesQuery, [myId, myId, otherUserIds, myId, otherUserIds]); const unreadQuery = `SELECT sender_id, COUNT(*) as count FROM messages WHERE recipient_id = ? AND is_read = 0 GROUP BY sender_id`; const [unreadCounts] = await dbPool.query(unreadQuery, [myId]); lastMessages.forEach(msg => { if (userMap.has(msg.other_user_id)) { const user = userMap.get(msg.other_user_id); user.lastMessage = msg.message_body; user.lastMessageTimestamp = msg.timestamp; }}); unreadCounts.forEach(uc => { if (userMap.has(uc.sender_id)) { userMap.get(uc.sender_id).unreadCount = uc.count; }}); } const sortedUsers = Array.from(userMap.values()).sort((a, b) => (new Date(b.lastMessageTimestamp) || 0) - (new Date(a.lastMessageTimestamp) || 0)); res.json({ success: true, data: sortedUsers }); } catch (error) { next(error); }});
app.get('/api/messages/:otherUserId', authenticateToken, async (req, res, next) => { let connection; try { connection = await dbPool.getConnection(); const { otherUserId } = req.params; const myId = req.user.userId; await connection.beginTransaction(); const [messages] = await connection.query(`SELECT * FROM messages WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?) ORDER BY timestamp ASC`, [myId, otherUserId, otherUserId, myId]); await connection.query(`UPDATE messages SET is_read = 1 WHERE recipient_id = ? AND sender_id = ? AND is_read = 0`, [myId, otherUserId]); await connection.commit(); res.json({ success: true, data: messages }); } catch (error) { if (connection) await connection.rollback(); next(error); } finally { if (connection) connection.release(); }});
app.post('/api/notifications/mark-all-read', authenticateToken, async (req, res, next) => { try { await dbPool.query("UPDATE messages SET is_read = 1 WHERE recipient_id = ?", [req.user.userId]); res.json({ success: true, message: 'All notifications marked as read.' }); } catch (error) { next(error); }});
app.get('/api/notifications', authenticateToken, async (req, res, next) => { try { const { userId, role } = req.user; let notifications = []; const [[msgCount]] = await dbPool.query("SELECT COUNT(*) as count FROM messages WHERE recipient_id = ? AND is_read = 0", [userId]); if (msgCount.count > 0) { notifications.push({ text: `You have ${msgCount.count} new message(s).`, view: 'messaging-view' }); } if (role === 'Admin') { const [[pendingUsers]] = await dbPool.query("SELECT COUNT(*) as count FROM pending_users"); if (pendingUsers.count > 0) { notifications.push({ text: `${pendingUsers.count} new user(s) awaiting approval.`, view: 'admin-pending-users-view' }); } const [[pendingReqs]] = await dbPool.query("SELECT COUNT(DISTINCT requisition_id) as count FROM requisitions WHERE status = 'Pending Approval'"); if (pendingReqs.count > 0) { notifications.push({ text: `${pendingReqs.count} new requisition(s) to approve.`, view: 'admin-pending-reqs-view' }); } } else if (role === 'Vendor') { const [[newItems]] = await dbPool.query("SELECT COUNT(DISTINCT ri.item_id) as count FROM requisition_items ri JOIN requisition_assignments ra ON ri.requisition_id = ra.requisition_id WHERE ra.vendor_id = ? AND ri.status = 'Active' AND ra.assigned_at > DATE_SUB(NOW(), INTERVAL 1 DAY)", [userId]); if (newItems.count > 0) { notifications.push({ text: `${newItems.count} new item(s) assigned for bidding.`, view: 'vendor-requirements-view' }); } } else { const [[processedItems]] = await dbPool.query("SELECT COUNT(*) as count FROM requisitions WHERE created_by = ? AND status = 'Processed' AND approved_at > DATE_SUB(NOW(), INTERVAL 1 DAY)", [userId]); if (processedItems.count > 0) { notifications.push({ text: `${processedItems.count} of your requisitions have been processed.`, view: 'user-status-view' }); } } res.json({ success: true, data: notifications }); } catch (error) { next(error); }});
app.get('/api/sidebar-counts', authenticateToken, async (req, res, next) => { try { const { userId, role } = req.user; let counts = { unreadMessages: 0, pendingReqs: 0, pendingUsers: 0 }; const [[msgCount]] = await dbPool.query("SELECT COUNT(*) as count FROM messages WHERE recipient_id = ? AND is_read = 0", [userId]); counts.unreadMessages = msgCount.count; if (role === 'Admin') { const [[pendingUsers]] = await dbPool.query("SELECT COUNT(*) as count FROM pending_users"); counts.pendingUsers = pendingUsers.count; const [[pendingReqs]] = await dbPool.query("SELECT COUNT(DISTINCT requisition_id) as count FROM requisitions WHERE status = 'Pending Approval'"); counts.pendingReqs = pendingReqs.count; } res.json({ success: true, data: counts }); } catch (error) { next(error); }});

// --- 7. MISC & EMAIL ---
app.post('/api/send-email', authenticateToken, async (req, res, next) => { if (!process.env.SENDGRID_API_KEY || !process.env.SENDGRID_API_KEY.startsWith('SG.')) { console.error("SENDGRID_API_KEY is not configured."); return res.status(500).json({ success: false, message: 'Email service is not configured.' }); } const { recipient, subject, htmlBody, cc } = req.body; const msg = { to: recipient, from: process.env.FROM_EMAIL, subject, html: htmlBody }; if (cc && cc.length > 0) msg.cc = cc; try { await sgMail.send(msg); res.json({ success: true, message: 'Email sent successfully.' }); } catch (error) { console.error("SENDGRID ERROR:", error?.response?.body); res.status(500).json({ success: false, message: 'Failed to send email.' }); }});

// ================== GLOBAL ERROR HANDLER ==================
app.use((err, req, res, next) => {
    console.error("====== GLOBAL ERROR HANDLER CAUGHT AN ERROR ======");
    console.error("ROUTE: ", req.method, req.originalUrl, err.message);
    res.status(500).send({ success: false, message: err.message || 'Something went wrong!', error: process.env.NODE_ENV === 'development' ? err.stack : undefined });
});

// ================== SERVER START ==================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server is running on http://localhost:${PORT}`));
