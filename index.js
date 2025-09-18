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
const { v2: cloudinary } = require('cloudinary'); // Cloudinary package
const { CloudinaryStorage } = require('multer-storage-cloudinary'); // Cloudinary storage for Multer
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

// ===== Serve index.html for the root URL ('Cannot GET /' error) =====
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
    connectionLimit: 10,
    queueLimit: 0,
    connectTimeout: 20000,
    dateStrings: true,
    ssl: {
        ca: fs.readFileSync(path.join(__dirname, 'ca.pem'))
    }
});

// ================== FILE STORAGE (NOW WITH CLOUDINARY) ==================
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'procurement_uploads', // A folder will be created in Cloudinary
        allowed_formats: ['jpg', 'jpeg', 'png', 'pdf'],
        public_id: (req, file) => `${Date.now()}-${file.originalname.replace(/\s/g, '_')}`,
    },
});

const upload = multer({ storage }); // Use Cloudinary storage for general uploads
const excelUpload = multer({ storage: multer.memoryStorage() }); // Keep Excel in memory


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
        console.error("LOGIN_ERROR_DETAIL:", error);
        next(error);
    }
});

app.post('/api/register', async (req, res, next) => {
    try {
        const { FullName, Email, Password, Role, CompanyName, ContactNumber, GSTIN } = req.body;
        const hashedPassword = await bcrypt.hash(Password, 10);
        await dbPool.query('INSERT INTO pending_users (full_name, email, password, role, company_name, contact_number, gstin) VALUES (?, ?, ?, ?, ?, ?, ?)', [FullName, Email, hashedPassword, Role, CompanyName, ContactNumber, GSTIN]);
        
        // NEW FEATURE: Send emails on registration
        try {
            const [admins] = await dbPool.query("SELECT email FROM users WHERE role = 'Admin' AND is_active = 1");
            const adminEmails = admins.map(a => a.email);

            // Email to User
            sgMail.send({
                to: Email,
                from: process.env.FROM_EMAIL,
                subject: "Registration Received - Awaiting Approval",
                html: `<p>Dear ${FullName},</p><p>Thank you for registering with DEB'S PROCUREMENT. Your account is currently pending approval from an administrator. You will be notified once your account is activated.</p><p>Regards,<br>The Procurement Team</p>`
            }).catch(console.error);

            // Email to Admins
            if (adminEmails.length > 0) {
                 sgMail.send({
                    to: adminEmails,
                    from: process.env.FROM_EMAIL,
                    subject: "New User Registration Approval Required",
                    html: `<p>Hello Admin Team,</p><p>A new user has registered and is awaiting approval:</p><ul><li><b>Name:</b> ${FullName}</li><li><b>Email:</b> ${Email}</li><li><b>Role:</b> ${Role}</li></ul><p>Please log in to the admin panel to review and approve the registration.</p>`
                }).catch(console.error);
            }
        } catch (emailError) {
            console.error("Failed to send registration emails:", emailError);
        }

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

app.post('/api/requisitions', authenticateToken, upload.any(), async (req, res, next) => {
    let connection;
    try {
        connection = await dbPool.getConnection();
        const { vendorIds, items } = req.body;
        if (!items) return res.status(400).json({ success: false, message: 'No items provided in the requisition.' });

        const parsedItems = JSON.parse(items);
        const parsedVendorIds = JSON.parse(vendorIds);
        
        await connection.beginTransaction();
        const [reqResult] = await connection.query("INSERT INTO requisitions (created_by, status, created_at) VALUES (?, 'Pending Approval', NOW())", [req.user.userId]);
        const reqId = reqResult.insertId;

        for (const [i, item] of parsedItems.entries()) {
            const drawingFile = req.files.find(f => f.fieldname === `drawing_${i}`);
            const specimenFile = req.files.find(f => f.fieldname === `specimen_${i}`);
            
            // The full URL from Cloudinary is in file.path
            const drawingUrl = drawingFile ? drawingFile.path : null;
            const specimenUrl = specimenFile ? specimenFile.path : null;

            await connection.query("INSERT INTO requisition_items (requisition_id, item_sl_no, item_name, item_code, description, quantity, unit, freight_required, delivery_location, drawing_url, specimen_url, status, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())", 
            [reqId, i + 1, item.ItemName, item.ItemCode, item.Description, item.Quantity, item.Unit, item.FreightRequired, item.DeliveryLocation, drawingUrl, specimenUrl, 'Pending Approval', req.user.userId]);
        }

        if (parsedVendorIds && parsedVendorIds.length > 0) {
            for (const vId of parsedVendorIds) await connection.query('INSERT INTO requisition_assignments (requisition_id, vendor_id, assigned_at) VALUES (?, ?, NOW())', [reqId, vId]);
        }
        await connection.commit();
        res.status(201).json({ success: true, message: 'Requisition submitted successfully!' });
    } catch (error) {
        if(connection) await connection.rollback();
        next(error);
    } finally {
        if(connection) connection.release();
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
        // NEW FEATURE: Consolidate items for vendors
        const query = `
            SELECT 
                ri.item_name, 
                ri.item_code, 
                ri.unit, 
                ri.freight_required,
                SUM(ri.quantity) as quantity,
                GROUP_CONCAT(ri.item_id SEPARATOR ',') as original_item_ids,
                MIN(b.bid_status) AS my_bid_status,
                (SELECT MIN(bid_amount) FROM bids WHERE item_id IN (SELECT item_id FROM requisition_items WHERE item_code = ri.item_code) AND vendor_id = ?) AS my_bid_amount,
                (SELECT MIN(ex_works_rate) FROM bids WHERE item_id IN (SELECT item_id FROM requisition_items WHERE item_code = ri.item_code) AND vendor_id = ?) AS my_ex_works_rate,
                (SELECT MIN(freight_rate) FROM bids WHERE item_id IN (SELECT item_id FROM requisition_items WHERE item_code = ri.item_code) AND vendor_id = ?) AS my_freight_rate,
                (SELECT MIN(sub_b.bid_amount) FROM bids sub_b WHERE sub_b.item_id IN (SELECT item_id FROM requisition_items WHERE item_code = ri.item_code)) as l1_bid
            FROM requisition_items ri
            JOIN requisition_assignments ra ON ri.requisition_id = ra.requisition_id
            LEFT JOIN bids b ON ri.item_id = b.item_id AND b.vendor_id = ?
            WHERE ra.vendor_id = ? AND ri.status = 'Active'
            GROUP BY ri.item_name, ri.item_code, ri.unit, ri.freight_required
            ORDER BY ri.item_name ASC;
        `;
        const [items] = await dbPool.query(query, [req.user.userId, req.user.userId, req.user.userId, req.user.userId, req.user.userId]);

        // Calculate rank after fetching data
        for (const item of items) {
            if (item.my_bid_amount) {
                const [rankResult] = await dbPool.query(
                    `SELECT COUNT(DISTINCT vendor_id) + 1 as rank FROM bids WHERE item_id IN (${item.original_item_ids}) AND bid_amount < ?`,
                    [item.my_bid_amount]
                );
                item.my_rank = rankResult[0].rank;
            } else {
                item.my_rank = null;
            }
        }

        res.json({ success: true, data: items });
    } catch(error) {
        next(error);
    }
});


app.post('/api/bids', authenticateToken, async (req, res, next) => {
    if (req.user.role !== 'Vendor') return res.status(403).json({ success: false, message: 'Forbidden' });
    
    let connection;
    try {
        connection = await dbPool.getConnection();
        const { bids } = req.body; // Bids will now contain original_item_ids
        
        await connection.beginTransaction();

        for (const bid of bids) {
            const originalItemIds = bid.original_item_ids.split(',');

            // Check bid limit for the first item (as it's a consolidated bid)
            const [[countResult]] = await connection.query('SELECT COUNT(*) as count FROM bidding_history_log WHERE item_id = ? AND vendor_id = ?', [originalItemIds[0], req.user.userId]);
            if (countResult.count >= 3) {
                 await connection.rollback();
                 return res.status(403).json({ success: false, message: `You have reached the maximum of 3 bids for item ${bid.item_name}.` });
            }

            // Apply the same bid to all original items
            for (const itemId of originalItemIds) {
                await connection.query('DELETE FROM bids WHERE item_id = ? AND vendor_id = ?', [itemId, req.user.userId]);
                
                const [result] = await connection.query("INSERT INTO bids (item_id, vendor_id, bid_amount, ex_works_rate, freight_rate, comments, bid_status) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                    [itemId, req.user.userId, bid.bid_amount, bid.ex_works_rate, bid.freight_rate, bid.comments, 'Submitted']);
                
                await connection.query("INSERT INTO bidding_history_log (bid_id, item_id, vendor_id, bid_amount, ex_works_rate, freight_rate, bid_status, submitted_at) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())", 
                    [result.insertId, itemId, req.user.userId, bid.bid_amount, bid.ex_works_rate, bid.freight_rate, 'Submitted']);
            }
        }
        await connection.commit();
        res.json({ success: true, message: 'Bids submitted successfully!' });
    } catch (error) {
        if(connection) await connection.rollback();
        next(error);
    } finally {
        if(connection) connection.release();
    }
});

app.get('/api/vendor/dashboard-stats', async (req, res, next) => {
    try {
        const vendorId = req.user.userId;
        const assignedQuery = "SELECT COUNT(DISTINCT ri.item_id) as count FROM requisition_items ri JOIN requisition_assignments ra ON ri.requisition_id = ra.requisition_id WHERE ra.vendor_id = ? AND ri.status = 'Active'";
        const submittedQuery = "SELECT COUNT(DISTINCT item_code) as count FROM bids b JOIN requisition_items ri ON b.item_id = ri.item_id WHERE b.vendor_id = ?";
        const wonQuery = "SELECT COUNT(*) as count, SUM(awarded_amount) as totalValue FROM awarded_contracts WHERE vendor_id = ?";
        const needsBidQuery = "SELECT COUNT(DISTINCT ri.item_code) as count FROM requisition_items ri JOIN requisition_assignments ra ON ri.requisition_id = ra.requisition_id WHERE ra.vendor_id = ? AND ri.status = 'Active' AND ri.item_id NOT IN (SELECT item_id FROM bids WHERE vendor_id = ?)";
        const l1BidsQuery = "SELECT COUNT(DISTINCT b.item_id) as count FROM bids b WHERE b.vendor_id = ? AND b.bid_amount = (SELECT MIN(bid_amount) FROM bids WHERE item_id = b.item_id)";
        const bidStatusQuery = "SELECT bid_status, COUNT(*) as count FROM bids WHERE vendor_id = ? GROUP BY bid_status";
        const recentItemsQuery = `SELECT ri.item_name, ri.requisition_id, ri.item_sl_no, ra.assigned_at FROM requisition_items ri JOIN requisition_assignments ra ON ri.requisition_id = ra.requisition_id WHERE ra.vendor_id = ? AND ri.status = 'Active' ORDER BY ra.assigned_at DESC LIMIT 5`;

        const [
            [[assigned]], [[submitted]], [[won]], [[needsBid]], [[l1Bids]], bidStatus, recentItems
        ] = await Promise.all([
            dbPool.query(assignedQuery, [vendorId]),
            dbPool.query(submittedQuery, [vendorId]),
            dbPool.query(wonQuery, [vendorId]),
            dbPool.query(needsBidQuery, [vendorId, vendorId]),
            dbPool.query(l1BidsQuery, [vendorId]),
            dbPool.query(bidStatusQuery, [vendorId]),
            dbPool.query(recentItemsQuery, [vendorId])
        ]);

        res.json({
            success: true,
            data: {
                assignedItems: assigned.count,
                submittedBids: submitted.count,
                contractsWon: won.count,
                totalWonValue: won.totalValue || 0,
                needsBid: needsBid.count,
                l1Bids: l1Bids.count,
                bidStatusChart: {
                    labels: bidStatus.map(s => s.bid_status),
                    data: bidStatus.map(s => s.count)
                },
                recentItems
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
            `SELECT ac.*, ri.item_name, ri.requisition_id, ri.item_sl_no 
             FROM awarded_contracts ac 
             JOIN requisition_items ri ON ac.item_id = ri.item_id 
             WHERE ac.vendor_id = ? AND ri.status = 'Awarded' 
             ORDER BY ac.awarded_date DESC`, [req.user.userId]
        );
        res.json({ success: true, data: contracts });
    } catch (error) {
        next(error);
    }
});


// --- 4. ADMIN FEATURES ---
app.get('/api/admin/dashboard-stats', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const activeItemsQuery = "SELECT COUNT(*) as count FROM requisition_items WHERE status = 'Active'";
        const pendingUsersQuery = "SELECT COUNT(*) as count FROM pending_users";
        const awardedQuery = "SELECT COUNT(*) as count FROM awarded_contracts";
        const pendingReqsQuery = "SELECT COUNT(DISTINCT requisition_id) as count FROM requisitions WHERE status = 'Pending Approval'";
        const reqsTodayQuery = "SELECT COUNT(*) as count FROM requisitions WHERE DATE(created_at) = CURDATE()";
        const activeVendorsQuery = "SELECT COUNT(*) as count FROM users WHERE role = 'Vendor' AND is_active = 1";
        const avgApprovalTimeQuery = "SELECT AVG(DATEDIFF(r.approved_at, r.created_at)) as avg_days FROM requisitions r WHERE r.status = 'Processed' AND r.approved_at IS NOT NULL";
        const noBidsQuery = "SELECT COUNT(*) as count FROM requisition_items WHERE status = 'Active' AND item_id NOT IN (SELECT DISTINCT item_id FROM bids)";
        const attentionItemsQuery = "SELECT item_id, item_name, requisition_id, item_sl_no FROM requisition_items WHERE status = 'Active' AND item_id NOT IN (SELECT DISTINCT item_id FROM bids) LIMIT 5";
        
        const activityQuery = `
            SELECT CAST(d.day AS CHAR) as date, IFNULL(r.count, 0) as requisitions, IFNULL(b.count, 0) as bids
            FROM (
                SELECT CURDATE() - INTERVAL (a.a + (10 * b.a) + (100 * c.a)) DAY as day
                FROM (SELECT 0 AS a UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9) AS a
                CROSS JOIN (SELECT 0 AS a UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9) AS b
                CROSS JOIN (SELECT 0 AS a UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9) AS c
            ) d
            LEFT JOIN (SELECT DATE(created_at) as day, COUNT(*) as count FROM requisitions GROUP BY day) r ON d.day = r.day
            LEFT JOIN (SELECT DATE(submitted_at) as day, COUNT(*) as count FROM bidding_history_log GROUP BY day) b ON d.day = b.day
            WHERE d.day BETWEEN CURDATE() - INTERVAL 6 DAY AND CURDATE()
            ORDER BY d.day;
        `;

        const [
            [[activeItems]], [[pendingUsers]], [[awarded]], [[pendingReqs]], [[reqsToday]], [[activeVendors]], [[avgApprovalTime]], [[noBids]], attentionItems, activity
        ] = await Promise.all([
            dbPool.query(activeItemsQuery), dbPool.query(pendingUsersQuery), dbPool.query(awardedQuery),
            dbPool.query(pendingReqsQuery), dbPool.query(reqsTodayQuery), dbPool.query(activeVendorsQuery),
            dbPool.query(avgApprovalTimeQuery), dbPool.query(noBidsQuery), dbPool.query(attentionItemsQuery), dbPool.query(activityQuery)
        ]);
        
        res.json({
            success: true,
            data: { 
                activeItems: activeItems.count, 
                pendingUsers: pendingUsers.count, 
                awardedContracts: awarded.count,
                pendingRequisitionsCount: pendingReqs.count,
                reqsToday: reqsToday.count,
                activeVendors: activeVendors.count,
                avgApprovalTime: avgApprovalTime.avg_days ? parseFloat(avgApprovalTime.avg_days).toFixed(1) : 0,
                itemsWithNoBids: noBids.count,
                attentionItems: attentionItems,
                activityChart: {
                    labels: activity.map(a => new Date(a.date).toLocaleDateString('en-US', { weekday: 'short' })),
                    requisitions: activity.map(a => a.requisitions),
                    bids: activity.map(a => a.bids)
                }
            }
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
    let connection;
    try {
        connection = await dbPool.getConnection();
        const { approvedItemIds, vendorAssignments, requisitionId } = req.body;
        
        await connection.beginTransaction();
        if (approvedItemIds && approvedItemIds.length > 0) {
            await connection.query("UPDATE requisition_items SET status = 'Active' WHERE item_id IN (?)", [approvedItemIds]);
        }
        await connection.query("UPDATE requisitions SET status = 'Processed', approved_at = NOW() WHERE requisition_id = ?", [requisitionId]);
        if (vendorAssignments) {
            await connection.query('DELETE FROM requisition_assignments WHERE requisition_id = ?', [requisitionId]);
            if(vendorAssignments.length > 0) {
                for(const vendorId of vendorAssignments) {
                    await connection.query('INSERT INTO requisition_assignments (requisition_id, vendor_id, assigned_at) VALUES (?, ?, NOW())', [requisitionId, vendorId]);
                }
            }
        }
        await connection.commit();
        res.json({ success: true, message: 'Requisition items processed!' });
    } catch(error) {
        if(connection) await connection.rollback();
        next(error);
    } finally {
        if(connection) connection.release();
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
        const [[itemDetails]] = await dbPool.query('SELECT * FROM requisition_items WHERE item_id = ?', [req.params.id]);
        res.json({ success: true, data: { bids, itemDetails } });
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
    let connection;
    try {
        connection = await dbPool.getConnection();
        await connection.beginTransaction();
        
        for (const bid of bids) {
            const [[itemDetails]] = await connection.query('SELECT * FROM requisition_items WHERE item_id = ?', [bid.item_id]);
            if (!itemDetails) {
                throw new Error(`Item with ID ${bid.item_id} not found.`);
            }

            await connection.query("UPDATE requisition_items SET status = 'Awarded' WHERE item_id = ?", [bid.item_id]);
            await connection.query("UPDATE bids SET bid_status = 'Awarded' WHERE bid_id = ?", [bid.bid_id]);
            await connection.query("UPDATE bids SET bid_status = 'Rejected' WHERE item_id = ? AND bid_id != ?", [bid.item_id, bid.bid_id]);
            
            await connection.query('DELETE FROM awarded_contracts WHERE item_id = ?', [bid.item_id]);
            
            const insertQuery = `
                INSERT INTO awarded_contracts 
                (item_id, requisition_id, item_name, item_code, quantity, unit, vendor_id, vendor_name, awarded_amount, ex_works_rate, freight_rate, winning_bid_id, remarks, awarded_date) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`;
            
            await connection.query(insertQuery, [
                bid.item_id, itemDetails.requisition_id, itemDetails.item_name, itemDetails.item_code, 
                itemDetails.quantity, itemDetails.unit, bid.vendor_id, bid.vendor_name, 
                bid.bid_amount, bid.ex_works_rate, bid.freight_rate, bid.bid_id, bid.remarks
            ]);
        }
        
        await connection.commit();
        res.json({ success: true, message: 'Contracts awarded successfully!' });
    } catch (error) {
        if (connection) await connection.rollback();
        next(error);
    } finally {
        if (connection) connection.release();
    }
});

app.get('/api/admin/awarded-contracts', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        // FIX: Added quantity and unit for the download report feature.
        const query = `
            SELECT 
                ac.contract_id, ac.item_id, ac.requisition_id, ac.vendor_id, 
                ac.awarded_amount, ac.ex_works_rate, ac.freight_rate,
                ac.winning_bid_id, ac.remarks, ac.awarded_date,
                ri.item_name, 
                ri.item_sl_no,
                ri.quantity,
                ri.unit,
                u.full_name as vendor_name
            FROM awarded_contracts ac
            JOIN users u ON ac.vendor_id = u.user_id
            JOIN requisition_items ri ON ac.item_id = ri.item_id
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
        
        const params = [];
        let dateFilter = '1=1';
        if (startDate && endDate) {
            dateFilter = 'ac.awarded_date BETWEEN ? AND ?';
            params.push(startDate, `${endDate} 23:59:59`);
        }
        
        // BUG FIX: Correctly parameterize all queries to avoid syntax errors.
        const kpiQuery = `
            SELECT
                SUM(ac.awarded_amount) AS totalSpend,
                (SELECT COUNT(DISTINCT vendor_id) FROM awarded_contracts ac WHERE ${dateFilter}) as participatingVendors,
                (SELECT COUNT(*) FROM users WHERE role='Vendor' AND is_active=1) as totalVendors,
                (SELECT COUNT(*) FROM awarded_contracts ac WHERE ${dateFilter} AND awarded_amount = (SELECT MIN(bid_amount) FROM bids WHERE item_id = ac.item_id)) as l1Awards,
                (SELECT COUNT(*) FROM awarded_contracts ac WHERE ${dateFilter}) as totalAwards
            FROM awarded_contracts ac
            WHERE ${dateFilter}`;

        const savingsQuery = `
            SELECT SUM(l2_bids.bid_amount - ac.awarded_amount) as totalSavings
            FROM awarded_contracts ac
            JOIN (
                SELECT b1.item_id, MIN(b1.bid_amount) as bid_amount
                FROM bids b1
                WHERE b1.bid_amount > (SELECT MIN(b2.bid_amount) FROM bids b2 WHERE b2.item_id = b1.item_id)
                GROUP BY b1.item_id
            ) l2_bids ON ac.item_id = l2_bids.item_id
            WHERE ${dateFilter}`;

        const vendorSpendQuery = `
            SELECT u.full_name, SUM(ac.awarded_amount) as total
            FROM awarded_contracts ac
            JOIN users u ON ac.vendor_id = u.user_id
            WHERE ${dateFilter}
            GROUP BY u.full_name ORDER BY total DESC LIMIT 5`;
        
        const categorySpendQuery = `SELECT item_code, SUM(awarded_amount) as total FROM awarded_contracts ac WHERE ${dateFilter} GROUP BY item_code ORDER BY total DESC LIMIT 5`;
        
        const savingsTrendQuery = `
            SELECT DATE_FORMAT(ac.awarded_date, '%Y-%m') as month, SUM(l2_bids.bid_amount - ac.awarded_amount) as savings
            FROM awarded_contracts ac
            JOIN (
                SELECT b1.item_id, MIN(b1.bid_amount) as bid_amount
                FROM bids b1
                WHERE b1.bid_amount > (SELECT MIN(b2.bid_amount) FROM bids b2 WHERE b2.item_id = b1.item_id)
                GROUP BY b1.item_id
            ) l2_bids ON ac.item_id = l2_bids.item_id
            ${params.length > 0 ? `WHERE ac.awarded_date BETWEEN ? AND ?` : ''}
            GROUP BY month ORDER BY month ASC`;

        const detailedReportQuery = `
            SELECT 
                ac.contract_id, ac.item_id, ac.requisition_id,
                ac.awarded_amount, ac.awarded_date,
                ri.item_name, 
                ri.item_sl_no,
                u.full_name as vendor_name
            FROM awarded_contracts ac
            JOIN requisition_items ri ON ac.item_id = ri.item_id
            JOIN users u ON ac.vendor_id = u.user_id
            WHERE ${dateFilter} 
            ORDER BY ac.awarded_date DESC`;

        const [
            [[kpis]], [[savings]], topVendors, categorySpend, savingsTrend, detailedReport
        ] = await Promise.all([
            dbPool.query(kpiQuery, [...params, ...params, ...params, ...params]),
            dbPool.query(savingsQuery, params),
            dbPool.query(vendorSpendQuery, params),
            dbPool.query(categorySpendQuery, params),
            dbPool.query(savingsTrendQuery, params),
            dbPool.query(detailedReportQuery, params)
        ]);

        res.json({
            success: true,
            data: {
                kpis: {
                    totalSpend: kpis.totalSpend || 0,
                    totalSavings: savings.totalSavings || 0,
                    vendorParticipationRate: kpis.totalVendors > 0 ? (kpis.participatingVendors / kpis.totalVendors) * 100 : 0,
                    l1AwardRate: kpis.totalAwards > 0 ? (kpis.l1Awards / kpis.totalAwards) * 100 : 0,
                },
                topVendors: {
                    labels: topVendors.map(v => v.full_name),
                    data: topVendors.map(v => v.total)
                },
                spendByCategory: {
                    labels: categorySpend.map(c => c.item_code || 'Unknown'),
                    data: categorySpend.map(c => c.total)
                },
                savingsTrend: {
                    labels: savingsTrend.map(s => s.month),
                    data: savingsTrend.map(s => s.savings)
                },
                detailedReport
            }
        });

    } catch (error) {
        next(error);
    }
});


app.post('/api/items/reopen-bidding', authenticateToken, isAdmin, async (req, res, next) => {
    let connection;
    try {
        connection = await dbPool.getConnection();
        const { itemIds } = req.body;
        
        await connection.beginTransaction();
        await connection.query('DELETE FROM awarded_contracts WHERE item_id IN (?)', [itemIds]);
        await connection.query("UPDATE requisition_items SET status = 'Active' WHERE item_id IN (?)", [itemIds]);
        await connection.query("UPDATE bids SET bid_status = 'Submitted' WHERE item_id IN (?)", [itemIds]);

        await connection.commit();
        res.json({ success: true, message: 'Bidding re-opened successfully.' });
    } catch(error) {
        if(connection) await connection.rollback();
        next(error);
    } finally {
        if(connection) connection.release();
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

    let connection;
    try {
        connection = await dbPool.getConnection();
        const workbook = xlsx.read(req.file.buffer, { type: 'buffer' });
        const items = xlsx.utils.sheet_to_json(workbook.Sheets[workbook.SheetNames[0]]);
        if (items.length === 0) return res.status(400).json({ success: false, message: 'Excel file is empty or invalid.' });

        await connection.beginTransaction();
        const [reqResult] = await connection.query("INSERT INTO requisitions (created_by, status, created_at) VALUES (?, 'Pending Approval', NOW())", [req.user.userId]);
        const reqId = reqResult.insertId;

        for (const [i, item] of items.entries()) {
            await connection.query(
                "INSERT INTO requisition_items (requisition_id, item_sl_no, item_name, item_code, description, quantity, unit, freight_required, delivery_location, status, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())",
                [reqId, i + 1, item.ItemName, item.ItemCode, item.Description, item.Quantity, item.Unit, (String(item.FreightRequired).toLowerCase() === 'yes'), item.DeliveryLocation, 'Pending Approval', req.user.userId]
            );
        }

        if (parsedVendorIds && parsedVendorIds.length > 0) {
            for (const vId of parsedVendorIds) await connection.query('INSERT INTO requisition_assignments (requisition_id, vendor_id, assigned_at) VALUES (?, ?, NOW())', [reqId, vId]);
        }
        await connection.commit();
        res.status(201).json({ success: true, message: `${items.length} items uploaded and submitted successfully!` });

    } catch (error) {
        if(connection) await connection.rollback();
        next(error);
    } finally {
        if(connection) connection.release();
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
    let connection;
    try {
        connection = await dbPool.getConnection();
        const { id } = req.params;
        const { vendorIds } = req.body;
        
        await connection.beginTransaction();
        await connection.query('DELETE FROM requisition_assignments WHERE requisition_id = ?', [id]);
        if (vendorIds && vendorIds.length > 0) {
            const values = vendorIds.map(vId => [id, vId, new Date()]);
            await connection.query('INSERT INTO requisition_assignments (requisition_id, vendor_id, assigned_at) VALUES ?', [values]);
        }
        await connection.commit();
        res.json({ success: true, message: 'Vendor assignments updated successfully.' });
    } catch (error) {
        if(connection) await connection.rollback();
        next(error);
    } finally {
        if(connection) connection.release();
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

// NEW HELPER ENDPOINT
app.get('/api/users/admins', authenticateToken, async (req, res, next) => {
    try {
        const [admins] = await dbPool.query("SELECT email FROM users WHERE role = 'Admin' AND is_active = 1");
        res.json({ success: true, data: admins.map(a => a.email) });
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

// --- 6. MESSAGING & NOTIFICATIONS API ---
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
            query = "SELECT user_id, full_name, role FROM users WHERE role IN ('Admin', 'User') AND is_active = 1";
        } else {
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
                u.user_id as other_user_id,
                u.full_name,
                u.role,
                m.message_body as lastMessage,
                m.timestamp as lastMessageTimestamp,
                (SELECT COUNT(*) FROM messages WHERE recipient_id = ? AND sender_id = u.user_id AND is_read = 0) as unreadCount
            FROM
                messages m
            JOIN
                users u ON u.user_id = CASE WHEN m.sender_id = ? THEN m.recipient_id ELSE m.sender_id END
            WHERE
                (m.sender_id = ? OR m.recipient_id = ?)
                AND m.timestamp = (
                    SELECT MAX(timestamp)
                    FROM messages
                    WHERE (sender_id = m.sender_id AND recipient_id = m.recipient_id)
                       OR (sender_id = m.recipient_id AND recipient_id = m.sender_id)
                )
            GROUP BY
                other_user_id, u.full_name, u.role, lastMessage, lastMessageTimestamp
            ORDER BY
                lastMessageTimestamp DESC
        `;
        const [conversations] = await dbPool.query(query, [myId, myId, myId, myId]);
        res.json({ success: true, data: conversations });
    } catch (error) {
        next(error);
    }
});

app.get('/api/messages/:otherUserId', authenticateToken, async (req, res, next) => {
    let connection;
    try {
        connection = await dbPool.getConnection();
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
        if(connection) await connection.rollback();
        next(error);
    } finally {
        if(connection) connection.release();
    }
});

// NEW FEATURE: Notifications Endpoint
app.get('/api/notifications', authenticateToken, async (req, res, next) => {
    try {
        const { userId, role } = req.user;
        let notifications = [];

        if (role === 'Admin') {
            const [pendingUsers] = await dbPool.query("SELECT COUNT(*) as count FROM pending_users");
            if (pendingUsers[0].count > 0) {
                notifications.push({ text: `${pendingUsers[0].count} new user(s) awaiting approval.`, view: 'admin-pending-users-view' });
            }
            const [pendingReqs] = await dbPool.query("SELECT COUNT(DISTINCT requisition_id) as count FROM requisitions WHERE status = 'Pending Approval'");
            if (pendingReqs[0].count > 0) {
                notifications.push({ text: `${pendingReqs[0].count} new requisition(s) to approve.`, view: 'admin-pending-reqs-view' });
            }
        } else if (role === 'Vendor') {
            const [newItems] = await dbPool.query("SELECT COUNT(DISTINCT ri.item_id) as count FROM requisition_items ri JOIN requisition_assignments ra ON ri.requisition_id = ra.requisition_id WHERE ra.vendor_id = ? AND ri.status = 'Active' AND ri.created_at > DATE_SUB(NOW(), INTERVAL 1 DAY)", [userId]);
            if (newItems[0].count > 0) {
                 notifications.push({ text: `${newItems[0].count} new item(s) assigned for bidding.`, view: 'vendor-requirements-view' });
            }
        } else { // User
            const [processedItems] = await dbPool.query("SELECT COUNT(*) as count FROM requisitions WHERE created_by = ? AND status = 'Processed' AND approved_at > DATE_SUB(NOW(), INTERVAL 1 DAY)", [userId]);
            if(processedItems[0].count > 0) {
                 notifications.push({ text: `${processedItems[0].count} of your requisitions have been processed.`, view: 'user-status-view' });
            }
        }
        res.json({ success: true, data: notifications });
    } catch (error) {
        next(error);
    }
});

// --- 7. MISC & EMAIL ---
app.post('/api/send-email', authenticateToken, async (req, res, next) => {
    if (!process.env.SENDGRID_API_KEY || !process.env.SENDGRID_API_KEY.startsWith('SG.')) {
        console.error("====== INVALID SENDGRID CONFIGURATION ======");
        console.error("CRITICAL: SENDGRID_API_KEY is missing from .env or does not start with 'SG.'. Email sending is disabled.");
        return res.json({ success: true, message: 'Email service not configured, but proceeding.' });
    }

    // NEW FEATURE: Handle CC
    const { recipient, subject, htmlBody, cc } = req.body;
    const msg = {
        to: recipient,
        from: process.env.FROM_EMAIL,
        subject: subject,
        html: htmlBody,
    };

    if (cc && cc.length > 0) {
        msg.cc = cc;
    }

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
    console.error("TIMESTAMP: ", new Date().toISOString());
    console.error("ROUTE: ", req.method, req.originalUrl);
    console.error("ERROR_MESSAGE: ", err.message);
    console.error("FULL_ERROR_OBJECT:", err);
    res.status(500).send({
        success: false,
        message: err.message || 'Something went wrong on the server!',
        error: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
});

// ================== SERVER START ==================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server is running on http://localhost:${PORT}`));
