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

// ===== Serve index.html for the root URL ('Cannot GET /' error) =====
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
    dateStrings: true
};

if (process.env.DB_CA_CERT_CONTENT) {
    dbConfig.ssl = {
        ca: process.env.DB_CA_CERT_CONTENT
    };
} else if (process.env.NODE_ENV === 'production' && !process.env.DB_CA_CERT_CONTENT) {
    console.warn("WARNING: DB_CA_CERT_CONTENT is not set. SSL connection might fail.");
} else {
    try {
        dbConfig.ssl = {
            ca: fs.readFileSync(path.join(__dirname, 'ca.pem'))
        };
    } catch (e) {
        console.warn("ca.pem not found. Proceeding without SSL certificate.");
    }
}

const dbPool = mysql.createPool(dbConfig);

// ================== FILE STORAGE (NOW WITH CLOUDINARY) ==================
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'procurement_uploads',
        upload_preset: 'ml_default',
        resource_type: 'auto',
        allowed_formats: ['jpg', 'jpeg', 'png', 'pdf'],
        public_id: (req, file) => `${Date.now()}-${file.originalname.replace(/\s/g, '_')}`,
    },
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
        console.error("LOGIN_ERROR_DETAIL:", error);
        next(error);
    }
});

app.post('/api/register', async (req, res, next) => {
    try {
        const { FullName, Email, Password, Role, CompanyName, ContactNumber, GSTIN } = req.body;
        const hashedPassword = await bcrypt.hash(Password, 10);
        await dbPool.query('INSERT INTO pending_users (full_name, email, password, role, company_name, contact_number, gstin, submitted_at) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())', [FullName, Email, hashedPassword, Role, CompanyName, ContactNumber, GSTIN]);

        try {
            const [admins] = await dbPool.query("SELECT email FROM users WHERE role = 'Admin' AND is_active = 1");
            const adminEmails = admins.map(a => a.email);

            sgMail.send({
                to: Email,
                from: process.env.FROM_EMAIL,
                subject: "Registration Received - Awaiting Approval",
                html: `<p>Dear ${FullName},</p><p>Thank you for registering with DEB'S PROCUREMENT. Your account is currently pending approval from an administrator. You will be notified once your account is activated.</p><p>Regards,<br>The Procurement Team</p>`
            }).catch(console.error);

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
        const query = `
            SELECT
                ri.item_name,
                ri.item_code,
                ri.unit,
                ri.freight_required,
                SUM(ri.quantity) as quantity,
                GROUP_CONCAT(ri.item_id SEPARATOR ',') as original_item_ids,
                (SELECT b.bid_status FROM bids b JOIN requisition_items ri2 ON b.item_id = ri2.item_id WHERE ri2.item_code = ri.item_code AND b.vendor_id = ? ORDER BY b.submitted_at DESC LIMIT 1) AS my_bid_status,
                (SELECT b.ex_works_rate FROM bids b JOIN requisition_items ri2 ON b.item_id = ri2.item_id WHERE ri2.item_code = ri.item_code AND b.vendor_id = ? ORDER BY b.submitted_at DESC LIMIT 1) AS my_ex_works_rate,
                (SELECT b.freight_rate FROM bids b JOIN requisition_items ri2 ON b.item_id = ri2.item_id WHERE ri2.item_code = ri.item_code AND b.vendor_id = ? ORDER BY b.submitted_at DESC LIMIT 1) AS my_freight_rate
            FROM requisition_items ri
            JOIN requisition_assignments ra ON ri.requisition_id = ra.requisition_id
            WHERE ra.vendor_id = ? AND ri.status = 'Active'
            GROUP BY ri.item_name, ri.item_code, ri.unit, ri.freight_required
            ORDER BY ri.item_name ASC;
        `;
        const [items] = await dbPool.query(query, [req.user.userId, req.user.userId, req.user.userId, req.user.userId]);

        for (const item of items) {
            item.my_bid_amount = (parseFloat(item.my_ex_works_rate || 0) + parseFloat(item.my_freight_rate || 0)) * parseFloat(item.quantity);
            if (item.my_bid_amount > 0) {
                const [rankResult] = await dbPool.query(
                    `SELECT COUNT(DISTINCT vendor_id) + 1 as \`rank\` FROM bids WHERE item_id IN (?) AND bid_amount < ?`,
                    [item.original_item_ids.split(','), item.my_bid_amount]
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
        const { bids } = req.body;
        
        await connection.beginTransaction();
        const invalidBids = [];

        for (const bid of bids) {
            const originalItemIds = bid.original_item_ids.split(',');
            const [[countResult]] = await connection.query('SELECT COUNT(*) as count FROM bidding_history_log WHERE item_id = ? AND vendor_id = ?', [originalItemIds[0], req.user.userId]);
            
            if (countResult.count >= 3) {
                invalidBids.push(bid.item_name);
                continue;
            }
            
            for (const itemId of originalItemIds) {
                const [[itemDetails]] = await connection.query('SELECT quantity FROM requisition_items WHERE item_id = ?', [itemId]);
                const totalBidAmount = (parseFloat(bid.ex_works_rate) + parseFloat(bid.freight_rate)) * parseFloat(itemDetails.quantity);
                
                // Delete previous bids for this item to keep only the latest in 'bids' table for live ranking
                await connection.query('DELETE FROM bids WHERE item_id = ? AND vendor_id = ?', [itemId, req.user.userId]);
                
                const [result] = await connection.query("INSERT INTO bids (item_id, vendor_id, bid_amount, ex_works_rate, freight_rate, comments, bid_status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    [itemId, req.user.userId, totalBidAmount, bid.ex_works_rate, bid.freight_rate, bid.comments, 'Submitted']);
                
                // Also log the bid in history
                await connection.query("INSERT INTO bidding_history_log (bid_id, item_id, vendor_id, bid_amount, ex_works_rate, freight_rate, bid_status, submitted_at) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())",
                    [result.insertId, itemId, req.user.userId, totalBidAmount, bid.ex_works_rate, bid.freight_rate, 'Submitted']);
            }
        }
        
        await connection.commit();
        
        if (invalidBids.length > 0) {
            res.status(200).json({ success: true, message: `Some bids were skipped. You have reached the max bids for: ${invalidBids.join(', ')}. Other bids were submitted successfully.` });
        } else {
            res.json({ success: true, message: 'Bids submitted successfully!' });
        }
    } catch (error) {
        if(connection) await connection.rollback();
        next(error);
    } finally {
        if(connection) connection.release();
    }
});

app.get('/api/vendor/dashboard-stats', authenticateToken, async (req, res, next) => {
    try {
        const vendorId = req.user.userId;
        
        const assignedQuery = "SELECT COUNT(DISTINCT ri.item_code) as count FROM requisition_items ri JOIN requisition_assignments ra ON ri.requisition_id = ra.requisition_id WHERE ra.vendor_id = ? AND ri.status = 'Active'";
        const submittedQuery = "SELECT COUNT(DISTINCT item_code) as count FROM bids b JOIN requisition_items ri ON b.item_id = ri.item_id WHERE b.vendor_id = ?";
        const wonQuery = "SELECT COUNT(*) as count, SUM(awarded_amount) as totalValue FROM awarded_contracts WHERE vendor_id = ?";
        const needsBidQuery = "SELECT COUNT(DISTINCT ri.item_code) as count FROM requisition_items ri JOIN requisition_assignments ra ON ri.requisition_id = ra.requisition_id WHERE ra.vendor_id = ? AND ri.status = 'Active' AND ri.item_id NOT IN (SELECT item_id FROM bids WHERE vendor_id = ? AND bid_status='Submitted')";
        const l1BidsQuery = "SELECT COUNT(DISTINCT b.item_id) as count FROM bids b WHERE b.vendor_id = ? AND b.bid_amount = (SELECT MIN(bid_amount) FROM bids WHERE item_id = b.item_id)";
        
        const recentBidsQuery = `SELECT b.bid_amount, b.bid_status, ri.item_name FROM bids b JOIN requisition_items ri ON b.item_id = ri.item_id WHERE b.vendor_id = ? ORDER BY b.submitted_at DESC LIMIT 5`;
        
        const avgRankQuery = `
            SELECT AVG(ranked_bids.rank) as avg_rank 
            FROM (
                SELECT b.bid_amount, b.item_id, 
                (SELECT COUNT(DISTINCT b2.vendor_id) FROM bids b2 WHERE b2.item_id = b.item_id AND b2.bid_amount < b.bid_amount) + 1 as \`rank\`
                FROM bids b 
                WHERE b.vendor_id = ? AND b.bid_status IN ('Submitted', 'Awarded', 'Rejected')
                GROUP BY b.item_id
            ) as ranked_bids`;
        const bidCountQuery = "SELECT COUNT(DISTINCT item_id) as count FROM bids WHERE vendor_id = ?";
        
        const [
            [assignedRows], [submittedRows], [wonRows], [needsBidRows], [l1BidsRows], recentBids, [avgRankResultRows], [bidCountResultRows],
        ] = await Promise.all([
            dbPool.query(assignedQuery, [vendorId]),
            dbPool.query(submittedQuery, [vendorId]),
            dbPool.query(wonQuery, [vendorId]),
            dbPool.query(needsBidQuery, [vendorId, vendorId]),
            dbPool.query(l1BidsQuery, [vendorId]),
            dbPool.query(recentBidsQuery, [vendorId]),
            dbPool.query(avgRankQuery, [vendorId]),
            dbPool.query(bidCountQuery, [vendorId]),
        ]);

        const assigned = assignedRows[0];
        const submitted = submittedRows[0];
        const won = wonRows[0];
        const needsBid = needsBidRows[0];
        const l1Bids = l1BidsRows[0];
        const avgRankResult = avgRankResultRows[0];
        const bidCountResult = bidCountResultRows[0];

        const totalBids = bidCountResult.count;
        const contractsWonCount = won.count;
        const winRate = totalBids > 0 ? (contractsWonCount / totalBids) * 100 : 0;

        res.json({
            success: true,
            data: {
                assignedItems: assigned.count,
                submittedBids: submitted.count,
                contractsWon: contractsWonCount,
                totalWonValue: won.totalValue || 0,
                needsBid: needsBid.count,
                l1Bids: l1Bids.count,
                recentBids: recentBids,
                avgRank: avgRankResult.avg_rank,
                winRate: winRate,
            }
        });
    } catch (error) {
        next(error);
    }
});


app.get('/api/vendor/my-bids', authenticateToken, async (req, res, next) => {
    try {
        const query = `
            SELECT 
                MAX(b.bid_id) as bid_id,
                MAX(b.bid_amount) as bid_amount,
                MAX(b.ex_works_rate) as ex_works_rate,
                MAX(b.freight_rate) as freight_rate,
                MAX(b.comments) as comments,
                MAX(b.bid_status) as bid_status,
                MAX(b.submitted_at) as submitted_at,
                ri.item_name, 
                ri.requisition_id, 
                ri.item_sl_no,
                (SELECT COUNT(DISTINCT b2.vendor_id) FROM bids b2 WHERE b2.item_id = ri.item_id AND b2.bid_amount < MAX(b.bid_amount)) + 1 AS \`rank\`
            FROM bids b
            JOIN requisition_items ri ON b.item_id = ri.item_id
            WHERE b.vendor_id = ?
            GROUP BY ri.item_id
            ORDER BY MAX(b.submitted_at) DESC;
        `;
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
        
        const latestReqsQuery = `SELECT r.requisition_id, r.status, r.created_at, u.full_name as creator_name, (SELECT COUNT(*) FROM requisition_items ri WHERE ri.requisition_id = r.requisition_id) as item_count FROM requisitions r JOIN users u ON r.created_by = u.user_id ORDER BY r.created_at DESC LIMIT 5`;
        
        const notificationsQuery = `SELECT CONCAT('New user registered: ', full_name) AS text, submitted_at AS timestamp FROM pending_users ORDER BY submitted_at DESC LIMIT 5`;
        
        const reqTrendsQuery = `SELECT DATE_FORMAT(created_at, '%Y-%m') as month, COUNT(*) as count FROM requisitions WHERE status != 'Pending Approval' GROUP BY month ORDER BY month ASC`;
        const biddingActivityQuery = `
            SELECT u.full_name, COUNT(DISTINCT b.item_id) as bid_count
            FROM bids b
            JOIN users u ON b.vendor_id = u.user_id
            GROUP BY u.full_name
            ORDER BY bid_count DESC LIMIT 5
        `;

        const [
            [activeItemsRows], [pendingUsersRows], [awardedRows], [pendingReqsRows],
            latestReqs, notifications, reqTrends, biddingActivity
        ] = await Promise.all([
            dbPool.query(activeItemsQuery), 
            dbPool.query(pendingUsersQuery), 
            dbPool.query(awardedQuery),
            dbPool.query(pendingReqsQuery), 
            dbPool.query(latestReqsQuery), 
            dbPool.query(notificationsQuery),
            dbPool.query(reqTrendsQuery),
            dbPool.query(biddingActivityQuery)
        ]);

        const activeItems = activeItemsRows[0];
        const pendingUsers = pendingUsersRows[0];
        const awarded = awardedRows[0];
        const pendingReqs = pendingReqsRows[0];

        const reqTrendsChart = {
            labels: reqTrends.map(row => row.month),
            data: reqTrends.map(row => row.count)
        };
        
        const biddingActivityChart = {
            labels: biddingActivity.map(row => row.full_name),
            data: biddingActivity.map(row => row.bid_count)
        };

        res.json({
            success: true,
            data: { 
                activeItems: activeItems.count, 
                pendingUsers: pendingUsers.count, 
                awardedContracts: awarded.count,
                pendingRequisitionsCount: pendingReqs.count,
                latestRequisitions: latestReqs,
                notifications: notifications,
                charts: {
                    reqTrends: reqTrendsChart,
                    biddingActivity: biddingActivityChart
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
                const values = vendorAssignments.map(vId => [requisitionId, vId, new Date()]);
                await connection.query('INSERT INTO requisition_assignments (requisition_id, vendor_id, assigned_at) VALUES ?', [values]);
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
        const query = `
            SELECT
                ac.*,
                ri.item_sl_no,
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
        let dateFilter = '';
        const params = [];

        if (startDate && endDate) {
            dateFilter = ' WHERE awarded_date BETWEEN ? AND ?';
            params.push(startDate, `${endDate} 23:59:59`);
        }

        const [kpisResult, detailedReport, vendorSpend, awardedValue] = await Promise.all([
            dbPool.query(`
                SELECT
                    COALESCE(SUM(ac.awarded_amount), 0) AS totalSpend,
                    COUNT(ac.item_id) as awardedItemsCount,
                    COALESCE(SUM(CASE WHEN ac.awarded_amount = (SELECT MIN(b.bid_amount) FROM bids b WHERE b.item_id = ac.item_id) THEN 1 ELSE 0 END), 0) as l1AwardsCount,
                    AVG(DATEDIFF(r.approved_at, r.created_at)) as avgApprovalTime
                FROM awarded_contracts ac
                JOIN requisition_items ri ON ac.item_id = ri.item_id
                LEFT JOIN requisitions r ON ri.requisition_id = r.requisition_id
                ${dateFilter}`, params),

            dbPool.query(`
                SELECT ac.awarded_amount, DATE_FORMAT(ac.awarded_date, '%Y-%m-%d') as awarded_date,
                        ri.requisition_id, ri.item_sl_no, ri.item_name, u.full_name as vendor_name
                FROM awarded_contracts ac
                JOIN requisition_items ri ON ac.item_id = ri.item_id
                JOIN users u ON ac.vendor_id = u.user_id
                ${dateFilter}
                ORDER BY ac.awarded_date DESC`, params),

            dbPool.query(`
                SELECT u.full_name as vendor, SUM(ac.awarded_amount) as total_spend
                FROM awarded_contracts ac
                JOIN users u ON ac.vendor_id = u.user_id
                ${dateFilter}
                GROUP BY u.full_name
                ORDER BY total_spend DESC LIMIT 5`, params),

            dbPool.query(`
                SELECT DATE_FORMAT(ac.awarded_date, '%Y-%m') as month, SUM(ac.awarded_amount) as total_awarded
                FROM awarded_contracts ac
                ${dateFilter}
                GROUP BY month
                ORDER BY month ASC`, params)
        ]);

        const kpis = kpisResult[0][0];
        const totalAwarded = kpis.awardedItemsCount;
        const l1AwardRate = totalAwarded > 0 ? (kpis.l1AwardsCount / totalAwarded) * 100 : 0;

        const vendorSpendData = {};
        vendorSpend[0].forEach(row => { vendorSpendData[row.vendor] = parseFloat(row.total_spend); });

        const awardedValueData = {};
        awardedValue[0].forEach(row => { awardedValueData[row.month] = parseFloat(row.total_awarded); });

        res.json({
            success: true,
            data: {
                detailedReport: detailedReport[0],
                kpis: {
                    totalSpend: kpis.totalSpend,
                    l1AwardRate: l1AwardRate,
                    awardedItemsCount: totalAwarded,
                    avgApprovalTime: kpis.avgApprovalTime || 0
                },
                charts: {
                    vendorSpend: vendorSpendData,
                    awardedValue: awardedValueData
                }
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
            const values = parsedVendorIds.map(vId => [reqId, vId, new Date()]);
            await connection.query('INSERT INTO requisition_assignments (requisition_id, vendor_id, assigned_at) VALUES ?', [values]);
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
        res.json({ success: true, message: 'User updated successfully.' });
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

app.post('/api/notifications/mark-all-read', authenticateToken, async (req, res, next) => {
    try {
        await dbPool.query("UPDATE messages SET is_read = 1 WHERE recipient_id = ?", [req.user.userId]);
        res.json({ success: true, message: 'All notifications marked as read.' });
    } catch (error) {
        next(error);
    }
});

app.get('/api/notifications', authenticateToken, async (req, res, next) => {
    try {
        const { userId, role } = req.user;
        let notifications = [];

        const [msgCount] = await dbPool.query("SELECT COUNT(*) as count FROM messages WHERE recipient_id = ? AND is_read = 0", [userId]);
        if (msgCount[0].count > 0) {
            notifications.push({ text: `You have ${msgCount[0].count} new message(s).`, view: 'messaging-view' });
        }

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
            const [newItems] = await dbPool.query("SELECT COUNT(DISTINCT ri.item_id) as count FROM requisition_items ri JOIN requisition_assignments ra ON ri.requisition_id = ra.requisition_id WHERE ra.vendor_id = ? AND ri.status = 'Active' AND ra.assigned_at > DATE_SUB(NOW(), INTERVAL 1 DAY)", [userId]);
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

app.get('/api/sidebar-counts', authenticateToken, async (req, res, next) => {
    try {
        const { userId, role } = req.user;
        let counts = {
            unreadMessages: 0,
            pendingReqs: 0,
            pendingUsers: 0
        };

        const [msgCount] = await dbPool.query("SELECT COUNT(*) as count FROM messages WHERE recipient_id = ? AND is_read = 0", [userId]);
        counts.unreadMessages = msgCount[0].count;

        if (role === 'Admin') {
            const [pendingUsers] = await dbPool.query("SELECT COUNT(*) as count FROM pending_users");
            counts.pendingUsers = pendingUsers[0].count;

            const [pendingReqs] = await dbPool.query("SELECT COUNT(DISTINCT requisition_id) as count FROM requisitions WHERE status = 'Pending Approval'");
            counts.pendingReqs = pendingReqs[0].count;
        }

        res.json({ success: true, data: counts });
    } catch (error) {
        next(error);
    }
});


// --- 7. MISC & EMAIL ---
app.post('/api/send-email', authenticateToken, async (req, res, next) => {
    if (!process.env.SENDGRID_API_KEY || !process.env.SENDGRID_API_KEY.startsWith('SG.')) {
        console.error("====== INVALID SENDGRID CONFIGURATION ======");
        return res.json({ success: true, message: 'Email service not configured, but proceeding.' });
    }

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

