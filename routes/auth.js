import express from 'express';
import { Admin } from '../models/Admin.js';
import { Student } from '../models/Student.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

const router = express.Router();

router.post('/login', async (req, res) => {
    try {
        const { username, password, role } = req.body;
        let user, secretKey;

        if (role === 'admin') {
            user = await Admin.findOne({ username });
            secretKey = process.env.Admin_Key;
        } else if (role === 'student') {
            user = await Student.findOne({ username });
            secretKey = process.env.Student_Key;
        }

        if (!user) {
            return res.json({ message: `${role} not registered` });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.json({ message: "Wrong password" });
        }

        const token = jwt.sign({ username: user.username, role }, secretKey);
        res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });

        return res.json({ login: true, role });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Internal server error" });
    }
});

const verifyAdmin = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ message: "No token provided" }); // Changed to status 401 (Unauthorized)
    }

    jwt.verify(token, process.env.Admin_Key, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: "Invalid token" }); // Changed to status 401 (Unauthorized)
        }
        req.username = decoded.username;
        req.role = decoded.role;
        next();
    });
};

const verifyUser = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ message: "No token provided" });
    }

    jwt.verify(token, process.env.Admin_Key, (err, decoded) => {
        if (err) {
            // Log for debugging
            console.error("Admin Key verification failed:", err);

            // Try student key
            jwt.verify(token, process.env.Student_Key, (err, decoded) => {
                if (err) {
                    // Log for debugging
                    console.error("Student Key verification failed:", err);
                    return res.status(401).json({ message: "Invalid token" });
                }
                req.username = decoded.username;
                req.role = decoded.role;
                next();
            });
        } else {
            req.username = decoded.username;
            req.role = decoded.role;
            next();
        }
    });
};


router.get('/verify', verifyUser, (req, res) => {
    return res.json({ login: true, role: req.role });
});

router.get('/logout', (req, res) => {
    res.clearCookie('token');
    return res.json({ logout: true });
});

export { router as AdminRouter, verifyAdmin, verifyUser };
