import express from 'express';
import { Admin } from '../models/Admin.js';
import { Student } from '../models/Student.js';
import bcrypt from 'bcryptjs';

const router = express.Router();

router.post('/login', async (req, res) => {
    try {
        const { username, password, role } = req.body;
        let user;

        if (role === 'admin') {
            user = await Admin.findOne({ username });
        } else if (role === 'student') {
            user = await Student.findOne({ username });
        }

        if (!user) {
            return res.status(401).json({ message: `${role} not registered` });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ message: "Wrong password" });
        }

        // Just return a successful response
        return res.json({ login: true, role });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Internal server error" });
    }
});

const verifyAdmin = (req, res, next) => {
    // Remove token verification logic
    // You can replace this with any other authorization check if needed
    next(); 
};

const verifyUser = (req, res, next) => {
    // Remove token verification logic
    // You can replace this with any other authorization check if needed
    next();
};

router.get('/verify', verifyUser, (req, res) => {
    return res.json({ login: true, role: 'guest' }); // Adjust response as needed
});

router.get('/logout', (req, res) => {
    // Remove cookie clearing logic
    return res.json({ logout: true });
});

export { router as AdminRouter, verifyAdmin, verifyUser };
