import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import './db.js';
import { AdminRouter } from './routes/auth.js';
import { studentRouter } from './routes/student.js';
import { bookRouter } from './routes/book.js';
import { Book } from './models/Book.js';
import { Student } from './models/Student.js';
import { Admin } from './models/Admin.js';
import jwt from 'jsonwebtoken';

// Set up __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
dotenv.config();

app.use(express.json());
app.use(cors({
    origin: [
        "https://e-assignment-platform.onrender.com"
    ],
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true
}));


app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/auth', AdminRouter);
app.use('/student', studentRouter);
app.use('/book', bookRouter);

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(403).json({ message: 'No token provided' });

    // First, try to verify with the Student_Key
    jwt.verify(token, process.env.Student_Key, (err, decoded) => {
        if (err) {
            // If verification with Student_Key fails, try Admin_Key
            jwt.verify(token, process.env.Admin_Key, (err, decoded) => {
                if (err) return res.status(403).json({ message: 'Invalid token' });

                req.user = decoded;
                next();
            });
        } else {
            req.user = decoded;
            next();
        }
    });
};


app.post('/book/add', verifyToken, async (req, res) => {
    const { name, author } = req.body;
    try {
        const newBook = new Book({ name, author });
        await newBook.save();
        res.json({ added: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/dashboard', async (req, res) => {
    try {
        const student = await Student.countDocuments();
        const admin = await Admin.countDocuments();
        const book = await Book.countDocuments();
        return res.json({ ok: true, student, book, admin });
    } catch (err) {
        return res.json(err);
    }
});

app.listen(process.env.PORT, () => {
    console.log("Server is Running");
});
