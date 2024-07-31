// studentRouter.js
import express from 'express';
import { Student } from '../models/Student.js';
import bcrypt from 'bcryptjs';
import { verifyAdmin } from '../routes/auth.js'; // Ensure this middleware is properly implemented

const router = express.Router();

router.post('/register', verifyAdmin, async (req, res) => {
    try {
        console.log("Request body:", req.body); // Log request body
        const { username, password, roll, grade } = req.body;

        // Check if student already exists
        const student = await Student.findOne({ username });
        if (student) {
            console.log("Student already exists:", student);
            return res.json({ message: "Student is already registered" });
        }

        // Hash the password
        const hashPassword = await bcrypt.hash(password, 10);

        // Create new student
        const newStudent = new Student({
            username,
            password: hashPassword,
            roll,
            grade
        });

        // Save to database
        await newStudent.save();
        console.log("Student registered successfully");
        return res.json({ registered: true });
    } catch (err) {
        console.error("Error in registering student:", err); // Improved error logging
        return res.status(500).json({ message: "Error in registering student" });
    }
});

export { router as studentRouter };