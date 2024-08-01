import express from 'express';
import { Admin } from '../models/Admin.js';
import { Student } from '../models/Student.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

const router = express.Router();

// Login route
router.post('/login', async (req, res) => {
  try {
    const { username, password, role } = req.body;

    if (role === 'admin') {
      const admin = await Admin.findOne({ username });
      if (!admin) {
        return res.status(401).json({ message: "Admin not registered" });
      }
      const validPassword = await bcrypt.compare(password, admin.password);
      if (!validPassword) {
        return res.status(401).json({ message: "Wrong password" });
      }
      const token = jwt.sign({ username: admin.username, role: 'admin' }, process.env.Admin_Key, { expiresIn: '1h' });
      
      res.cookie('token', token, { 
        httpOnly: true, 
        secure: true, // Set to true if you're serving over HTTPS
        sameSite: 'None' 
      });
  
      return res.json({ login: true, role: 'admin', token });
    } else if (role === 'student') {
      const student = await Student.findOne({ username });
      if (!student) {
        return res.status(401).json({ message: "Student not registered" });
      }
      const validPassword = await bcrypt.compare(password, student.password);
      if (!validPassword) {
        return res.status(401).json({ message: "Wrong password" });
      }
      const token = jwt.sign({ username: student.username, role: 'student' }, process.env.Student_Key, { expiresIn: '1h' });
      return res.json({ login: true, role: 'student', token });
    } else {
      return res.status(400).json({ message: "Invalid role" });
    }
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Verify admin middleware
const verifyAdmin = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
      console.log("Authorization header missing");
      return res.status(403).json({ message: "Authorization header missing" });
  }

  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.Admin_Key, (err, decoded) => {
      if (err) {
          console.log("Token verification failed:", err);
          return res.status(403).json({ message: "Invalid token" });
      }

      req.username = decoded.username;
      req.role = decoded.role;
      next();
  });
};


// Verify user middleware
const verifyUser = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(403).json({ message: "Authorization header missing" });
  }
  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.Student_Key, (err, decoded) => {
    if (err) {
      jwt.verify(token, process.env.Admin_Key, (err, decoded) => {
        if (err) {
          return res.status(403).json({ message: "Invalid token" });
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

// Verify route
router.get('/verify', verifyUser, (req, res) => {
  return res.json({ login: true, role: req.role });
});

// Logout route
router.get('/logout', (req, res) => {
  // Clear the token from client-side storage
  return res.json({ logout: true });
});

export { router as AdminRouter, verifyAdmin };
