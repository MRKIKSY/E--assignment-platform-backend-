import express from 'express';
import bcrypt from 'bcrypt';
import { Student } from './models/Student.js';
import './db.js';

async function SeedStudents() {
    try {
        // Example students data
        const studentsData = [
            {
                username: 'student1',
                password: 'password1',
                roll: '101',
                grade: 'A'
            },
            {
                username: 'student2',
                password: 'password2',
                roll: '102',
                grade: 'B'
            },
            {
                username: 'student3',
                password: 'password3',
                roll: '103',
                grade: 'C'
            }
        ];

        for (let studentData of studentsData) {
            // Check if student already exists
            const studentExists = await Student.findOne({ username: studentData.username });
            if (studentExists) {
                console.log(`Student with username ${studentData.username} already exists.`);
                continue;
            }

            // Hash the password before saving
            const hashPassword = await bcrypt.hash(studentData.password, 10);

            // Create new student instance
            const newStudent = new Student({
                username: studentData.username,
                password: hashPassword,
                roll: studentData.roll,
                grade: studentData.grade
            });

            // Save the student to the database
            await newStudent.save();
            console.log(`Student ${studentData.username} created successfully.`);
        }

        console.log("Student seeding completed.");
    } catch (err) {
        console.error("Error seeding students:", err);
    }
}

SeedStudents();
