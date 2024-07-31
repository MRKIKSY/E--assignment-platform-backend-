// import bcrypt from 'bcryptjs';
// import { Admin } from './models/Admin.js';
// import './db.js'; // Ensure your DB connection is established

// async function AdminAccount() {
//     try {
//         const adminCount = await Admin.countDocuments();
//         if (adminCount === 0) {
//             const hashPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10);
//             const newAdmin = new Admin({
//                 username: process.env.ADMIN_USERNAME,
//                 password: hashPassword
//             });
//             await newAdmin.save();
//             console.log("Admin account created");
//         } else {
//             console.log("Admin account already exists");
//         }
//     } catch (err) {
//         console.error("Error creating admin account:", err);
//     }
// }

// AdminAccount();

