import mongoose from "mongoose";
import dotenv from 'dotenv';
dotenv.config();

const Connection = async () => {
    try {
        await mongoose.connect(process.env.MONGODB_URL);
        console.log("Connected");
    } catch (err) {
        console.log("Error: " + err);
    }
};

Connection();

