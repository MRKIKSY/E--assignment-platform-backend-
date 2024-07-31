import mongoose from "mongoose";
import dotenv from 'dotenv';
dotenv.config();

const Connection = async () => {
    try {
        await mongoose.connect(process.env.MONGODB_URL, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        console.log("Connected");
    } catch (err) {
        console.log("Error: " + err);
    }
};

Connection();
