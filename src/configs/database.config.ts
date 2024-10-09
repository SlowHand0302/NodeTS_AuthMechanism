import mongoose from 'mongoose';
import dotenv from 'dotenv';
dotenv.config();
const DB_URL: string = process.env.DB_URL || 'mongodb://localhost:27017/SocketChatApp';

async function connect() {
    mongoose.set('debug', true);
    mongoose.set('debug', { color: true });
    await mongoose
        .connect(DB_URL)
        .then(() => {
            console.log(`Database connected on ${DB_URL}`);
        })
        .catch((err) => {
            console.log(err);
        });
}

export { connect };
