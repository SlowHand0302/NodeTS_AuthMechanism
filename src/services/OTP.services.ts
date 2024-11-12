import { redis } from '../configs/redis.config';
import { Types } from 'mongoose';

export type OTP = {
    userId: Types.ObjectId;
    email: string;
    otp: string;
};

export const generateOTP = async (userId: Types.ObjectId, email: string) => {
    const pin = Math.floor(100000 + Math.random() * 900000)
        .toString()
        .padStart(6, '0');
    const expirationTime = Date.now() + 5 * 60 * 1000;
    const otp: OTP = {
        userId,
        email,
        otp: pin,
    };
    await redis.setex(`otp:${email}`, expirationTime, JSON.stringify(otp), (err, reply) => {
        if (err) {
            console.log('Error storing OTP:', err);
        }
        console.log('OTP stored:', reply);
    });
    return pin;
};

export const validateOTP = async (email: string, otp: string) => {
    const result = await redis.get(`otp:${email}`);
    if (result) {
        const storedToken: OTP = JSON.parse(result);
        console.log(storedToken);
        if (storedToken.otp === otp) {
            await redis.del(`otp:${email}`);
            return storedToken.userId;
        }
    }
    return null;
};
