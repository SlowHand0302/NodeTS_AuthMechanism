import { redis } from '../configs/redis.config';

export const generateOTP = async (email: string) => {
    const otp = Math.floor(100000 + Math.random() * 900000)
        .toString()
        .padStart(6, '0');
    const expirationTime = Date.now() + 5 * 60 * 1000;
    await redis.setex(`otp:${email}`, expirationTime, otp, (err, reply) => {
        if (err) {
            console.log('Error storing OTP:', err);
        }
        console.log('OTP stored:', reply);
    });
    return otp;
};

export const validateOTP = async (email: string, otp: string) => {
    const storedOTP = await redis.get(`otp:${email}`);
    if (!storedOTP || storedOTP !== otp) {
        return false;
    }
    await redis.del(`otp:${email}`);
    return true;
};
