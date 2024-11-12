import { Response } from 'express';
import jwt from 'jsonwebtoken';
import { Types } from 'mongoose';
import { redis } from '../configs/redis.config';

// multi-session with JWT
export const generateToken = (res: Response, userId: Types.ObjectId) => {
    const token = jwt.sign({ _id: userId }, process.env.SECRET_KEY as string, { expiresIn: '10m' });

    if (token) {
        res.cookie('token', token, {
            // can only be accessed by server requests
            httpOnly: true,
            // path = where the cookie is valid
            path: '/',
            // domain = what domain the cookie is valid on
            domain: 'localhost',
            // secure = only send cookie over https
            secure: false,
            // sameSite = only send cookie if the request is coming from the same origin
            // sameSite's "Strict" setting won't allow cross-origin and "none" only works if secure is true, so "lax" is the best option
            sameSite: 'lax', // "strict" | "lax" | "none" (secure must be true)
            // maxAge = how long the cookie is valid for in milliseconds
            maxAge: 3600000, // 1 hour
        });
    }
};

export const generateTokenSingle = async (res: Response, userId: Types.ObjectId) => {
    const token = jwt.sign({ _id: userId }, process.env.SECRET_KEY as string, { expiresIn: '10m' });

    if (token) {
        await redis.setex(`token:${userId}`, Date.now() + 10 * 60 * 1000, token, (error, reply) => {
            if (error) {
                console.log(error);
                throw error;
            }
            res.cookie('token', token, {
                // can only be accessed by server requests
                httpOnly: true,
                // path = where the cookie is valid
                path: '/',
                // domain = what domain the cookie is valid on
                domain: 'localhost',
                // secure = only send cookie over https
                secure: false,
                // sameSite = only send cookie if the request is coming from the same origin
                // sameSite's "Strict" setting won't allow cross-origin and "none" only works if secure is true, so "lax" is the best option
                sameSite: 'lax', // "strict" | "lax" | "none" (secure must be true)
                // maxAge = how long the cookie is valid for in milliseconds
                maxAge: 3600000, // 1 hour
            });
        });
    }
};

export const validateTokenSingle = async (userId: Types.ObjectId, token: string) => {
    const storedToken = await redis.get(`token:${userId}`);
    if (token !== storedToken || !storedToken) {
        return false;
    }
    return true;
};
