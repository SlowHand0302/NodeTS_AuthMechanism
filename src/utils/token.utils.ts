import { Response } from 'express';
import jwt from 'jsonwebtoken';
import { Types } from 'mongoose';

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
