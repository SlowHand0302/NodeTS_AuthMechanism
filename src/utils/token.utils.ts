import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { Types } from 'mongoose';

export const generateAccessToken = (req: Request, userId: Types.ObjectId) => {
    const token = jwt.sign({ _id: userId }, process.env.SECRET_KEY as string, { expiresIn: '1m' });
    if (token) {
        req.session.accessToken = token;
        req.session.save();
        console.log('AccessToken Generated');
    }
};

export const generateRefreshToken = (res: Response, userId: Types.ObjectId) => {
    const token = jwt.sign({ _id: userId }, process.env.SECRET_KEY as string, { expiresIn: '2m' });

    if (token) {
        res.cookie('refreshToken', token, { httpOnly: true, maxAge: 2 * 60000 });
        console.log('RefreshToken Generated');
    }
};
