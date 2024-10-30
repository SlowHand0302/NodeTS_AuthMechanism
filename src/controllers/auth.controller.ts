import { NextFunction, Request, Response } from 'express';
import createHttpError from 'http-errors';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { LoginTicket, OAuth2Client, TokenPayload } from 'google-auth-library';
import dotenv from 'dotenv';
dotenv.config();

import UserService from '../services/User.services';
import { User } from '../entities/User.entity';
import { generateToken } from '../utils/token.utils';
import { sendMail } from '../utils/mailer.utils';
import { SendMailOptions } from 'nodemailer';

const oAuth2Client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, 'postmessage');

class AuthController {
    static async signUp(req: Request, res: Response, next: NextFunction) {
        const user: User = { ...req.body };
        const services = new UserService();
        try {
            const existed = await services.findByEmail(user.email);
            if (existed) {
                return next(createHttpError(401, 'Existed Email'));
            }
            const createdUser = services.create(user);
            return res.status(200).json({
                statusCode: 200,
                msg: 'Create new user success',
                metadata: { ...createdUser },
            });
        } catch (error) {
            next();
            throw error;
        }
    }

    // multi-session authentication
    static async signIn(req: Request, res: Response, next: NextFunction) {
        const user: Pick<User, 'email' | 'password'> = { ...req.body };
        const services = new UserService();
        try {
            const existed = await services.findByEmail(user.email);
            if (!existed) {
                return next(createHttpError(404, 'Not Found User'));
            }
            if (existed?.password !== user.password) {
                return next(createHttpError(401, 'Wrong password'));
            }

            generateToken(res, existed._id);

            return res.status(200).json({
                statusCode: 200,
                msg: 'Signed In Success',
                metadata: { ...existed },
            });
        } catch (error) {
            next(error);
            throw error;
        }
    }

    static async signInWithGoogle(req: Request, res: Response, next: NextFunction) {
        const { code } = req.body;
        const services = new UserService();

        try {
            const response = await oAuth2Client.getToken(code);
            const token = response.tokens;
            const ticket = await oAuth2Client
                .verifyIdToken({
                    idToken: token.id_token as string,
                    audience: process.env.GOOGLE_CLIENT_ID,
                })
                .then((ticket): LoginTicket => ticket)
                .catch((error) => {
                    next(error);
                    throw error;
                });
            const payload = (ticket as LoginTicket).getPayload();
            const existed = await services.findByEmail((payload as TokenPayload).email as string);
            console.log(existed);

            if (!existed) {
                const user = await services.create({
                    fullname: (payload as TokenPayload).name as string,
                    username: (payload as TokenPayload).email as string,
                    email: (payload as TokenPayload).email as string,
                });
                if (user) {
                    generateToken(res, user._id);
                    return res.status(200).json({
                        statusCode: 200,
                        msg: 'Signed In Success',
                        metadata: { ...user },
                    });
                }
            }
            if (existed) {
                generateToken(res, existed._id);
            }
            return res.status(200).json({
                statusCode: 200,
                msg: 'Signed In Success',
                metadata: { ...existed },
            });
        } catch (error) {
            next(error);
            throw error;
        }
    }

    static async signOut(req: Request, res: Response, next: NextFunction) {
        res.clearCookie('token');
        return res.status(200).json({
            statusCode: 200,
            msg: 'Signed Out Success',
        });
    }

    // multi-session verify authorization
    static async verifyAuth(req: Request, res: Response, next: NextFunction) {
        const token = req.cookies.token;
        if (!token) {
            next(createHttpError(401, 'No credentials provide'));
            return;
        }
        jwt.verify(token as string, process.env.SECRET_KEY as string, (err, decoded) => {
            if (err) {
                next(createHttpError(401, 'Credential Expired'));
                return;
            }
            const payload = decoded as JwtPayload;
            (req as any)._id = payload._id;
            next();
        });
    }

    static async resetPassword(req: Request, res: Response, next: NextFunction) {
        const { email } = req.body;
        const service = new UserService();
        const mailOptions: SendMailOptions = {
            to: email,
            subject: 'Hello World',
            html: '<h3>Hello worlds</h3>',
        };
        try {
            const existed = await service.findByEmail(email);
            if (!existed) {
                return next(createHttpError(404, 'Email Not Existed in System'));
            }
            const result = await sendMail(mailOptions);
            if (result) {
                return res.status(200).json({
                    statusCode: 200,
                    msg: 'OTP Sent',
                    metadata: { ...result },
                });
            }
        } catch (error) {
            next(error);
            throw error;
        }
    }
}

export default AuthController;
