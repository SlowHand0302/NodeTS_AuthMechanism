import { NextFunction, Request, Response } from 'express';
import createHttpError from 'http-errors';
import { Types } from 'mongoose';
import jwt, { JwtPayload } from 'jsonwebtoken';
import UserService from '../services/User.services';
import { User } from '../entities/User.entity';
import { generateRefreshToken, generateAccessToken } from '../utils/token.utils';
import dotenv from 'dotenv';
dotenv.config();

class AuthController {
    static async signUp(req: Request, res: Response, next: NextFunction) {
        const user: User = { ...req.body };
        const services = new UserService();
        try {
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

            generateAccessToken(req, existed._id);
            generateRefreshToken(res, existed._id);

            return res.status(200).json({
                statusCode: 200,
                msg: 'Signed In Success',
                metadata: { ...existed },
            });
        } catch (error) {
            next();
            throw error;
        }
    }

    static async signOut(req: Request, res: Response, next: NextFunction) {
        req.session.destroy((err) => {
            if (err) {
                next(createHttpError(500, 'Internal Server Error'));
                throw err;
            }
            res.clearCookie('refreshToken');
            return res.status(200).json({
                statusCode: 200,
                msg: 'Signed Out Success',
            });
        });
    }

    static async verifyAuth(req: Request, res: Response, next: NextFunction) {
        const accessToken = req.session.accessToken;
        const refreshToken = req.cookies.refreshToken;
        if (!accessToken && !refreshToken) {
            next(createHttpError(401, 'No credentials provide'));
            return;
        }
        jwt.verify(accessToken as string, process.env.SECRET_KEY as string, (err, accessTokenDecoded) => {
            if (err) {
                return jwt.verify(
                    refreshToken as string,
                    process.env.SECRET_KEY as string,
                    (err, refreshTokenDecoded) => {
                        if (err) {
                            next(createHttpError(401, 'Credential Expired'));
                            return;
                        }
                        const payload = refreshTokenDecoded as JwtPayload;
                        (req as any)._id = payload._id;
                        generateAccessToken(req, payload._id);
                        next();
                    },
                );
            }
            const payload = accessTokenDecoded as JwtPayload;
            (req as any)._id = payload._id;
            next();
        });
    }
}

export default AuthController;
