import { LoginTicket, OAuth2Client, TokenPayload } from 'google-auth-library';
import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import UserService from '../services/User.services';

import dotenv from 'dotenv';
dotenv.config();

const oAuth2Client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, 'postmessage');

class OAuthController {
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
                .catch((error) => console.log(error));
            const payload = (ticket as LoginTicket).getPayload();
            const isExisted = await services.findByEmail((payload as TokenPayload).email as string);

            if (!isExisted) {
                const user = await services.create({
                    fullname: (payload as TokenPayload).name as string,
                    username: (payload as TokenPayload).email as string,
                    email: (payload as TokenPayload).email as string,
                });
                if (user) {
                    const token = jwt.sign({ id: user._id, username: user.username }, process.env.SECRET_KEY, {
                        expiresIn: 86400,
                    });
                    return res.status(200).json({
                        success: true,
                        msg: 'Login Success',
                        token,
                        user: {
                            _id: user._id,
                            username: user.username,
                        },
                    });
                }
            }

            return res.status(200).json({
                code: 200,
                success: true,
                token: jwt.sign({ id: isExisted?._id, username: isExisted?.username }, process.env.SECRET_KEY, {
                    expiresIn: 86400,
                }),
                user: {
                    _id: isExisted?._id,
                    username: isExisted?.username,
                },
            });
        } catch (error) {
            return res.status(500).json({
                code: 500,
                success: false,
                error,
            });
        }
    }
}

export default OAuthController;
