import express, { Request, Response, NextFunction } from 'express';
import OAuthController from '../controllers/oAuth.controller';
const routers = express.Router();

routers.post('/signIn/google', (req: Request, res: Response, next: NextFunction) => {
    OAuthController.signInWithGoogle(req, res, next);
});

export default routers;
