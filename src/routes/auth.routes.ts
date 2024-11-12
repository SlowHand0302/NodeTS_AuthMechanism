import express, { Request, Response, NextFunction } from 'express';
import AuthController from '../controllers/auth.controller';
const routers = express.Router();

routers.post('/signUp', (req: Request, res: Response, next: NextFunction): any =>
    AuthController.signUp(req, res, next),
);

routers.post('/signIn', (req: Request, res: Response, next: NextFunction): any =>
    AuthController.signIn(req, res, next),
);

routers.post('/signIn/google', (req: Request, res: Response, next: NextFunction) => {
    AuthController.signInWithGoogle(req, res, next);
});

routers.post('/signOut', (req: Request, res: Response, next: NextFunction) => {
    AuthController.signOut(req, res, next);
});

routers.post('/resetPassword', (req: Request, res: Response, next: NextFunction) => {
    AuthController.resetPassword(req, res, next);
});

routers.post('/verifyOTP', (req: Request, res: Response, next: NextFunction) => {
    AuthController.verifyOTP(req, res, next);
});

export default routers;
