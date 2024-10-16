import express, { Request, Response, NextFunction } from 'express';
import AuthController from '../controllers/auth.controller';
const routers = express.Router();

routers.post('/signUp', (req: Request, res: Response, next: NextFunction): any =>
    AuthController.signUp(req, res, next),
);

routers.post('/signIn', (req: Request, res: Response, next: NextFunction): any =>
    AuthController.signIn(req, res, next),
);

routers.post('/signOut', (req: Request, res: Response, next: NextFunction) => {
    AuthController.signOut(req, res, next);
});

export default routers;
