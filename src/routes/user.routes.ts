import express, { Request, Response, NextFunction } from 'express';
import AuthController from '../controllers/auth.controller';
import UserController from '../controllers/user.controller';
const routers = express.Router();

// middleware for multi-session authentication
routers.use(AuthController.verifyAuth);

// middleware for single-session authtication
// routers.use(AuthController.verifyAuthSingle)

routers.get('/read', (req: Request, res: Response, next: NextFunction): any =>
    UserController.getAllUser(req, res, next),
);

export default routers;
