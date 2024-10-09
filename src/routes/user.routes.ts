import express, { Request, Response, NextFunction } from 'express';
import AuthController from '../controllers/auth.controller';
import UserController from '../controllers/user.controller';
const routers = express.Router();

routers.use(AuthController.verifyAuth);

routers.get('/read', (req: Request, res: Response, next: NextFunction): any =>
    UserController.getAllUser(req, res, next),
);

export default routers;
