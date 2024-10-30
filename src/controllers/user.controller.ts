import { NextFunction, Request, Response } from 'express';
import UserService from '../services/User.services';
import { User } from '../entities/User.entity';
import createHttpError from 'http-errors';

class UserController {
    static async getAllUser(req: Request, res: Response, next: NextFunction) {
        const services = new UserService();
                
        try {
            const users = await services.findAll();
            return res.status(200).json({
                statusCode: 200,
                msg: 'Get All User Success',
                metadata: [...users],
            });
        } catch (error) {
            next();
            throw error;
        }
    }

    static async updateProfile(req: Request, res: Response, next: NextFunction) {
        const services = new UserService();
        const userInfor: Partial<User> = { ...req.body } as Partial<User>;
        try {
            const userUpdated = await services.update(userInfor);
            return res.status(200).json({
                statusCode: 200,
                msg: 'Updated success',
                metadata: { ...userUpdated },
            });
        } catch (error) {
            const err = createHttpError(500, 'Internal Server Error');
            next(err);
            throw error;
        }
    }
}

export default UserController;
