import { Types } from 'mongoose';
import { User } from '../entities/User.entity';
import UserRepo from '../repositories/User.repository';
import { UserModel } from '../models/User.model';

class UserService implements UserRepo {
    async findAll(): Promise<User[]> {
        return await UserModel.find().lean();
    }
    async findById(_id: Types.ObjectId): Promise<User | null> {
        return await UserModel.findById(_id).lean();
    }
    async findByEmail(email: string): Promise<User | null> {
        return await UserModel.findOne({ email }).lean();
    }
    async searchByUsername(username: string, _id: Types.ObjectId): Promise<User[] | null> {
        return await UserModel.find({ username: { $regex: username, $options: 'i' }, _id: { $ne: _id } })
            .select('username')
            .limit(10)
            .lean();
    }
    async create(user: Pick<User, 'email' | 'fullname' | 'username'>): Promise<User> {
        const newUser = new UserModel(user);
        await newUser.save();
        return newUser as User;
    }
    async update(user: Partial<User>): Promise<User> {
        const updatedUser = await UserModel.findByIdAndUpdate(user._id, { ...user }, { returnOriginal: false });
        return updatedUser as User;
    }
}

export default UserService;
