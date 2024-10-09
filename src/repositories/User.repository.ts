import { User } from '../entities/User.entity';
import { Types } from 'mongoose';

export default interface UserRepo {
    findAll(): Promise<User[]>;
    findById(_id: Types.ObjectId): Promise<User | null>;
    findByEmail(email: string): Promise<User | null>;
    searchByUsername(username: string, _id: Types.ObjectId): Promise<User[] | null>;
    create(user: Omit<User, '_id'>): Promise<User>;
    update(user: Partial<User>): Promise<User>;
}
