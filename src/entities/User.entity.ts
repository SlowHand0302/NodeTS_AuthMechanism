import { Types } from 'mongoose';

export type User = {
    _id: Types.ObjectId;
    fullname: string;
    username: string;
    email: string;
    avatar: string | null;
    password: string;
    phoneNumber: string;
};
