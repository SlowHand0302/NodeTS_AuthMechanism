import mongoose from 'mongoose';

const Schema = mongoose.Schema;

interface IUser extends Document {
    fullname: string;
    username: string;
    email: string;
    avatar: string;
    password: string;
    phoneNumber: string;
}

const Users = new Schema<IUser>(
    {
        fullname: { type: String, required: true },
        username: { type: String, required: true },
        email: { type: String, required: true },
        avatar: { type: String },
        password: { type: String },
        phoneNumber: { type: String },
    },
    {
        timestamps: true,
    },
);

const UserModel = mongoose.model<IUser>('Users', Users);

export { UserModel, IUser };
