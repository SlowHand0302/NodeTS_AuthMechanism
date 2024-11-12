import Redis from 'ioredis';
import dotenv from 'dotenv';
dotenv.config();

export const redis = new Redis({
    host: process.env.REDIS_HOST,
    port: Number(process.env.REDIS_PORT),
});

export const connect = async () => {
    redis.on('connect', () => {
        console.log(`Redis server is connected on redis://${process.env.REDIS_HOST}:${process.env.REDIS_PORT}`);
    });
    redis.on('error', (err) => {
        console.log('Redis error: ' + err);
        throw err;
    });
};
