import path from 'path';
import dotenv from 'dotenv';

// Parsing the env file.
dotenv.config({ path: path.resolve(__dirname, '../configs/env.config') });

// Interface to load env variables
// Note these variables can possibly be undefined
// as someone could skip these varibales or not setup a .env file at all
interface ENV {
    PORT: number | undefined;
    SECRET_KEY: string | undefined;
    SERVER_URL: string | undefined;
    CLIENT_URL: string | undefined;
    DB_URL: string | undefined;
    GOOGLE_CLIENT_ID: string | undefined;
    GOOGLE_CLIENT_SECRET: string | undefined;
}

interface EnvConfig {
    SECRET_KEY: string;
    PORT: number;
    SERVER_URL: string;
    CLIENT_URL: string;
    DB_URL: string;
    GOOGLE_CLIENT_ID: string;
    GOOGLE_CLIENT_SECRET: string;
}

// Loading process.env as ENV interface
export const getConfig = (): ENV => {
    return {
        PORT: process.env.PORT ? Number(process.env.PORT) : undefined,
        SECRET_KEY: process.env.SECRET_KEY,
        SERVER_URL: process.env.SERVER_URL,
        CLIENT_URL: process.env.CLIENT_URL,
        DB_URL: process.env.DB_URL,
        GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
        GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET,
    };
};

export const getSanitzedConfig = (config: ENV): EnvConfig => {
    for (const [key, value] of Object.entries(config)) {
        if (value === undefined) {
            throw new Error(`Missing key ${key} in config.env`);
        }
    }
    return config as EnvConfig;
};

// export const config = getConfig();

// export const sanitizedConfig = getSanitzedConfig(config);

// export default sanitizedConfig;
