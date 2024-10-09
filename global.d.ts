declare global {
    namespace NodeJS {
        interface ProcessEnv {
            SECRET_KEY: string;
            PORT: string;
            SERVER_URL: string;
            CLIENT_URL: string;
            DB_URL: string;
            GOOGLE_CLIENT_ID: string;
            GOOGLE_CLIENT_SECRET: string;
        }
    }
}

export {};
