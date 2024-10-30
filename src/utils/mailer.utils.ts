import { createTransport, SendMailOptions } from 'nodemailer';
import { OAuth2Client } from 'google-auth-library';
import dotenv from 'dotenv';
import SMTPConnection from 'nodemailer/lib/smtp-connection';
dotenv.config();

const oAuth2Client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, 'postmessage');
oAuth2Client.setCredentials({ refresh_token: process.env.GOOGLE_MAILER_REFRESH_TOKEN });

const createTransporter = async () => {
    const accessToken = (await oAuth2Client.getAccessToken()).token;
    const transporter = createTransport({
        service: 'gmail',
        auth: {
            type: 'OAuth2',
            user: process.env.ADMIN_EMAIL_ADDRESS,
            clientId: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            refreshToken: process.env.GOOGLE_MAILER_REFRESH_TOKEN,
            accessToken,
        } as SMTPConnection.AuthenticationType,
    });
    return transporter;
};

export const sendMail = async (mailOptions: SendMailOptions) => {
    const transporter = await createTransporter();
    return transporter.sendMail(mailOptions);
};
