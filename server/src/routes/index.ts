import express from 'express';
import { ECDH, decode } from '../controllers/ECDH';
const router = express.Router();

export default () => {
    router.post('/exchangeECDH', ECDH);
    router.post('/decode', decode);
    return router;
}