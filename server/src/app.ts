import express from 'express';
import routes from './routes/index';
import cors from 'cors';
const app = express();
const port = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(cors({
    origin: 'http://localhost:5173',
}));

app.use(routes());

app.listen(port, () => {
    return console.log(`Express is listening at http://localhost:${port}`);
});