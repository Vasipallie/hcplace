//inits
import express from 'express';
import { createClient } from '@supabase/supabase-js';
import bodyParser from 'body-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cookieParser());
const supalink = process.env.SUPALINK ;
const supakey = process.env.SUPAKEY ;
/* 
const supabase = createClient(supalink, supakey);  */

// Middleware data stuff, important for app to run
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'views')));
app.use(bodyParser.urlencoded({ extended: true }));

app.get('/', (req, res) => {
    res.render('index', { title: 'hc/place' });
});

app.get('/:id', (req, res) => {
    res.render('404', { title: '404' });
});

//Server start 
app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});