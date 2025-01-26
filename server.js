const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();


const app = express();
app.use(bodyParser.json());

mongoose.connect(process.env.CONNECTION_STRING);

const bookSchema = new mongoose.Schema({
    isbn: String,
    title: String,
    author: String,
    description: String
});
const userSchema = new mongoose.Schema({
    username: String,
    password: String
});
const reviewSchema = new mongoose.Schema({
    bookId: mongoose.Schema.Types.ObjectId,
    userId: mongoose.Schema.Types.ObjectId,
    review: String
});

const Book = mongoose.model('Book', bookSchema);
const User = mongoose.model('User', userSchema);
const Review = mongoose.model('Review', reviewSchema);


const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).send('Access denied');

    jwt.verify(token, 'secretkey', (err, user) => {
        if (err) return res.status(403).send('Invalid token');
        req.user = user;
        next();
    });
};
app.post('/books', async (req, res) => {
    try {
        const { isbn, title, author, description } = req.body;

        // Validate required fields
        if (!isbn || !title || !author || !description) {
            return res.status(400).send('All fields (isbn, title, author, description) are required');
        }

        // Create a new book instance
        const book = new Book({ isbn, title, author, description });

        // Save the book to the database
        await book.save();

        // Respond with the created book
        res.status(201).json(book);
    } catch (err) {
        res.status(500).send(err.message);
    }
});

app.get('/books', async (req, res) => {
    try {
        const books = await Book.find().select('title author').limit(10);
        res.json(books);
    } catch (err) {
        res.status(500).send(err.message);
    }
});


app.get('/books/:isbn', (req, res) => {
    Book.findOne({ isbn: req.params.isbn })
        .then(book => book ? res.json(book) : res.status(404).send('Book not found'))
        .catch(err => res.status(500).send(err.message));
});


app.get('/books/author/:name', async (req, res) => {
    try {
        const books = await Book.find({ author: req.params.name });
        res.json(books);
    } catch (err) {
        res.status(500).send(err.message);
    }
});


app.get('/books/title/:title', (req, res) => {
    Book.find({ title: req.params.title })
        .then(books => res.json(books))
        .catch(err => res.status(500).send(err.message));
});


app.get('/books/:isbn/reviews', async (req, res) => {
    try {
        const book = await Book.findOne({ isbn: req.params.isbn });
        if (!book) return res.status(404).send('Book not found');

        const reviews = await Review.find({ bookId: book._id });
        res.json(reviews);
    } catch (err) {
        res.status(500).send(err.message);
    }
});


app.post('/users/register', async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = new User({ username: req.body.username, password: hashedPassword });
        await user.save();
        res.status(201).send('User registered');
    } catch (err) {
        res.status(500).send(err.message);
    }
});


app.post('/users/login', async (req, res) => {
    try {
        const user = await User.findOne({ username: req.body.username });
        if (!user) return res.status(404).send('User not found');

        const validPassword = await bcrypt.compare(req.body.password, user.password);
        if (!validPassword) return res.status(403).send('Invalid credentials');

        const token = jwt.sign({ userId: user._id }, 'secretkey');
        res.json({ token });
    } catch (err) {
        res.status(500).send(err.message);
    }
});


app.post('/reviews', async (req, res) => {
    try {
        const book = await Book.findById(req.body.bookId);
        if (!book) return res.status(404).send('Book not found');

        const review = new Review({ bookId: book._id, review: req.body.review });
        await review.save();
        res.status(201).send('Review added');
    } catch (err) {
        res.status(500).send(err.message);
    }
});


app.put('/reviews/:id', async (req, res) => {
    try {
        const review = await Review.findOne({ _id: req.params.id });
        if (!review) return res.status(404).send('Review not found');

        review.review = req.body.review;
        await review.save();
        res.send('Review updated');
    } catch (err) {
        res.status(500).send(err.message);
    }
});


app.delete('/reviews/:id', async (req, res) => {
    try {
        const review = await Review.findOneAndDelete({ _id: req.params.id });
        if (!review) return res.status(404).send('Review not found');

        res.send('Review deleted');
    } catch (err) {
        res.status(500).send(err.message);
    }
});


const PORT = 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
