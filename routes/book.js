import express from 'express';
import { Book } from '../models/Book.js';
const router = express.Router();
import { verifyAdmin } from './auth.js';

// Add a new book (Admin only)
router.post('/add', verifyAdmin, async (req, res) => {
    try {
        const { name, author, imageUrl } = req.body;
        const newBook = new Book({
            name,
            author,
            imageUrl
        });
        await newBook.save();
        return res.status(201).json({ added: true });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: "Error in adding book" });
    }
});

// Get all books
router.get('/books', async (req, res) => {
    try {
        const books = await Book.find();
        return res.status(200).json(books);
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: "Error fetching books" });
    }
});

// Get a specific book by ID
router.get('/book/:id', async (req, res) => {
    try {
        const id = req.params.id;
        const book = await Book.findById(id);
        if (!book) {
            return res.status(404).json({ message: "Book not found" });
        }
        return res.status(200).json(book);
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: "Error fetching book" });
    }
});

// Update a specific book by ID
router.put('/book/:id', verifyAdmin, async (req, res) => {
    try {
        const id = req.params.id;
        const updatedBook = await Book.findByIdAndUpdate(id, req.body, { new: true });
        if (!updatedBook) {
            return res.status(404).json({ message: "Book not found" });
        }
        return res.status(200).json({ updated: true, book: updatedBook });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: "Error updating book" });
    }
});

// Delete a specific book by ID
router.delete('/book/:id', verifyAdmin, async (req, res) => {
    try {
        const id = req.params.id;
        const deletedBook = await Book.findByIdAndDelete(id);
        if (!deletedBook) {
            return res.status(404).json({ message: "Book not found" });
        }
        return res.status(200).json({ deleted: true, book: deletedBook });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: "Error deleting book" });
    }
});

export { router as bookRouter };
