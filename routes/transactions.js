import express from "express";
import {
  createTransaction,
  createUserTransaction,
  getTransaction,
  listTransactions,
} from "../controllers/transaction.js";
import { verifyAdmin, verifyToken } from "../utils/verifyToken.js";

const router = express.Router();

router.post("/", verifyAdmin, createTransaction);
router.post("/checkout", verifyToken, createUserTransaction);
router.get("/", verifyToken, listTransactions);
router.get("/:id", verifyToken, getTransaction);

export default router;
