import express from "express";
import { getSummary } from "../controllers/analytics.js";
import { verifyAdmin } from "../utils/verifyToken.js";

const router = express.Router();

router.get("/summary", verifyAdmin, getSummary);

export default router;
