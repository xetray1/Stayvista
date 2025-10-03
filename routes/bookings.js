import express from "express";
import {
  createBooking,
  deleteBooking,
  getBooking,
  listBookings,
  updateBookingStatus,
} from "../controllers/booking.js";
import { verifyAdmin, verifyToken } from "../utils/verifyToken.js";

const router = express.Router();

router.post("/", verifyToken, createBooking);
router.get("/", verifyToken, listBookings);
router.get("/:id", verifyToken, getBooking);
router.patch("/:id/status", verifyAdmin, updateBookingStatus);
router.delete("/:id", verifyAdmin, deleteBooking);

export default router;
