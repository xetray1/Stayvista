import express from "express";
import {
  updateUser,
  deleteUser,
  getUser,
  getUsers,
  getAvailableAvatars,
  updateUserAvatar,
  resetUserPassword,
} from "../controllers/user.js";
import { verifyAdmin, verifyToken, verifyUser } from "../utils/verifyToken.js";

const router = express.Router();

// router.get("/checkauthentication", verifyToken, (req,res,next)=>{
//   res.send("hello user, you are logged in")
// })

// router.get("/checkuser/:id", verifyUser, (req,res,next)=>{
//   res.send("hello user, you are logged in and you can delete your account")
// })

// router.get("/checkadmin/:id", verifyAdmin, (req,res,next)=>{
//   res.send("hello admin, you are logged in and you can delete all accounts")
// })

//AVATAR OPTIONS
router.get("/assets/avatars", verifyToken, getAvailableAvatars);
router.put("/:id/avatar", verifyUser, updateUserAvatar);

//UPDATE
router.put("/:id", verifyUser, updateUser);

//DELETE
router.delete("/:id", verifyUser, deleteUser);

//RESET PASSWORD (SUPER ADMIN ONLY)
router.post("/:id/reset-password", verifyAdmin, resetUserPassword);

//GET
router.get("/:id", verifyUser, getUser);

//GET ALL
router.get("/", verifyAdmin, getUsers);

export default router;
