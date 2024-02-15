import { Router } from "express";
import {
  loginUser,
  // refreshAccessToken,
  registerUser,
  sendOTP,
  verifyOTP,
  logoutUser,
  forgotPassword,
  resetPassword,
  checkAuth,
} from "../controllers/auth.controllers.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router();

router.route("/check-auth").post(verifyJWT, checkAuth);
router.route("/register-user").post(registerUser, sendOTP);
router.route("/verify-otp").post(verifyOTP);
router.route("/login-user").post(loginUser);
// router.route("/refresh-token").post(refreshAccessToken);
router.route("/logout-user").post(verifyJWT, logoutUser);
router.route("/forgot-password").post(forgotPassword);
router.route("/reset-password").post(resetPassword);

export default router;
