import { Router } from "express";
import { verifyJWT } from "../middlewares/auth.middleware.js";
import {
  getCurrentUser,
  updateAccountDetails,
} from "../controllers/user.controllers.js";

const router = Router();

router.use(verifyJWT);

router.route("/current-user").get(getCurrentUser);
router.route("/update-account").post(updateAccountDetails);

export default router;
