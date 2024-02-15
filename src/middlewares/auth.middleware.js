import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";
import { generateAccessAndRefreshTokens } from "../utils/generateTokens.js";
import { asyncHandler } from "../utils/asyncHandler.js";

const options = {
  httpOnly: true,
  secure: false,
};

export const refreshAccessToken = async (req, res, next) => {
  try {
    const incomingRefreshToken =
      req.cookies?.refreshToken || req.header("x-refresh-token");
    if (!incomingRefreshToken) {
      throw new ApiError(401, "unauthorized request");
    }

    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    const user = await User.findById(decodedToken._id);
    console.log("user: ", user);
    if (!user) {
      throw new ApiError(401, "unauthorized user");
    }
    if (user.refreshToken !== incomingRefreshToken) {
      throw new ApiError(400, "refresh token expired or used");
    }

    const { newAccessToken, newRefreshToken } =
      await generateAccessAndRefreshTokens(user._id);
    console.log(newAccessToken, newRefreshToken);

    req.user = user;

    res
      .cookie("accessToken", newAccessToken, options)
      .cookie("refreshToken", newRefreshToken, options);

    next(); // Call next middleware
  } catch (error) {
    console.log(error);
    throw new ApiError(
      400,
      error?.message || "something went wrong while refreshing access token"
    );
  }
};

export const verifyJWT = asyncHandler(async (req, res, next) => {
  try {
    const token =
      req.cookies?.accessToken ||
      req.header("Authorization")?.replace("Bearer ", "");
    if (!token) {
      throw new ApiError(401, "invalid access token");
    }

    try {
      const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

      const user = await User.findById(decodedToken._id).select(
        "-password -refreshToken"
      );
      if (!user) {
        throw new ApiError(401, "unauthorized user");
      }

      req.user = user;
      next();
    } catch (error) {
      if (error.name === "TokenExpiredError") {
        // Call refreshAccessToken and pass next middleware
        await refreshAccessToken(req, res, next);
      } else {
        throw new ApiError(400, error);
      }
    }
  } catch (error) {
    console.log(error);
    throw new ApiError(
      400,
      error?.message || "something went wrong while verifying user"
    );
  }
});
