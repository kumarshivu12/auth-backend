import { User } from "../models/user.model.js";
import { ApiError } from "./ApiError.js";

export const generateAccessAndRefreshTokens = async (userId) => {
  try {
    const user = await User.findById(userId);

    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    console.log(error);
    throw new ApiError(
      400,
      error?.message ||
        "something went wrong while generating access and refresh token"
    );
  }
};
