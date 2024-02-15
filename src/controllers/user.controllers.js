import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";

export const getCurrentUser = asyncHandler(async (req, res) => {
  try {
    const userId = req.user?._id;

    const currentUser = await User.findById(userId).select(
      "_id username fullName email"
    );

    return res
      .status(200)
      .json(new ApiResponse(200, currentUser, "user fetched successfully"));
  } catch (error) {
    console.log(error);
    throw new ApiError(
      40,
      error?.message || "something went wrong while fetching current user"
    );
  }
});

export const changeCurrentPassword = asyncHandler(async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) {
      throw new ApiError(400, "all fields required");
    }

    const id = req.user?._id;
    const user = await User.findById(id);

    const isValidPassword = await user.isPasswordCorrect(oldPassword);
    if (!isValidPassword) {
      throw new ApiError(400, "invalid old password");
    }

    user.password = newPassword;
    await user.save({ validateBeforeSave: false });

    return res
      .status(200)
      .json(new ApiResponse(200, {}, "password changed successfully"));
  } catch (error) {
    console.log(error);
    throw new ApiError(
      400,
      error?.message || "something went wrong while changing password"
    );
  }
});

export const updateAccountDetails = asyncHandler(async (req, res) => {
  try {
    const { username, fullName } = req.body;
    if (!fullName || !username) {
      throw new ApiError(400, "all fields required");
    }

    const id = req.user?._id;

    const user = await User.findByIdAndUpdate(
      id,
      { $set: { fullName, username } },
      { new: true }
    ).select("-password -refreshToken");

    return res
      .status(200)
      .json(new ApiResponse(200, user, "account details updated successfully"));
  } catch (error) {
    console.log(error);
    throw new ApiError(
      error?.message || "something went wrong while updating account details"
    );
  }
});
