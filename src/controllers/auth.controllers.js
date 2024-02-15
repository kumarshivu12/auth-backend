import otpGenerator from "otp-generator";
import nodemailer from "nodemailer";
import { User } from "../models/user.model.js";
import { OTP } from "../models/otp.model.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { generateAccessAndRefreshTokens } from "../utils/generateTokens.js";

const options = {
  httpOnly: true,
  secure: false,
};

export const checkAuth = asyncHandler(async (req, res) => {
  try {
    return res
      .status(200)
      .json(new ApiResponse(200, req.user, "user fetched successfully"));
  } catch (error) {
    console.log(error);
    throw new ApiError(
      40,
      error?.message || "something went wrong while fetching current user"
    );
  }
});

export const sendOTP = asyncHandler(async (req, res) => {
  try {
    const email = req.email;

    const otp = otpGenerator.generate(6, {
      upperCaseAlphabets: false,
      specialChars: false,
      lowerCaseAlphabets: false,
    });
    const otpExpiry = Date.now() + 10 * 60 * 1000;
    console.log(otp);

    const user = await OTP.findOne({ email });
    if (user) {
      user.otp = otp.toString();
      user.otpExpiry = otpExpiry;
      user.save({ validateBeforeSave: false });
    } else {
      await OTP.create({
        email,
        otp: otp.toString(),
        otpExpiry,
      });
    }

    //send otp via email
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL,
        pass: process.env.PASSWORD,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL,
      to: email,
      subject: "OTP Request",
      html: `
    <p>Hello,</p>
    <p>Your One-Time Password (OTP) is: <strong>${otp}</strong></p>
    <p>This OTP is valid for 10 minutes. Please do not share it with anyone.</p>
    <p>Best regards,</p>
    <p>Talkie Support</p>
  `,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        throw new ApiError(400, error);
      } else {
        console.log(info);
        return res
          .status(200)
          .json(new ApiResponse(200, { email }, "otp sent successfully"));
      }
    });
  } catch (error) {
    console.log(error);
    throw new ApiError(
      400,
      error?.message || "something went wrong while sending otp"
    );
  }
});

export const verifyOTP = asyncHandler(async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) {
      throw new ApiError(400, "all fields required");
    }

    const user = await User.findOne({ email });
    const userOTP = await OTP.findOne({
      email,
      otpExpiry: { $gt: Date.now() },
    });
    if (!userOTP) {
      throw new ApiError(400, "invalid email or otp");
    }

    if (user.verified) {
      throw new ApiError(400, "user already verified");
    }

    const isValidOTP = await userOTP.isOTPCorrect(otp);
    if (!isValidOTP) {
      throw new ApiError(400, "invalid otp");
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
      user._id
    );

    await OTP.findByIdAndDelete(userOTP._id);
    const verifiedUser = await User.findByIdAndUpdate(
      user._id,
      {
        $set: {
          verified: true,
        },
      },
      { new: true }
    ).select("_id username email verified");

    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", refreshToken, options)
      .json(new ApiResponse(200, verifiedUser, "user verified successfully"));
  } catch (error) {
    console.log(error);
    console.log(error);
    throw new ApiError(
      400,
      error?.message || "something went wrong while verifying otp"
    );
  }
});

export const registerUser = asyncHandler(async (req, res, next) => {
  try {
    const { username, fullName, email, password } = req.body;
    if (
      [username, fullName, email, password].some(
        (field) => !field || field.trim() === ""
      )
    ) {
      throw new ApiError(400, "all fields required");
    }

    const existedUser = await User.findOne({ $or: [{ username }, { email }] });
    //user exist and verified
    if (existedUser && existedUser.verified) {
      throw new ApiError(409, "user already exists");
    }
    //user exists but not verified
    else if (existedUser) {
      const updatedUser = await User.findByIdAndUpdate(
        existedUser._id,
        { $set: { username, fullName, email } },
        { new: true }
      );
      updatedUser.password = password;
      await updatedUser.save({ validateBeforeSave: false });

      req.email = updatedUser.email;
      next();
    }
    //user doesn't exists
    else {
      const createdUser = await User.create({
        username,
        fullName,
        email,
        password,
      });
      req.email = createdUser.email;
      next();
    }
  } catch (error) {
    console.log(error);
    throw new ApiError(
      400,
      error?.message || "something went wrong while registering user"
    );
  }
});

export const loginUser = asyncHandler(async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      throw new ApiError(400, "all fileds required");
    }

    const user = await User.findOne({ email });
    if (!user || !user.verified) {
      throw new ApiError(400, "user not found");
    }

    const isValidPassword = await user.isPasswordCorrect(password);
    if (!isValidPassword) {
      throw new ApiError(400, "invalid user credentials");
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
      user._id
    );

    const loggedInUser = await User.findById(user._id).select(
      "_id username email verified"
    );

    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", refreshToken, options)
      .json(new ApiResponse(200, loggedInUser, "user logged in successfully"));
  } catch (error) {
    console.log(error);
    throw new ApiError(
      400,
      error?.message || "something went wrong while logging user"
    );
  }
});

export const logoutUser = asyncHandler(async (req, res) => {
  try {
    const id = req.user?._id;

    const user = await User.findById(id);
    user.refreshToken = undefined;
    await user.save({ validateBeforeSave: false });

    return res
      .status(200)
      .clearCookie("accessToken", options)
      .clearCookie("refreshToken", options)
      .json(new ApiResponse(200, {}, "user logged out successfully"));
  } catch (error) {
    console.log(error);
    throw new ApiError(
      400,
      error?.message || "something went wrong while logging out user"
    );
  }
});

export const forgotPassword = asyncHandler(async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      throw new ApiError(400, "email is required");
    }

    const user = await User.findOne({ email });
    if (!user || !user.verified) {
      throw new ApiError(400, "user not found");
    }

    const resetToken = await user.generateResetPasswordToken();
    const resetURL = `http://localhost:5173/auth/reset-password?token=${resetToken}`;
    console.log(resetURL);

    user.resetPasswordToken = resetToken;
    user.resetPasswordTokenExpiry = Date.now() + 10 * 60 * 1000;
    await user.save({ validateBeforeSave: false });

    //send reset url via email
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL,
        pass: process.env.PASSWORD,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL,
      to: email,
      subject: "Password Reset Request",
      html: `
    <p>Hello,</p>
    <p>We received a request to reset your password. Click the link below to reset it:</p>
    <p><a href="${resetURL}">${resetURL}</a></p>
    <p>This link is valid for 10 minutes. Please keep it confidential and do not share it with anyone.</p>
    <p>Best regards,</p>
    <p>Talkie Support</p>
  `,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        throw new ApiError(400, error);
      } else {
        console.log(info);
        return res
          .status(200)
          .json(new ApiResponse(200, { email }, "otp sent successfully"));
      }
    });
  } catch (error) {
    console.log(error);
    throw new ApiError(
      400,
      error?.message || "something went wrong while forgetting password"
    );
  }
});

export const resetPassword = asyncHandler(async (req, res) => {
  try {
    const { resetToken, password } = req.body;
    if (!resetToken || !password) {
      throw new ApiError(400, "all fields required");
    }

    const user = await User.findOne({
      resetPasswordToken: resetToken,
      // resetPasswordTokenExipry: { $gt: Date.now() },
    });
    if (!user) {
      throw new ApiError(400, "invalid token");
    }

    user.password = password;
    user.resetPasswordToken = undefined;
    user.resetPasswordTokenExipry = undefined;
    user.save({ validateBeforeSave: false });

    return res
      .status(200)
      .json(new ApiResponse(200, {}, "password reset successfully"));
  } catch (error) {
    console.log(error);
    console.log(error);
    throw new ApiError(
      400,
      error?.message || "something went wrong while reseting password"
    );
  }
});
