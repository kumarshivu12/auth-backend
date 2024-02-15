import mongoose, { Schema } from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import crypto from "crypto";

const userSchema = new Schema(
  {
    username: {
      type: String,
      required: [true, "username is required"],
      unique: [true, "username already exists"],
      lowercase: true,
      trim: true,
      index: true,
    },
    fullName: {
      type: String,
      required: [true, "fullname is required"],
      trim: true,
      index: true,
    },
    email: {
      type: String,
      required: [true, "email is required"],
      unique: [true, "email already exists"],
      lowecase: true,
      trim: true,
      validate: {
        validator: function (email) {
          return String(email)
            .toLowerCase()
            .match(
              /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
            );
        },
        message: (props) => `Email (${props.value}) is invalid!`,
      },
    },
    password: {
      type: String,
      required: [true, "password is required"],
    },
    avatar: {
      type: String,
      default: "https://i.pravatar.cc/150?u=a042581f4e29026704d",
    },
    resetPasswordToken: {
      type: String,
    },
    resetPasswordTokenExpiry: {
      type: Date,
    },
    verified: {
      type: Boolean,
      default: false,
    },
    refreshToken: {
      type: String,
    },
  },
  {
    timestamps: true,
  }
);

userSchema.pre("save", async function (next) {
  if (!this.isModified("password") || !this.password) {
    return next();
  }

  this.password = await bcrypt.hash(this.password, 10);
  next();
});

userSchema.methods.isPasswordCorrect = async function (password) {
  return await bcrypt.compare(password, this.password);
};

userSchema.methods.generateAccessToken = function () {
  return jwt.sign(
    {
      _id: this._id,
      email: this.email,
      username: this.username,
      verified: this.verified,
    },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: "3s",
    }
  );
};

userSchema.methods.generateRefreshToken = function () {
  return jwt.sign(
    {
      _id: this._id,
    },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
    }
  );
};

userSchema.methods.generateResetPasswordToken = function () {
  const resetToken = crypto.randomBytes(32).toString("hex");

  this.resetPasswordToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  return resetToken;
};

export const User = mongoose.model("User", userSchema);
