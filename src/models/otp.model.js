import mongoose, { Schema } from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const otpSchema = new Schema(
  {
    email: {
      type: String,
      required: [true, "email is required"],
    },
    otp: {
      type: String,
    },
    otpExpiry: {
      type: Date,
    },
  },
  { timestamps: true }
);

otpSchema.pre("save", async function (next) {
  if (!this.isModified("otp") || !this.otp) {
    return next();
  }

  this.otp = await bcrypt.hash(this.otp.toString(), 10);
  next();
});

otpSchema.methods.isOTPCorrect = async function (otp) {
  return await bcrypt.compare(otp, this.otp);
};

export const OTP = mongoose.model("OTP", otpSchema);
