import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

const app = express();

app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  })
);
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ limit: "16kb", extended: true }));
app.use(express.static("public"));
app.use(cookieParser());

//importing routes
import authRouter from "./routes/auth.routes.js";
import userRouter from "./routes/user.routes.js";

//routes declaration
app.use("/api/v1/auth", authRouter);
app.use("/api/v1/user", userRouter);

export default app;
