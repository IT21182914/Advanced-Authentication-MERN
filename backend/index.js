import express from "express";
import { connectDB } from "./db/connectDB.js";
import dotenv from "dotenv";
import authRoutes from "./routes/auth.route.js";

const app = express();
dotenv.config();

app.get("/", (req, res) => {
  res.send("Hello World !");
});

app.use("/api/auth", authRoutes);

app.listen(3000, () => {
  connectDB();
  console.log("\nServer is Running on Port 3000 🔥");
});
