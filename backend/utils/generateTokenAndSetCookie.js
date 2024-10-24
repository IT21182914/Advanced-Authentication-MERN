import jwt from "jsonwebtoken";

export const generateTokenAndSetCookie = (res, userId) => {
  const token = jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });

  res.cookie("token", token, {
    httpOnly: true, // prevent XSS (Cross-Site Scripting) attacks which can steal the cookie data from the client side
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict", // prevent CSRF attacks which can trick the browser into making a malicious request
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });

  return token;
};
