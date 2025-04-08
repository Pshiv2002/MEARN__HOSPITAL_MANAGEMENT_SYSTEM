import { User } from "../models/userSchema.js";
import { catchAsyncErrors } from "./catchAsyncErrors.js";
import ErrorHandler from "./errorMiddleware.js";
import jwt from "jsonwebtoken";

// Middleware to authenticate dashboard users
export const isAdminAuthenticated = catchAsyncErrors(async (req, _res, next) => {
  const token = req.cookies?.adminToken;
  if (!token) {
    return next(new ErrorHandler("Dashboard User is not authenticated!", 401));
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    req.user = await User.findById(decoded.id);

    if (!req.user) {
      return next(new ErrorHandler("User not found!", 404));
    }

    if (req.user.role !== "Admin") {
      return next(new ErrorHandler(`${req.user.role} not authorized for this resource!`, 403));
    }

    next();
  } catch (error) {
    return next(new ErrorHandler("Invalid or expired token!", 401));
  }
});

// Middleware to authenticate frontend users
export const isPatientAuthenticated = catchAsyncErrors(async (req, _res, next) => {
  const token = req.cookies?.patientToken;
  if (!token) {
    return next(new ErrorHandler("User is not authenticated!", 401));
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    req.user = await User.findById(decoded.id);

    if (!req.user) {
      return next(new ErrorHandler("User not found!", 404));
    }

    if (req.user.role !== "Patient") {
      return next(new ErrorHandler(`${req.user.role} not authorized for this resource!`, 403));
    }

    next();
  } catch (error) {
    return next(new ErrorHandler("Invalid or expired token!", 401));
  }
});

// Middleware for role-based authorization
export const isAuthorized = (...roles) => {
  return (req, _res, next) => {
    if (!req.user) {
      return next(new ErrorHandler("User is not authenticated!", 401));
    }

    if (!roles.includes(req.user.role)) {
      return next(new ErrorHandler(`${req.user.role} not allowed to access this resource!`, 403));
    }

    next();
  };
};
