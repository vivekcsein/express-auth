import { Router } from "express";
import * as authControllers from "./auth.controllers";
import { errorHandler } from "./auth.errors";

const authRoutes: ReturnType<typeof Router> = Router();

// All API routes for auth services with contextual error handling
authRoutes.post(
  "/login",
  authControllers.signinAuthController,
  errorHandler("signin")
);
authRoutes.post(
  "/logout",
  authControllers.signoutAuthController,
  errorHandler("signout")
);
authRoutes.post(
  "/register",
  authControllers.signupAuthController,
  errorHandler("signup")
);
authRoutes.post(
  "/profile",
  authControllers.profileAuthController,
  errorHandler("profile")
);
authRoutes.post(
  "/refresh",
  authControllers.refreshTokenAuthController,
  errorHandler("refreshToken")
);

export default authRoutes;

export type routesOptions =
  | "signup"
  | "signin"
  | "signout"
  | "profile"
  | "refreshToken"
  | "verifyEmail"
  | "resetPassword"
  | "forgotPassword";
