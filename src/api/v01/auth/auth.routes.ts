import { Router } from "express";
import * as authControllers from "./auth.controllers";

const authRoutes: ReturnType<typeof Router> = Router();

//all api routes for auth services
authRoutes.post("/login", authControllers.loginAuthController);
authRoutes.post("/logout", authControllers.logoutAuthController);
authRoutes.post("/register", authControllers.registerAuthController);
authRoutes.post("/profile", authControllers.profileAuthController);
authRoutes.post("/refresh", authControllers.refreshTokenAuthController);

export default authRoutes;
