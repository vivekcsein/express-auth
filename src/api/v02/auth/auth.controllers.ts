import { Request, Response, NextFunction } from "express";
import { AuthError, Session, User } from "@supabase/supabase-js";

import {
  IUserProfileRoleType,
  IUserRegistration,
  IUserSignin,
  IUserSignup,
} from "../../../types/users";

import {
  getUserByToken,
  getUserProfile,
  refreshTokenUser,
  registerUser,
  setUserToiLocalUser,
  signinUser,
  signoutUser,
} from "./auth.helper";

import {
  getCookieExpiryInDays,
  getCookieExpiryInMinutes,
} from "../../../libs/utils/utils.app";

// 🌀 Refresh Token
export const refreshTokenAuthController = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const refreshToken = req.cookies.refreshtoken as string;
    const remember = Boolean(req.body?.remember);

    if (!refreshToken) {
      return res
        .status(401)
        .json({ success: false, message: "Unauthorized", data: null });
    }

    const result = await refreshTokenUser({ refreshToken });
    const { session } = result.data as { session: Session };

    if (!session?.access_token || !session?.refresh_token) {
      return res.status(500).json({
        success: false,
        status: "error",
        message: "Token generation failed",
        data: null,
      });
    }

    res.cookie("accesstoken", session.access_token, {
      maxAge: remember
        ? getCookieExpiryInDays(1)
        : getCookieExpiryInMinutes(15),
      httpOnly: true,
    });

    res.cookie("refreshtoken", session.refresh_token, {
      maxAge: remember ? getCookieExpiryInDays(30) : getCookieExpiryInDays(7),
      httpOnly: true,
    });

    return res.status(200).json({
      success: true,
      message: "Tokens are refreshed successfully",
      data: null,
    });
  } catch (err) {
    next({
      status: (err as AuthError)?.status || 500,
      message:
        (err as AuthError)?.message || "Unexpected error during refreshToken.",
    });
  }
};

// 👤 Profile
export const profileAuthController = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const token = req.cookies.accesstoken as string;
    if (!token) {
      return res
        .status(401)
        .json({ success: false, message: "Unauthorized", data: null });
    }

    const user = await getUserByToken(token);
    const userDatafromDB = await getUserProfile(user.email!);

    const currentUser = {
      id: userDatafromDB?.id,
      email: user.email,
      role: (userDatafromDB?.role ?? "USER") as IUserProfileRoleType,
      fullname: userDatafromDB?.fullname ?? "",
      avatar: userDatafromDB?.avatar ?? null,
      created_at: user.created_at,
      updated_at: user.updated_at,
      isUserVerified: user.user_metadata?.isUserVerified ?? false,
    };

    return res.status(200).json({
      success: true,
      message: "User profile fetched successfully",
      data: currentUser,
    });
  } catch (err) {
    next({
      status: (err as AuthError)?.status || 500,
      message:
        (err as AuthError)?.message || "Unexpected error during profile fetch.",
    });
  }
};

// 🔐 Signin
export const signinAuthController = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { email, password, remember } = req.body as IUserSignin;
    const result = await signinUser({ email, password });
    const { user, session } = result.data as { user: User; session: Session };

    if (!session?.access_token || !session?.refresh_token) {
      return res.status(500).json({
        status: "error",
        message: "Token generation failed",
        data: null,
      });
    }

    const userDatafromDB = await getUserProfile(email);

    res.cookie("accesstoken", session.access_token, {
      maxAge: remember
        ? getCookieExpiryInDays(1)
        : getCookieExpiryInMinutes(15),
      httpOnly: true,
    });

    res.cookie("refreshtoken", session.refresh_token, {
      maxAge: remember ? getCookieExpiryInDays(30) : getCookieExpiryInDays(7),
      httpOnly: true,
    });

    const currentUser = {
      id: userDatafromDB?.id,
      email,
      role: (userDatafromDB?.role ?? "USER") as IUserProfileRoleType,
      fullname: userDatafromDB?.fullname ?? "",
      avatar: userDatafromDB?.avatar ?? null,
      created_at: user.created_at,
      updated_at: user.updated_at,
      isUserVerified: user.user_metadata?.isUserVerified ?? false,
    };

    return res.status(200).json({
      success: true,
      message: "User signed in successfully.",
      data: currentUser,
    });
  } catch (err) {
    next({
      status: (err as AuthError)?.status || 500,
      message:
        (err as AuthError)?.message ||
        "Unexpected error during authentication.",
    });
  }
};

// 🚪 Signout
export const signoutAuthController = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    await signoutUser();

    res.clearCookie("accesstoken", { path: "/" });
    res.clearCookie("refreshtoken", { path: "/" });

    return res.status(200).json({
      success: true,
      message: "User signed out successfully",
      data: null,
    });
  } catch (err) {
    next({
      status: (err as AuthError)?.status || 500,
      message:
        (err as AuthError)?.message ||
        "Unexpected error during unauthentication.",
    });
  }
};

// 📝 Signup
export const signupAuthController = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { email, password, fullname, terms } = req.body as IUserSignup;
    const result = await registerUser({ email, password, fullname, terms });

    if (!result.success) {
      return res.status(result.statusCode).json({
        success: false,
        message: result.message,
        error: result.error,
      });
    }

    const { user } = result.data as { user: User; session: Session };

    const newUser: IUserRegistration = {
      user_id: user.id,
      email,
      fullname,
      role: "USER" as IUserProfileRoleType,
      created_at: user.created_at,
      updated_at: user.updated_at,
    };

    await setUserToiLocalUser(newUser);

    return res.status(result.statusCode).json({
      success: true,
      message: result.message,
      data: newUser,
    });
  } catch (err) {
    next({
      status: (err as AuthError)?.status || 500,
      message:
        (err as AuthError)?.message || "Unexpected error during registration.",
    });
  }
};
