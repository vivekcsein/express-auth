import z from "zod";
import { Request, Response } from "express";
import { Session, User } from "@supabase/supabase-js";

import { errorHandler } from "./auth.error";
import { supabase } from "../../../libs/db/db.supabase";
import { IUserProfileRoleType } from "../../../types/users";
import { loginSchema, registrationSchema } from "./auth.schemas";

import {
  loginAuthHelper,
  logoutAuthHelper,
  registerAuthHelper,
} from "./auth.helper";

//register controller
export const registerAuthController = async (req: Request, res: Response) => {
  try {
    const parsed = registrationSchema.safeParse(req.body);

    if (!parsed.success) {
      if (process.env.NODE_ENV === "development") {
        console.error("[Validation Error]", parsed.error.issues); // Avoid .format()
      }

      return res.status(400).json({
        status: "failed",
        message: "Invalid input",
        errors: parsed.error.issues.map((issue) => ({
          path: issue.path.join("."),
          message: issue.message,
          code: issue.code,
        })),
      });
    }

    const { email, fullname, password } = parsed.data;
    const result = await registerAuthHelper(email, password);
    const { user } = result as { user: User; session: Session };

    //new user information to be stored on database
    const newUser = {
      user_id: user.id,
      email: email,
      fullname: fullname,
      role: "USER" as IUserProfileRoleType,
      created_at: user.created_at,
      updated_at: user.updated_at,
    };

    const { error: insertError } = await supabase
      .from("iLocalUsers")
      .insert([newUser])
      .single();

    if (insertError) {
      throw insertError;
    }

    return res.status(201).json({
      status: "success",
      message: "Registration successful",
      data: newUser,
    });
  } catch (error) {
    return errorHandler(error, req, res);
  }
};

export const loginAuthController = async (req: Request, res: Response) => {
  try {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      if (process.env.NODE_ENV === "development") {
        console.error("[Validation Error]", parsed.error.issues);
      }

      return res.status(400).json({
        status: "failed",
        message: "Invalid input",
        errors: parsed.error.issues.map(({ path, message, code }) => ({
          path: path.join("."),
          message,
          code,
        })),
      });
    }

    const { email, password, remember } = parsed.data;
    const { user, session } = (await loginAuthHelper(email, password)) as {
      user: User;
      session: Session;
    };

    if (!session?.access_token || !session?.refresh_token) {
      return res.status(500).json({
        status: "error",
        message: "Token generation failed",
      });
    }

    const { data: roleData, error: roleError } = await supabase
      .from("iLocalUsers")
      .select("id, role")
      .eq("email", email)
      .single();

    if (roleError) throw roleError;

    const accessTokenMaxAge = remember ? 86400000 : 900000; // 1 day or 15 min
    const refreshTokenMaxAge = remember ? 2592000000 : 604800000; // 30 or 7 days

    const cookieOptions = {
      httpOnly: true,
      secure: true,
      sameSite: "none" as const,
      path: "/",
    };

    res.cookie("accessToken", session.access_token, {
      ...cookieOptions,
      maxAge: accessTokenMaxAge,
    });

    res.cookie("refreshToken", session.refresh_token, {
      ...cookieOptions,
      maxAge: refreshTokenMaxAge,
    });

    const currentUser = {
      id: roleData?.id,
      email,
      role: (roleData?.role ?? "USER") as IUserProfileRoleType,
      created_at: user.created_at,
      updated_at: user.updated_at,
      isUserVerified: user.user_metadata?.isUserVerified ?? false,
    };

    return res.status(200).json({
      status: "success",
      message: "Login successful",
      data: { currentUser },
    });
  } catch (error) {
    errorHandler(error, req, res);
  }
};

export const logoutAuthController = async (req: Request, res: Response) => {
  try {
    await logoutAuthHelper();

    res.clearCookie("accessToken", { path: "/" });
    res.clearCookie("refreshToken", { path: "/" });

    return res.status(200).json({
      status: "success",
      message: "Logout successful",
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    console.error("Logout error:", error);

    return res.status(500).json({
      status: "error",
      message: "Internal server error",
      details: message,
    });
  }
};

export const profileAuthController = async (req: Request, res: Response) => {
  try {
    const token = req.cookies.accessToken;
    if (!token) {
      return res.status(401).json({ status: "error", message: "Unauthorized" });
    }

    const {
      data: { user },
      error,
    } = await supabase.auth.getUser(token);

    if (error || !user) {
      return res
        .status(401)
        .json({ status: "error", message: "Invalid token" });
    }

    const { data: userData, error: userError } = await supabase
      .from("iLocalUsers")
      .select("id, email, role, created_at, updated_at")
      .eq("id", user.id)
      .single();

    if (userError || !userData) {
      return res
        .status(404)
        .json({ status: "error", message: "User not found" });
    }

    return res.status(200).json({
      status: "success",
      data: {
        currentUser: {
          ...userData,
          isUserVerified: user.user_metadata?.isUserVerified ?? false,
        },
      },
    });
  } catch (error) {
    errorHandler(error, req, res);
  }
};