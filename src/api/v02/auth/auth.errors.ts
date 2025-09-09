import { Request, Response, NextFunction } from "express";
import type { routesOptions } from "./auth.routes";

type SupabaseAuthError = {
  message?: string;
  status?: number;
  code?: string;
};

/**
 * Maps Supabase error codes/messages to user-friendly messages.
 */
const mapAuthErrorMessage = (err: SupabaseAuthError): string => {
  const raw = err.message?.toLowerCase() ?? "";

  if (
    raw.includes("unauthorized") ||
    raw.includes("invalid login credentials")
  ) {
    return "Invalid email or password. Please try again.";
  }

  if (raw.includes("user not found")) {
    return "No account found with this email.";
  }

  if (raw.includes("email already registered")) {
    return "This email is already registered. Try logging in instead.";
  }

  if (raw.includes("invalid email")) {
    return "Please enter a valid email address.";
  }

  if (raw.includes("password too short")) {
    return "Password must be at least 6 characters long.";
  }

  if (raw.includes("too many requests")) {
    return "Too many login attempts. Please wait a moment and try again.";
  }

  return err.message || "Something went wrong. Please try again.";
};

/**
 * Creates a reusable auth error handler for Express routes.
 * @param context - Optional context label for debugging or logging.
 */
const createAuthErrorHandler =
  (context?: routesOptions) =>
  (
    err: Error & SupabaseAuthError,
    _req: Request,
    res: Response,
    _next: NextFunction
  ) => {
    const message = mapAuthErrorMessage(err);

    if (process.env.NODE_ENV === "development") {
      console.error("❌ Auth error:", {
        message: err.message,
        code: err.code,
        status: err.status,
        stack: err.stack,
        context,
      });
    }

    res.status(err.status ?? 401).json({
      success: false,
      message,
      ...(context && { context }),
    });
  };

export const errorHandler = (context: routesOptions) =>
  createAuthErrorHandler(context);
