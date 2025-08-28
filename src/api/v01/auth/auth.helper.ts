import { AuthResponse } from "@supabase/supabase-js";
import { supabase } from "../../../libs/db/db.supabase";

// Custom error type
interface AuthError {
  message: string;
  status?: number;
}

interface LogoutResult {
  success: boolean;
  message: string;
}

// Controller return type
type LoginResult = AuthResponse["data"] | null;
type RegisterResult = AuthResponse["data"] | null;

/**
 * Attempts to log in a user via Supabase.
 * @param email - User's email
 * @param password - User's password
 * @returns Supabase user session on success
 * @throws AuthError with descriptive message
 */
export const loginAuthHelper = async (
  email: string,
  password: string
): Promise<LoginResult> => {
  if (!email || !password) {
    throw {
      message: "Email and password are required for login.",
      status: 400,
    } satisfies AuthError;
  }

  try {
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) {
      throw {
        message:
          error.message || "Login failed. Please check your credentials.",
        status: error.status || 401,
      } satisfies AuthError;
    }

    if (!data?.session) {
      throw {
        message: "No active session returned. Login may have failed silently.",
        status: 500,
      } satisfies AuthError;
    }

    return data;
  } catch (err: unknown) {
    const fallback = err as AuthError;
    throw {
      message: fallback?.message || "Unexpected error during login.",
      status: fallback?.status || 500,
    };
  }
};

/**
 * Logs out the current user session.
 * @returns success status on successful logout
 * @throws AuthError with helpful message
 */
export const logoutAuthHelper = async (): Promise<LogoutResult> => {
  try {
    const { error } = await supabase.auth.signOut();

    if (error) {
      throw {
        message: error.message || "Logout failed due to Supabase error.",
        status: error.status || 500,
      } satisfies AuthError;
    }

    return { success: true, message: "user logged out successfully" };
  } catch (err: unknown) {
    const fallback = err as AuthError;
    throw {
      message: fallback?.message || "Unexpected error during logout.",
      status: fallback?.status || 500,
    };
  }
};

/**
 * Registers a new user with Supabase.
 * @param email - New user's email
 * @param fullname - New fullname
 * @param password - New user's password
 * @returns User session on successful signup
 * @throws AuthError with descriptive feedback
 */
export const registerAuthHelper = async (
  email: string,
  password: string
): Promise<RegisterResult> => {
  if (!email || !password) {
    throw {
      message: "Email and password are required to register.",
      status: 400,
    } satisfies AuthError;
  }

  try {
    const { data, error } = await supabase.auth.signUp({ email, password });

    if (error) {
      throw {
        message: error.message || "Registration failed. Try a different email.",
        status: error.status || 409,
      } satisfies AuthError;
    }

    if (!data?.user) {
      throw {
        message:
          "No user object returned. Something went wrong during registration.",
        status: 500,
      } satisfies AuthError;
    }

    return data;
  } catch (err: unknown) {
    const fallback = err as AuthError;
    throw {
      message: fallback?.message || "Unexpected error during registration.",
      status: fallback?.status || 500,
    };
  }
};
