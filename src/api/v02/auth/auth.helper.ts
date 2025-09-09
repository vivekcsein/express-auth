import { AuthError } from "@supabase/supabase-js";
import { supabase } from "../../../libs/db/db.supabase";
import {
  IUserRegistration,
  IUserSignin,
  IUserSignup,
} from "../../../types/users";

export const refreshTokenUser = async (params: { refreshToken: string }) => {
  const { refreshToken } = params;
  try {
    const { data, error } = await supabase.auth.refreshSession({
      refresh_token: refreshToken,
    });

    if (error) {
      throw new AuthError("Refresh token not found or unauthorized", 401);
    }

    return {
      success: true,
      message: "access token refresh successfully",
      data: data,
    };
  } catch (err: unknown) {
    const fallback = err as AuthError;
    throw {
      status: fallback?.status || 500,
      message:
        fallback?.message || "Unexpected error during fetching refresh token.",
    };
  }
};

export const getUserProfile = async (email: string) => {
  try {
    if (!email) throw new AuthError("Email not found or unauthorized", 401);

    const { data: userData, error: userError } = await supabase
      .from("iLocalUsers")
      .select("id, role, fullname, avatar")
      .eq("email", email)
      .single();

    if (userError) throw userError;
    return userData;
  } catch (err: unknown) {
    const fallback = err as AuthError;
    throw {
      status: fallback?.status || 500,
      message: fallback?.message || "Unexpected error during getUserProfile.",
    };
  }
};

export const getUserByToken = async (token: string) => {
  try {
    const {
      data: { user },
      error,
    } = await supabase.auth.getUser(token);

    if (error || !user) {
      throw new AuthError("User not found or unauthorized", 401);
    }

    if (!user.email) {
      throw new AuthError("User email not found or unauthorized", 401);
    }
    return user;
  } catch (error) {
    const fallback = error as AuthError;
    throw {
      status: fallback?.status || 500,
      message: fallback?.message || "Unexpected error during fetching user.",
    };
  }
};

export const registerUser = async (user: IUserSignup) => {
  try {
    const { data, error } = await supabase.auth.signUp({
      email: user.email,
      password: user.password,
    });

    if (error) {
      return {
        success: false,
        statusCode: 400,
        message: error.message,
        error,
      };
    }

    return {
      success: true,
      statusCode: 201,
      message: "User registered successfully",
      data,
    };
  } catch (err: unknown) {
    const fallback = err as AuthError;
    throw {
      status: fallback?.status || 500,
      message: fallback?.message || "Unexpected error during register.",
    };
  }
};

export const setUserToiLocalUser = async (
  newUser: IUserRegistration
): Promise<any> => {
  const { error: insertError } = await supabase
    .from("iLocalUsers")
    .insert([newUser])
    .single();

  if (insertError) {
    throw insertError;
  }
};

/**
 * Logs out the current user session.
 * @returns success status on successful logout
 * @throws AuthError with helpful message
 */
export const signoutUser = async () => {
  try {
    const { error } = await supabase.auth.signOut();

    if (error) {
      const fallback = error as AuthError;
      throw {
        status: fallback?.status || 500,
        message: fallback?.message || "Logout failed due to database error.",
      };
    }

    return { success: true, message: "user logged out successfully" };
  } catch (err: unknown) {
    const fallback = err as AuthError;
    throw {
      status: fallback?.status || 500,
      message: fallback?.message || "Unexpected error during signout.",
    };
  }
};

export const signinUser = async (user: IUserSignin) => {
  try {
    const { email, password } = user;

    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) {
      throw {
        success: false,
        status: error.status || 500,
        message: error.message,
        data: null,
      };
    }

    return {
      success: true,
      message: "user logged in successfully",
      data: data,
    };
  } catch (err: unknown) {
    const fallback = err as AuthError;
    throw {
      status: fallback?.status || 500,
      message: fallback?.message || "Unexpected error during signin.",
    };
  }
};
