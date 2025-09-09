export type IUserProfileRoleType = "ADMIN" | "USER" | "MODERATOR";

export interface ILocalUserAttributes {
  id?: number;
  uid: string;
  email: string;
  password: string;
  role: IUserProfileRoleType;
  fullname: string;
  username?: string;
  avatar?: string;
  isActive: boolean;
  email_verified: boolean;
  last_login?: Date;
  created_at?: Date;
  updated_at?: Date;
}

export interface IUserSignup {
  email: string;
  password: string;
  fullname: string;
  terms: boolean;
}

export interface IUserSignin {
  email: string;
  password: string;
  remember?: boolean;
}

export interface IUserRegistration {
  user_id: string;
  email: string;
  fullname: string;
  role: IUserProfileRoleType;
  created_at: string;
  updated_at: string | undefined;
}
