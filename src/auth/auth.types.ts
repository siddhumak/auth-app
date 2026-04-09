import { UserRole } from '../users/entities/user.entity';

export type AuthenticatedUser = {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  isActive: boolean;
};

export type RefreshRequestUser = AuthenticatedUser & {
  refreshToken: string;
};

export type AuthResponseUser = AuthenticatedUser & {
  createdAt: Date;
  updatedAt: Date;
};

export type AuthTokensResult = {
  accessToken: string;
  refreshToken: string;
  user: AuthResponseUser;
};
