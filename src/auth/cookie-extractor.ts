import { Request } from 'express';

export const extractAccessTokenFromCookie = (
  req: Request,
): string | null => {
  if (!req || !req.cookies) return null;
  return req.cookies['access_token'] || null;
};

export const extractRefreshTokenFromCookie = (
  req: Request,
): string | null => {
  if (!req || !req.cookies) return null;
  return req.cookies['refresh_token'] || null;
};
