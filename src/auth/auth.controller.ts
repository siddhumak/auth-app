import {
  Body,
  Controller,
  Get,
  Post,
  Request,
  Res,
  UseGuards,
} from '@nestjs/common';
import type { Response } from 'express';
import { ForgotPinDto } from './dto/forgot-pin.dto';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { ResetPinDto } from './dto/reset-pin.dto';
import { SendOtpDto } from './dto/send-otp.dto';
import { SetPinDto } from './dto/set-pin.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { JwtRefreshGuard } from './jwt-refresh.guard';
import { AuthService } from './auth.service';
import {
  AuthTokensResult,
  AuthenticatedUser,
  RefreshRequestUser,
} from './auth.types';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  private readonly isProduction = process.env.NODE_ENV === 'production';
  private readonly accessTokenMaxAge = this.parseDurationToMs(
    process.env.JWT_EXPIRES_IN,
    15 * 60 * 1000,
  );
  private readonly refreshTokenMaxAge = this.parseDurationToMs(
    process.env.JWT_REFRESH_EXPIRES_IN,
    7 * 24 * 60 * 60 * 1000,
  );

  private parseDurationToMs(value: string | undefined, fallback: number) {
    if (!value) return fallback;

    const match = value.trim().match(/^(\d+)(ms|s|m|h|d)?$/i);
    if (!match) return fallback;

    const amount = Number(match[1]);
    const unit = (match[2] ?? 'ms').toLowerCase();
    const multipliers: Record<string, number> = {
      ms: 1,
      s: 1000,
      m: 60 * 1000,
      h: 60 * 60 * 1000,
      d: 24 * 60 * 60 * 1000,
    };

    return amount * (multipliers[unit] ?? 1);
  }

  private setAuthCookies(res: Response, tokens: AuthTokensResult) {
    res.cookie('access_token', tokens.accessToken, {
      httpOnly: true,
      secure: this.isProduction,
      sameSite: 'lax',
      maxAge: this.accessTokenMaxAge,
    });

    res.cookie('refresh_token', tokens.refreshToken, {
      httpOnly: true,
      secure: this.isProduction,
      sameSite: 'lax',
      maxAge: this.refreshTokenMaxAge,
    });
  }

  private clearAuthCookies(res: Response) {
    res.clearCookie('access_token', {
      httpOnly: true,
      secure: this.isProduction,
      sameSite: 'lax',
    });
    res.clearCookie('refresh_token', {
      httpOnly: true,
      secure: this.isProduction,
      sameSite: 'lax',
    });
  }
  @Post('register')
  async register(
    @Body() registerDto: RegisterDto,
  ) {
    const result = await this.authService.register(registerDto);
    return result;
  }

  @Post('send-otp')
  sendOtp(@Body() dto: SendOtpDto) {
    return this.authService.sendOtp(dto);
  }

  @Post('verify-otp')
  verifyOtp(@Body() dto: VerifyOtpDto) {
    return this.authService.verifyOtp(dto);
  }

  @Post('set-pin')
  async setPin(
    @Body() dto: SetPinDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.setPin(dto);
    this.setAuthCookies(res, result);

    return {
      message: 'PIN set successfully',
      user: result.user,
    };
  }

  @Post('login')
  async login(
    @Body() loginDto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.login(loginDto);
    this.setAuthCookies(res, result);

    return {
      message: 'Login successful',
      user: result.user,
    };
  }

  @Post('forgot-pin')
  forgotPin(@Body() dto: ForgotPinDto) {
    return this.authService.forgotPin(dto);
  }

  @Post('reset-pin')
  resetPin(@Body() dto: ResetPinDto) {
    return this.authService.resetPin(dto);
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  getProfile(@Request() req: { user: AuthenticatedUser }) {
    return {
      message: 'Current user profile',
      user: req.user,
    };
  }

  @UseGuards(JwtRefreshGuard)
  @Post('refresh')
  async refresh(
    @Request() req: { user: RefreshRequestUser },
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.refreshTokens(
      req.user.id,
      req.user.refreshToken,
    );
    this.setAuthCookies(res, result);

    return {
      message: 'Tokens refreshed successfully',
      user: result.user,
    };
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  async logout(
    @Request() req: { user: AuthenticatedUser },
    @Res({ passthrough: true }) res: Response,
  ) {
    await this.authService.logout(req.user.id);
    this.clearAuthCookies(res);

    return {
      message: 'Logout successful',
    };
  }
}
