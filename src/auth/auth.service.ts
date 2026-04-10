import {
  BadRequestException,
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { randomInt } from 'crypto';
import {
  OtpPurpose,
  RegistrationStatus,
  User,
} from '../users/entities/user.entity';
import { UsersService } from '../users/users.service';
import { ForgotPinDto } from './dto/forgot-pin.dto';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { ResetPinDto } from './dto/reset-pin.dto';
import { SendOtpDto } from './dto/send-otp.dto';
import { SetPinDto } from './dto/set-pin.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import {
  AuthResponseUser,
  AuthTokensResult,
  AuthenticatedUser,
} from './auth.types';

@Injectable()
export class AuthService {
  private readonly otpCooldownMs = 60 * 1000;
  private readonly otpExpiryMs = 5 * 60 * 1000;
  private readonly registrationWindowMs = 24 * 60 * 60 * 1000;
  private readonly maxOtpAttempts = 5;
  private readonly maxLoginAttempts = 5;
  private readonly loginLockMs = 15 * 60 * 1000;

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async register(registerDto: RegisterDto) {
    const existingUser = await this.usersService.findByEmail(registerDto.email);
    if (existingUser) {
      if (existingUser.registrationStatus === RegistrationStatus.COMPLETED) {
        throw new ConflictException('Email already exists');
      }

      const registrationExpired =
        existingUser.registrationExpiresAt &&
        existingUser.registrationExpiresAt.getTime() < Date.now();

      if (registrationExpired) {
        const refreshedRegistrationExpiresAt = new Date(
          Date.now() + this.registrationWindowMs,
        );

        await this.usersService.updateOtpData(existingUser.id, {
          otpCodeHash: null,
          otpPurpose: null,
          otpExpiresAt: null,
          otpVerifiedAt: null,
          otpLastSentAt: null,
          otpAttempts: 0,
          isOtpVerified: false,
          registrationStatus: RegistrationStatus.PENDING,
          registrationExpiresAt: refreshedRegistrationExpiresAt,
        });

        const refreshedUser = await this.usersService.findById(existingUser.id);

        if (!refreshedUser) {
          throw new UnauthorizedException('Unable to restart registration');
        }

        return {
          message:
            'Previous registration expired. A fresh registration window has been started. Please send OTP again.',
          user: this.toAuthResponseUser(refreshedUser),
        };
      }

      return {
        message:
          'Registration already started. Please continue with OTP verification and PIN setup.',
        user: this.toAuthResponseUser(existingUser),
      };
    }

    const registrationExpiresAt = new Date(
      Date.now() + this.registrationWindowMs,
    );
    const user = await this.usersService.create({
      name: registerDto.name,
      email: registerDto.email,
      isPinSet: false,
      isOtpVerified: false,
      registrationStatus: RegistrationStatus.PENDING,
      registrationExpiresAt,
    });

    return {
      message:
        'Registration started successfully. Please send OTP, verify it, and set your PIN.',
      user: this.toAuthResponseUser(user),
    };
  }

  async sendOtp(sendOtpDto: SendOtpDto) {
    const user = await this.usersService.findByEmailWithSensitiveFields(
      sendOtpDto.email,
    );

    if (!user) {
      return {
        message: 'If the account is eligible, an OTP has been sent.',
      };
    }

    if (
      user.registrationStatus !== RegistrationStatus.COMPLETED &&
      user.registrationExpiresAt &&
      user.registrationExpiresAt.getTime() < Date.now()
    ) {
      throw new UnauthorizedException(
        'Registration session expired. Please register again.',
      );
    }

    if (
      user.otpLastSentAt &&
      Date.now() - user.otpLastSentAt.getTime() < this.otpCooldownMs
    ) {
      throw new BadRequestException(
        'Please wait before requesting another OTP',
      );
    }

    if (
      sendOtpDto.purpose === OtpPurpose.PIN_SETUP &&
      user.registrationStatus === RegistrationStatus.COMPLETED
    ) {
      throw new BadRequestException('PIN is already set for this account');
    }

    const rawOtp = this.generateOtp();
    const hashedOtp = await bcrypt.hash(rawOtp, 10);
    const expiresAt = new Date(Date.now() + this.otpExpiryMs);

    await this.usersService.updateOtpData(user.id, {
      otpCodeHash: hashedOtp,
      otpPurpose: sendOtpDto.purpose,
      otpExpiresAt: expiresAt,
      otpVerifiedAt: null,
      otpLastSentAt: new Date(),
      otpAttempts: 0,
      isOtpVerified: false,
      registrationStatus:
        sendOtpDto.purpose === OtpPurpose.PIN_SETUP
          ? RegistrationStatus.PENDING
          : user.registrationStatus,
    });

    console.log(`OTP for ${sendOtpDto.email} [${sendOtpDto.purpose}]: ${rawOtp}`);

    return {
      message: 'OTP sent successfully',
    };
  }

  async verifyOtp(verifyOtpDto: VerifyOtpDto) {
    const user = await this.usersService.findByEmailWithSensitiveFields(
      verifyOtpDto.email,
    );

    if (
      !user ||
      !user.otpCodeHash ||
      !user.otpExpiresAt ||
      user.otpPurpose !== verifyOtpDto.purpose
    ) {
      throw new UnauthorizedException('Invalid OTP request');
    }

    if (user.otpExpiresAt.getTime() < Date.now()) {
      await this.usersService.updateOtpData(user.id, {
        otpCodeHash: null,
        otpPurpose: null,
        otpExpiresAt: null,
        otpVerifiedAt: null,
        otpAttempts: 0,
        isOtpVerified: false,
      });
      throw new UnauthorizedException('OTP expired');
    }

    if ((user.otpAttempts ?? 0) >= this.maxOtpAttempts) {
      await this.clearOtpState(user.id);
      throw new UnauthorizedException(
        'OTP attempts exceeded. Request a new OTP',
      );
    }

    const isOtpValid = await bcrypt.compare(verifyOtpDto.otp, user.otpCodeHash);

    if (!isOtpValid) {
      const nextAttempts = (user.otpAttempts ?? 0) + 1;

      if (nextAttempts >= this.maxOtpAttempts) {
        await this.clearOtpState(user.id);
        throw new UnauthorizedException(
          'OTP attempts exceeded. Request a new OTP',
        );
      }

      await this.usersService.updateOtpData(user.id, {
        otpAttempts: nextAttempts,
      });
      throw new UnauthorizedException('Invalid OTP');
    }

    await this.usersService.updateOtpData(user.id, {
      otpCodeHash: null,
      otpPurpose: null,
      otpExpiresAt: null,
      otpVerifiedAt: new Date(),
      otpAttempts: 0,
      isOtpVerified: true,
      registrationStatus:
        verifyOtpDto.purpose === OtpPurpose.PIN_SETUP
          ? RegistrationStatus.OTP_VERIFIED
          : user.registrationStatus,
    });

    return {
      message: 'OTP verified successfully',
    };
  }

  async setPin(setPinDto: SetPinDto): Promise<AuthTokensResult> {
    const user = await this.usersService.findByEmailWithSensitiveFields(
      setPinDto.email,
    );

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    if (setPinDto.pin !== setPinDto.confirmPin) {
      throw new BadRequestException('PIN and confirm PIN do not match');
    }

    if (user.registrationStatus !== RegistrationStatus.OTP_VERIFIED) {
      throw new UnauthorizedException('Verify OTP before setting PIN');
    }

    const pinHash = await bcrypt.hash(setPinDto.pin, 10);
    await this.usersService.updatePin(user.id, pinHash);

    const updatedUser = await this.usersService.findByIdWithSensitiveFields(
      user.id,
    );

    if (!updatedUser) {
      throw new UnauthorizedException('User not found after PIN setup');
    }

    return this.generateTokensAndStoreRefreshToken(updatedUser);
  }

  async login(loginDto: LoginDto): Promise<AuthTokensResult> {
    const user = await this.usersService.findByEmailWithSensitiveFields(
      loginDto.email,
    );
    if (!user || !user.pinHash) {
      throw new UnauthorizedException('Invalid email or PIN');
    }

    if (user.lockedUntil && user.lockedUntil.getTime() > Date.now()) {
      throw new UnauthorizedException(
        'Account temporarily locked. Please try again later.',
      );
    }

    if (!user.isPinSet || user.registrationStatus !== RegistrationStatus.COMPLETED) {
      throw new UnauthorizedException('Complete registration before login');
    }

    if (!user.isActive) {
      throw new UnauthorizedException('Account is inactive');
    }

    const isPinValid = await bcrypt.compare(loginDto.pin, user.pinHash);
    if (!isPinValid) {
      const nextAttempts = (user.failedLoginAttempts ?? 0) + 1;

      if (nextAttempts >= this.maxLoginAttempts) {
        await this.usersService.updateLoginSecurity(user.id, {
          failedLoginAttempts: 0,
          lockedUntil: new Date(Date.now() + this.loginLockMs),
        });
        throw new UnauthorizedException(
          'Account temporarily locked due to repeated failed login attempts',
        );
      }

      await this.usersService.updateLoginSecurity(user.id, {
        failedLoginAttempts: nextAttempts,
      });
      throw new UnauthorizedException('Invalid email or PIN');
    }

    if ((user.failedLoginAttempts ?? 0) > 0 || user.lockedUntil) {
      await this.usersService.updateLoginSecurity(user.id, {
        failedLoginAttempts: 0,
        lockedUntil: null,
      });
    }

    return this.generateTokensAndStoreRefreshToken(user);
  }

  async forgotPin(forgotPinDto: ForgotPinDto) {
    const user = await this.usersService.findByEmail(forgotPinDto.email);

    if (!user) {
      return {
        message: 'If an account with that email exists, OTP has been sent.',
      };
    }

    return this.sendOtp({
      email: forgotPinDto.email,
      purpose: OtpPurpose.PIN_RESET,
    });
  }

  async resetPin(resetPinDto: ResetPinDto) {
    const user = await this.usersService.findByEmailWithSensitiveFields(
      resetPinDto.email,
    );

    if (
      !user ||
      !user.otpCodeHash ||
      !user.otpExpiresAt ||
      user.otpPurpose !== OtpPurpose.PIN_RESET
    ) {
      throw new UnauthorizedException('Invalid reset request');
    }

    if (user.otpExpiresAt.getTime() < Date.now()) {
      await this.usersService.updateOtpData(user.id, {
        otpCodeHash: null,
        otpPurpose: null,
        otpExpiresAt: null,
        otpVerifiedAt: null,
        otpAttempts: 0,
        isOtpVerified: false,
      });
      throw new UnauthorizedException('OTP expired');
    }

    if ((user.otpAttempts ?? 0) >= this.maxOtpAttempts) {
      await this.clearOtpState(user.id);
      throw new UnauthorizedException(
        'OTP attempts exceeded. Request a new OTP',
      );
    }

    const isOtpValid = await bcrypt.compare(resetPinDto.otp, user.otpCodeHash);

    if (!isOtpValid) {
      const nextAttempts = (user.otpAttempts ?? 0) + 1;

      if (nextAttempts >= this.maxOtpAttempts) {
        await this.clearOtpState(user.id);
        throw new UnauthorizedException(
          'OTP attempts exceeded. Request a new OTP',
        );
      }

      await this.usersService.updateOtpData(user.id, {
        otpAttempts: nextAttempts,
      });
      throw new UnauthorizedException('Invalid OTP');
    }

    const pinHash = await bcrypt.hash(resetPinDto.newPin, 10);
    await this.usersService.updatePin(user.id, pinHash);
    await this.usersService.updateHashedRefreshToken(user.id, null);

    return {
      message: 'PIN reset successfully',
    };
  }

  async refreshTokens(
    userId: string,
    refreshToken: string,
  ): Promise<AuthTokensResult> {
    const user = await this.usersService.findByIdWithSensitiveFields(userId);

    if (!user || !user.hashedRefreshToken) {
      throw new UnauthorizedException('Access denied');
    }

    if (!user.isActive) {
      throw new UnauthorizedException('Account is inactive');
    }

    if (!user.isPinSet || user.registrationStatus !== RegistrationStatus.COMPLETED) {
      throw new UnauthorizedException('Complete registration before continuing');
    }

    const refreshTokenMatches = await bcrypt.compare(
      refreshToken,
      user.hashedRefreshToken,
    );

    if (!refreshTokenMatches) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    return this.generateTokensAndStoreRefreshToken(user);
  }
  //Logout Method
  async logout(userId: string) {
    await this.usersService.updateHashedRefreshToken(userId, null);
    return { message: 'Logged out successfully' };
  }

  //validate user by Id
  async validateUserById(userId: string): Promise<AuthenticatedUser | null> {
    const user = await this.usersService.findById(userId);
    return user ? this.toAuthenticatedUser(user) : null;
  }
  //Generate Access and Refresh Tokens
  private async generateTokens(user: User) {
    const accessSecret = this.configService.getOrThrow<string>('JWT_SECRET');
    const accessExpiresIn =
      this.configService.getOrThrow<string>('JWT_EXPIRES_IN');
    const refreshSecret =
      this.configService.getOrThrow<string>('JWT_REFRESH_SECRET');
    const refreshExpiresIn = this.configService.getOrThrow<string>(
      'JWT_REFRESH_EXPIRES_IN',
    );

    const payload = {
      sub: user.id,
      email: user.email,
      role: user.role,
    };

    const accessToken = await this.jwtService.signAsync(payload, {
      secret: accessSecret,
      expiresIn: accessExpiresIn as any,
    });

    const refreshToken = await this.jwtService.signAsync(payload, {
      secret: refreshSecret,
      expiresIn: refreshExpiresIn as any,
    });

    return {
      accessToken,
      refreshToken,
    };
  }

  private async generateTokensAndStoreRefreshToken(
    user: User,
  ): Promise<AuthTokensResult> {
    const { accessToken, refreshToken } = await this.generateTokens(user);

    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

    await this.usersService.updateHashedRefreshToken(
      user.id,
      hashedRefreshToken,
    );
    return {
      accessToken,
      refreshToken,
      user: this.toAuthResponseUser(user),
    };
  }

  private toAuthenticatedUser(user: User): AuthenticatedUser {
    return {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      isActive: user.isActive,
      isPinSet: user.isPinSet,
      registrationStatus: user.registrationStatus,
    };
  }

  private toAuthResponseUser(user: User): AuthResponseUser {
    return {
      ...this.toAuthenticatedUser(user),
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }

  private generateOtp(): string {
    return String(randomInt(100000, 1000000));
  }

  private async clearOtpState(userId: string) {
    await this.usersService.updateOtpData(userId, {
      otpCodeHash: null,
      otpPurpose: null,
      otpExpiresAt: null,
      otpVerifiedAt: null,
      otpLastSentAt: null,
      otpAttempts: 0,
      isOtpVerified: false,
    });
  }
}
