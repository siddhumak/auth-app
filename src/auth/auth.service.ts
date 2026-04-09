import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { User } from '../users/entities/user.entity';
import { UsersService } from '../users/users.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import {
  AuthResponseUser,
  AuthTokensResult,
  AuthenticatedUser,
} from './auth.types';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  //Rgister a new user
  async register(registerDto: RegisterDto): Promise<AuthTokensResult> {
    const existingUser = await this.usersService.findByEmail(registerDto.email);
    if (existingUser) {
      throw new ConflictException('Email already exists');
    }

    const hashedPassword = await bcrypt.hash(registerDto.password, 10);

    const user = await this.usersService.create({
      name: registerDto.name,
      email: registerDto.email,
      password: hashedPassword,
    });

    return this.generateTokensAndStoreRefreshToken(user);
  }

  //Login user
  async login(loginDto: LoginDto): Promise<AuthTokensResult> {
    const user = await this.usersService.findByEmail(loginDto.email, true);
    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const isPasswordValid = await bcrypt.compare(
      loginDto.password,
      user.password,
    );
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid email or password');
    }

    return this.generateTokensAndStoreRefreshToken(user);
  }

  async refreshTokens(
    userId: string,
    refreshToken: string,
  ): Promise<AuthTokensResult> {
    const user = await this.usersService.findByIdWithSensitiveFields(userId);

    if (!user || !user.hashedRefreshToken) {
      throw new UnauthorizedException('Access denied');
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
    };
  }

  private toAuthResponseUser(user: User): AuthResponseUser {
    return {
      ...this.toAuthenticatedUser(user),
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }
}
