import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import {
  OtpPurpose,
  RegistrationStatus,
  User,
} from './entities/user.entity';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async create(user: Partial<User>): Promise<User> {
    const newUser = this.userRepository.create(user);
    return this.userRepository.save(newUser);
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { email } });
  }

  async findById(id: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { id } });
  }

  async findByIdWithSensitiveFields(id: string): Promise<User | null> {
    return this.findOneWithSensitiveFields({ id });
  }

  async findByEmailWithSensitiveFields(email: string): Promise<User | null> {
    return this.findOneWithSensitiveFields({ email });
  }

  private async findOneWithSensitiveFields(
    where: Partial<Pick<User, 'id' | 'email'>>,
  ): Promise<User | null> {
    return this.userRepository.findOne({
      where,
      select: {
        id: true,
        name: true,
        email: true,
        pinHash: true,
        role: true,
        isActive: true,
        isPinSet: true,
        isOtpVerified: true,
        registrationStatus: true,
        otpCodeHash: true,
        otpPurpose: true,
        otpExpiresAt: true,
        otpVerifiedAt: true,
        otpLastSentAt: true,
        registrationExpiresAt: true,
        otpAttempts: true,
        failedLoginAttempts: true,
        lockedUntil: true,
        hashedRefreshToken: true,
        createdAt: true,
        updatedAt: true,
      },
    });
  }

  async updateHashedRefreshToken(
    userId: string,
    hashedRefreshToken: string | null,
  ): Promise<void> {
    await this.userRepository.update(userId, { hashedRefreshToken });
  }

  async updateOtpData(
    userId: string,
    data: {
      otpCodeHash?: string | null;
      otpPurpose?: OtpPurpose | null;
      otpExpiresAt?: Date | null;
      otpVerifiedAt?: Date | null;
      otpLastSentAt?: Date | null;
      otpAttempts?: number;
      isOtpVerified?: boolean;
      registrationStatus?: RegistrationStatus;
      registrationExpiresAt?: Date | null;
    },
  ): Promise<void> {
    await this.userRepository.update(userId, data);
  }

  async updatePin(userId: string, pinHash: string): Promise<void> {
    await this.userRepository.update(userId, {
      pinHash,
      isPinSet: true,
      isOtpVerified: false,
      registrationStatus: RegistrationStatus.COMPLETED,
      otpCodeHash: null,
      otpPurpose: null,
      otpExpiresAt: null,
      otpVerifiedAt: null,
      otpLastSentAt: null,
      otpAttempts: 0,
      registrationExpiresAt: null,
    });
  }

  async updateLoginSecurity(
    userId: string,
    data: {
      failedLoginAttempts?: number;
      lockedUntil?: Date | null;
    },
  ): Promise<void> {
    await this.userRepository.update(userId, data);
  }
}
