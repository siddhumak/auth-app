import { ConflictException, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Test, TestingModule } from '@nestjs/testing';
import { RegistrationStatus, UserRole } from '../users/entities/user.entity';
import { UsersService } from '../users/users.service';
import { AuthService } from './auth.service';

describe('AuthService', () => {
  let service: AuthService;
  let usersService: {
    findByEmail: jest.Mock;
    findByEmailWithSensitiveFields: jest.Mock;
    findByIdWithSensitiveFields: jest.Mock;
    updateHashedRefreshToken: jest.Mock;
    updateLoginSecurity: jest.Mock;
    updateOtpData: jest.Mock;
    create: jest.Mock;
    findById: jest.Mock;
    updatePin: jest.Mock;
  };

  beforeEach(async () => {
    usersService = {
      findByEmail: jest.fn(),
      findByEmailWithSensitiveFields: jest.fn(),
      findByIdWithSensitiveFields: jest.fn(),
      updateHashedRefreshToken: jest.fn(),
      updateLoginSecurity: jest.fn(),
      updateOtpData: jest.fn(),
      create: jest.fn(),
      findById: jest.fn(),
      updatePin: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: UsersService,
          useValue: usersService,
        },
        {
          provide: JwtService,
          useValue: {
            signAsync: jest.fn().mockResolvedValue('token'),
          },
        },
        {
          provide: ConfigService,
          useValue: {
            getOrThrow: jest.fn((key: string) => {
              const config: Record<string, string> = {
                JWT_SECRET: 'secret',
                JWT_EXPIRES_IN: '15m',
                JWT_REFRESH_SECRET: 'refresh-secret',
                JWT_REFRESH_EXPIRES_IN: '7d',
              };

              return config[key];
            }),
          },
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('throws conflict when a completed user registers again', async () => {
    usersService.findByEmail.mockResolvedValue({
      id: '1',
      name: 'Existing User',
      email: 'existing@example.com',
      role: UserRole.USER,
      isActive: true,
      isPinSet: true,
      registrationStatus: RegistrationStatus.COMPLETED,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    await expect(
      service.register({
        name: 'Existing User',
        email: 'existing@example.com',
      }),
    ).rejects.toBeInstanceOf(ConflictException);
  });

  it('blocks refresh for incomplete registrations', async () => {
    usersService.findByIdWithSensitiveFields.mockResolvedValue({
      id: '1',
      name: 'Pending User',
      email: 'pending@example.com',
      role: UserRole.USER,
      isActive: true,
      isPinSet: false,
      registrationStatus: RegistrationStatus.PENDING,
      hashedRefreshToken: '$2b$10$fakehash',
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    await expect(service.refreshTokens('1', 'raw-refresh-token')).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });
});
