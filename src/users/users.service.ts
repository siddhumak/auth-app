import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';

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

  async findByEmail(
    email: string,
    includePassword = false,
  ): Promise<User | null> {
    return this.userRepository.findOne({
      where: { email },
      select: includePassword
        ? {
            id: true,
            name: true,
            email: true,
            password: true,
            role: true,
            isActive: true,
            hashedRefreshToken: true,
            createdAt: true,
            updatedAt: true,
          }
        : undefined,
    });
  }

  async findById(id: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { id } });
  }

  async findByIdWithSensitiveFields(id: string): Promise<User | null> {
    return this.userRepository.findOne({
      where: { id },
      select: {
        id: true,
        name: true,
        email: true,
        password: true,
        role: true,
        isActive: true,
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
}
