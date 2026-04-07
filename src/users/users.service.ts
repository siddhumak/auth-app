import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';

@Injectable()
export class UsersService {
    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
    ) {}

    async create(user:Partial<User>): Promise<User> {
        const newUser = this.userRepository.create(user);
        return this.userRepository.save(newUser);
    }

    async findByEmail(email:string): Promise<User | null> {
        return this.userRepository.findOne({ where: { email } });
    }

    async findById(id:string): Promise<User | null> {
        return this.userRepository.findOne({ where: { id } });
    }


}
