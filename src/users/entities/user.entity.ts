import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

export enum UserRole {
  USER = 'user',
  ADMIN = 'admin',
}

export enum OtpPurpose {
  PIN_SETUP = 'pin_setup',
  PIN_RESET = 'pin_reset',
}

export enum RegistrationStatus {
  PENDING = 'pending',
  OTP_VERIFIED = 'otp_verified',
  COMPLETED = 'completed',
}

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ length: 100 })
  name!: string;

  @Column({ unique: true })
  email!: string;

  @Column({ type: 'text', select: false, nullable: true })
  pinHash?: string | null;


  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.USER,
  })
  role!: UserRole;

  @Column({ default: true })
  isActive!: boolean;

  @Column({ default: false })
  isPinSet!: boolean;

  @Column({ default: false })
  isOtpVerified!: boolean;

  @Column({
    type: 'enum',
    enum: RegistrationStatus,
    default: RegistrationStatus.PENDING,
  })
  registrationStatus!: RegistrationStatus;

  @Column({ type: 'text', nullable: true, select: false })
  otpCodeHash?: string | null;

  @Column({
    type: 'enum',
    enum: OtpPurpose,
    nullable: true,
  })
  otpPurpose?: OtpPurpose | null;

  @Column({ type: 'timestamp', nullable: true })
  otpExpiresAt?: Date | null;

  @Column({ type: 'timestamp', nullable: true })
  otpVerifiedAt?: Date | null;

  @Column({ type: 'timestamp', nullable: true })
  otpLastSentAt?: Date | null;

  @Column({ type: 'timestamp', nullable: true })
  registrationExpiresAt?: Date | null;

  @Column({ type: 'int', default: 0 })
  otpAttempts!: number;

  @Column({ type: 'int', default: 0 })
  failedLoginAttempts!: number;

  @Column({ type: 'timestamp', nullable: true })
  lockedUntil?: Date | null;

  @Column({ type: 'text', nullable: true })
  hashedRefreshToken?: string | null;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;
}
