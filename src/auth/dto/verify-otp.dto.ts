import { IsEmail, IsEnum, IsString, Length, Matches } from 'class-validator';
import { OtpPurpose } from '../../users/entities/user.entity';

export class VerifyOtpDto {
  @IsEmail()
  email!: string;

  @IsString()
  @Length(6, 6)
  @Matches(/^\d{6}$/, { message: 'OTP must be 6 digits' })
  otp!: string;

  @IsEnum(OtpPurpose)
  purpose!: OtpPurpose;
}
