import { IsEmail, IsEnum } from 'class-validator';
import { OtpPurpose } from '../../users/entities/user.entity';

export class SendOtpDto {
  @IsEmail()
  email!: string;

  @IsEnum(OtpPurpose)
  purpose!: OtpPurpose;
}
