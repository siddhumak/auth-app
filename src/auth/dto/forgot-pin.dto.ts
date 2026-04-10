import { IsEmail } from 'class-validator';

export class ForgotPinDto {
  @IsEmail()
  email!: string;
}
