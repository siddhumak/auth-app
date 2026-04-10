import { IsEmail, IsString, Length, Matches } from 'class-validator';

export class SetPinDto {
  @IsEmail()
  email!: string;

  @IsString()
  @Length(6, 6)
  @Matches(/^\d{6}$/, { message: 'PIN must be 6 digits' })
  pin!: string;

  @IsString()
  @Length(6, 6)
  @Matches(/^\d{6}$/, { message: 'Confirm PIN must be 6 digits' })
  confirmPin!: string;
}
