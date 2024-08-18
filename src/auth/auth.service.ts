import { HttpStatus, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { RegisterUserDto } from './dto/register-user.dto';
import { RpcException } from '@nestjs/microservices';

import * as bcrypt from 'bcrypt';
import { LoginUserDto } from './dto/login-user.dto';
import { JwtService } from '@nestjs/jwt';
import { IJwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config/envs';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  constructor(private readonly jwtService: JwtService) {
    super();
  }
  private logger = new Logger('Auth Service-MS');

  onModuleInit() {
    this.$connect();
    this.logger.log('MongoDB connected');
  }

  async signJwt(payload: IJwtPayload) {
    return await this.jwtService.signAsync(payload);
  }

  async verifyToken(token: string) {
    try {
      const payload: IJwtPayload = await this.jwtService.verifyAsync(token, {
        secret: envs.jwtSecret,
      });
      return payload;
    } catch (error) {
      throw new RpcException({
        statusCode: HttpStatus.UNAUTHORIZED,
        message: 'Invalid Token',
      });
    }
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    const { email, password, name } = registerUserDto;
    try {
      const user = await this.user.findUnique({ where: { email } });

      if (user)
        throw new RpcException({
          statusCode: 400,
          message: 'User already exists',
        });

      const hashedPassword = await bcrypt.hash(password, 10);

      const newUser = await this.user.create({
        data: {
          email,
          password: hashedPassword,
          name,
        },
      });

      const payloadToken = {
        id: newUser.id,
        email: newUser.email,
      };

      const token = await this.signJwt(payloadToken);

      const { password: __, ...rest } = newUser;
      return { newUser: rest, token };
    } catch (error) {
      throw new RpcException({
        statusCode: 400,
        message: error.message,
      });
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;
    try {
      const user = await this.user.findUnique({ where: { email } });
      if (!user)
        throw new RpcException({
          statusCode: 400,
          message: 'Invalid credentials',
        });

      const isValidPassword = await bcrypt.compare(password, user.password);
      if (!isValidPassword)
        throw new RpcException({
          statusCode: 400,
          message: 'Invalid credentials',
        });

      const payloadToken = {
        id: user.id,
        email: user.email,
      };

      const token = await this.signJwt(payloadToken);
      const { password: __, ...rest } = user;
      return { user: rest, token };
    } catch (error) {
      throw new RpcException({
        statusCode: 400,
        message: error.message,
      });
    }
  }
}
