using System;
using System.Diagnostics.Eventing.Reader;
using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers;

public class AccountController(DataContext context, ITokenService tokenService):BaseApiController
{
    [HttpPost("register")]
    public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
    {
        if(await UserExists(registerDto.Username))
        {
            return BadRequest("User already exists");
        }
        using var hmac = new HMACSHA512();

        var user=new AppUser
        {
            UserName =registerDto.Username.ToLower(),
            PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
            PasswordSalt = hmac.Key
        };
        context.Add(user);
        await context.SaveChangesAsync();
        return new UserDto{
            Username =registerDto.Username,
            Token = tokenService.CreateToken(user)
        };
    }

    [HttpPost("login")]
    public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
    {
        var user= context.Users.FirstOrDefault(x=>x.UserName ==loginDto.Username.ToLower());
        if(user ==null){
            return Unauthorized("Invalid Username");
        }
        using var hmac= new HMACSHA512(user.PasswordSalt);

        var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

        for (int i = 0; i < computedHash.Length; i++)
        {
            if(computedHash[i]!= user.PasswordHash[i])
            {
                return Unauthorized("Invaid password");
            }
        }
        return new UserDto{
            Username =loginDto.Username,
            Token = tokenService.CreateToken(user)
        };
    }
    public async Task<bool> UserExists(string username)
    {
        return await context.Users.AnyAsync(x=>x.UserName.ToLower() == username.ToLower());
    }
}
