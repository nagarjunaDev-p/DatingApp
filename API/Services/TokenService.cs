using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using API.Entities;
using API.Interfaces;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace API.Services;

public class TokenService(IConfiguration config) : ITokenService
{
    public string CreateToken(AppUser appUser){
        
        var test = config.GetSection("Tokenkey").Value;
        var tokenKey=config["Tokenkey"] ?? throw new Exception("Cannot access Token key from Appsettings");
        if(tokenKey.Length<64) throw new Exception("Token needs to be longer");

        var key =new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenKey)); //UTF8 uses less memory

        var claims =new List<Claim>{
            new (ClaimTypes.NameIdentifier,appUser.UserName)
        };
        var creds= new SigningCredentials(key,SecurityAlgorithms.HmacSha512Signature);

        var tokenDescriptor = new SecurityTokenDescriptor{
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = creds
        };

        var tokenhandler= new JwtSecurityTokenHandler();
        var token = tokenhandler.CreateToken(tokenDescriptor);

        return tokenhandler.WriteToken(token);
    }
}
