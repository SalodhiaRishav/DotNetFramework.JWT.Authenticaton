﻿using Microsoft.IdentityModel.Tokens;
using Shared.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using DAL.Context;
using System.Security.Cryptography;
using System.Text;

namespace BAL
{
    public class JwtTokensData
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public string RefreshTokenSerial { get; set; }
        public IEnumerable<Claim> Claims { get; set; }
    }
    public class TokenBusinessLogic
    {
        private static string secret = "XCAP05H6LoKvbRRa/QkqLNMI7cOHguaRyHzyg7n5qEkGjQmtBhz4SzYh4Fqwjyi3KJHlSXKPwVu2+bXr6CtpgQ==";
        //private readonly string secret;
        private readonly RoleBusinessLogic roleBusinessLogic;
        private AuthenticationDbContext dbContext;
        public TokenBusinessLogic()
        {
            //secret = "This is my shared key, not so secret, secret!";
            roleBusinessLogic = new RoleBusinessLogic();
            dbContext = new AuthenticationDbContext();
        }

        public JwtTokensData CreateJwtTokens(User user)
        {
            var (accessToken, claims) = GenerateAccessToken(user);
            var (refreshTokenValue, refreshTokenSerial) = GenerateRefreshToken(user);
            return new JwtTokensData
            {
                AccessToken = accessToken,
                RefreshToken = refreshTokenValue,
                RefreshTokenSerial = refreshTokenSerial,
                Claims = claims
            };
        }

        private (string AccessToken, IEnumerable<Claim> Claims) GenerateAccessToken(User user)
        {
            byte[] key = Convert.FromBase64String(secret);
            SymmetricSecurityKey securityKey = new SymmetricSecurityKey(key);
            //var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            List<Claim> claims = new List<Claim>();

            claims.Add(new Claim(ClaimTypes.Email, user.Email));
            List<Role> roles = roleBusinessLogic.GetUserRoles(user.Id);
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role.RoleName, ClaimValueTypes.String));
            }
            SecurityTokenDescriptor descriptor = new SecurityTokenDescriptor
            {
                Issuer="rishav server",
                NotBefore=DateTime.UtcNow,
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(2),
                SigningCredentials = new SigningCredentials(securityKey,
                SecurityAlgorithms.HmacSha256Signature)
            };

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            JwtSecurityToken token = handler.CreateJwtSecurityToken(descriptor);
            var accessToken=handler.WriteToken(token);
            return (accessToken, claims);
        }

        public Guid CreateCryptographicallySecureGuid()
        {
            RandomNumberGenerator rand = RandomNumberGenerator.Create();
            var bytes = new byte[16];
            rand.GetBytes(bytes);
            return new Guid(bytes);
        }

        private (string RefreshTokenValue, string RefreshTokenSerial) GenerateRefreshToken(User user)
        {
            byte[] key = Convert.FromBase64String(secret);
            SymmetricSecurityKey securityKey = new SymmetricSecurityKey(key);
            //var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            var refreshTokenSerial = this.CreateCryptographicallySecureGuid().ToString().Replace("-", "");
            List<Claim> claims = new List<Claim>();
            claims.Add(new Claim(ClaimTypes.SerialNumber, refreshTokenSerial));

            SecurityTokenDescriptor descriptor = new SecurityTokenDescriptor
            {
                Issuer = "rishav server",
                NotBefore = DateTime.UtcNow,
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(60),
                SigningCredentials = new SigningCredentials(securityKey,
                SecurityAlgorithms.HmacSha256Signature)
            };

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            JwtSecurityToken token = handler.CreateJwtSecurityToken(descriptor);
            var refreshTokenValue =handler.WriteToken(token);
            return (refreshTokenValue, refreshTokenSerial);
        }

        public void AddNewToken(User user,string accessToken,string refreshTokenSerialNumber)
        {
            UserToken userToken = new UserToken();
            userToken.UserId = user.Id;
            userToken.AccessTokenHash = accessToken;
            userToken.RefreshTokenIdHash = refreshTokenSerialNumber;
            userToken.RefreshTokenIdHashSource = null;
            userToken.RefreshTokenExpiresDateTime = DateTimeOffset.UtcNow.AddMinutes(60);
            userToken.AccessTokenExpiresDateTime = DateTimeOffset.UtcNow.AddMinutes(8);
            dbContext.UserTokens.Add(userToken);
            dbContext.SaveChanges();
        }


        public ClaimsPrincipal GetPrincipal(string token)
        {
            try
            {
                JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
                JwtSecurityToken jwtToken = (JwtSecurityToken)tokenHandler.ReadToken(token);
                if (jwtToken == null)
                    return null;

                byte[] key = Convert.FromBase64String(secret);
                //var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
                //byte[] key = Convert.FromBase64String(secret);
                TokenValidationParameters parameters = new TokenValidationParameters()
                {
                    RequireExpirationTime = true,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key)
                };
                SecurityToken securityToken;
                ClaimsPrincipal principal = tokenHandler.ValidateToken(token,
                      parameters, out securityToken);
                return principal;
            }
            catch (Exception e)
            {
                throw e;
            }
        }
    }
}
