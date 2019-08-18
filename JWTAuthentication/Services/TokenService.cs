using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using ServiceStack.ServiceInterface;
using JWTAuthentication.Endpoints;
using BAL;

namespace JWTAuthentication.Services
{
    public class RefreshTokenResult
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
    }
    public class TokenService : Service
    {
        private readonly TokenBusinessLogic tokenBusinessLogic;

        public TokenService()
        {
            tokenBusinessLogic = new TokenBusinessLogic();
        }
        public string Post(RefreshAccessToken request)
        {
            string refreshTokenSerial = request.RefreshTokenSerialId;
            if (String.IsNullOrEmpty(refreshTokenSerial))
            {
               return "Invalid Token,please login again";
            }

            var refreshTokenResult = tokenBusinessLogic.RefreshToken(refreshTokenSerial);
            if(refreshTokenResult == null)
            {
                return null;
            }

           
            

            return refreshTokenResult;
        }
    }
}