namespace JWTAuthentication.Services
{
    using JWTAuthentication.Endpoints;
    using ServiceStack.ServiceInterface;
    using System;
    using BAL;
    using System.Collections.Generic;
   
    public class LoginResult
    {
        public string AccessToken { get; set; }
        public string RefreshTokenSerialNumber { get; set; }
    }
    public class LoginService : Service
    {
        private readonly UserAuthenticationBusinessLogic userAuthenticationBusinessLogic;
        public LoginService()
        {
            userAuthenticationBusinessLogic = new UserAuthenticationBusinessLogic();
        }

        public LoginResult Post(LoginUser request)
        {
           var result= userAuthenticationBusinessLogic.Login(request.Email, request.Password);
            LoginResult loginResult = new LoginResult();
            loginResult.AccessToken = result.AccessToken;
            loginResult.RefreshTokenSerialNumber = result.RefreshToken;
            return loginResult;
        }
    }
}