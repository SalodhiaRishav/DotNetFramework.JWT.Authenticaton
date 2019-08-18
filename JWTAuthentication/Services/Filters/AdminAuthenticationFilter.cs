using BAL;
using Microsoft.IdentityModel.Tokens;
using ServiceStack.ServiceHost;
using ServiceStack.ServiceInterface;
using System;
using System.Security.Claims;

namespace JWTAuthentication.Services.Filters
{
    public class AdminAuthenticationFilter : RequestFilterAttribute
    {

        private readonly TokenBusinessLogic tokenBusinessLogic;

        public AdminAuthenticationFilter()
        {
            tokenBusinessLogic = new TokenBusinessLogic();
        }
        public override void Execute(IHttpRequest req, IHttpResponse res, object requestDto)
        {
            string bearerToken = req.Headers.Get("Authorization");
            
            if (String.IsNullOrEmpty(bearerToken))
            {
                res.ReturnAuthRequired("You are not authorized");
                res.Close();
                return;
            }

            var token= bearerToken.Split(' ')[1];
            bool isAdmin=ValidateTokenForAdmin(token);
            if(!isAdmin)
            {
                res.ReturnAuthRequired("You are not authorized");
                res.Close();
                return;
            }
            res.AddHeader("Bearer", "new token");
            res.Write("your new token");
            
        }

        private bool ValidateTokenForAdmin(string token)
        {
            
            try
            {
                ClaimsPrincipal principal = tokenBusinessLogic.GetPrincipal(token);
                if (principal == null)
                    return false;
                ClaimsIdentity identity = null;
                identity = (ClaimsIdentity)principal.Identity;
                if(identity ==  null)
                {
                    return false;
                }
                var roles = identity.FindAll(ClaimTypes.Role);
                bool isAdmin = false;
                foreach (var role in roles)
                {
                    if (role.Value == "Admin")
                    {
                        isAdmin = true;
                        break;
                    }
                }
                return isAdmin;
            }
            catch(SecurityTokenExpiredException)
            {
                //TODO handle
                return false;
            }
            catch (Exception)
            {
                return false;
            }
            
        }
    }
}