using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Shared.Models;
using DAL.Context;

namespace BAL
{
    public class UserAuthenticationBusinessLogic
    {
        private readonly AuthenticationDbContext dbContext;
        private readonly TokenBusinessLogic tokenBusinessLogic;
        public UserAuthenticationBusinessLogic()
        {
            dbContext = new AuthenticationDbContext();
            tokenBusinessLogic = new TokenBusinessLogic();
        }
        public (string AccessToken,string RefreshToken) Login(string email,string password)
        {
            List<User> userList = dbContext.Users.Where(u => u.Email == email && u.Password == password).ToList();

            if(userList.Count == 0)
            {
                return (null,null);
            }
            User user = userList.First();
            JwtTokensData jwtTokensData = tokenBusinessLogic.CreateJwtTokens(user);
            tokenBusinessLogic.AddNewToken(user, jwtTokensData.AccessToken, jwtTokensData.RefreshTokenSerial);
            return (jwtTokensData.AccessToken,jwtTokensData.RefreshTokenSerial);
        }
    }
}
