using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Shared.Models;
using DAL.Context;

namespace BAL
{
    public class RoleBusinessLogic
    {
        private readonly AuthenticationDbContext dbContext;

        public RoleBusinessLogic()
        {
            dbContext = new AuthenticationDbContext();
        }
        public List<Role> GetUserRoles(int userId)
        {
            List<Role> roles = new List<Role>();
            List<UserRole> userRoles = dbContext.UserRoles.Where(ur => ur.UserId == userId).ToList();
            if(userRoles.Count!=0)
            {
                foreach(UserRole userRole in userRoles)
                {
                    var role=dbContext.Roles.Find(userRole.RoleId);
                    if(role!=null)
                    {
                        roles.Add(role);
                    }
                }
            }
            return roles;
        }


    }
}
