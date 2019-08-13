using JWTAuthentication.Endpoints;
using ServiceStack.ServiceInterface;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace JWTAuthentication.Services
{
    public class AdminService : Service
    {
        public string Get(GetAdminName request)
        {
            return "this is from secured admin api. you can't see this without login as admin";
        }
    }
}