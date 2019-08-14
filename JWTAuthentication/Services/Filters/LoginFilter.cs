using ServiceStack.ServiceHost;
using ServiceStack.ServiceInterface;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace JWTAuthentication.Services.Filters
{
    public class LoginFilter : RequestFilterAttribute
    {
        public override void Execute(IHttpRequest req, IHttpResponse res, object requestDto)
        {
            throw new NotImplementedException();
        }
    }
}