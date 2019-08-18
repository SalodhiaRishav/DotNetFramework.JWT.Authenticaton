using ServiceStack.ServiceHost;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace JWTAuthentication.Endpoints
{
    [Route("/refreshtoken", "POST")]
    public class RefreshAccessToken
    {
        public string RefreshTokenSerialId { get; set; }
    }
}