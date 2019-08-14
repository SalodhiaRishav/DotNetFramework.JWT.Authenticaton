using JWTAuthentication.Services.Filters;
using ServiceStack.ServiceHost;


namespace JWTAuthentication.Endpoints
{

    [Route("/adminname","GET")]
    [AdminAuthenticationFilter]
    public class GetAdminName
    {
        
    }
}