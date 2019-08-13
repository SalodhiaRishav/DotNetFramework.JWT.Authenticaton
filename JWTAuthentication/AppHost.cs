namespace JWTAuthentication
{
   
    using Funq;
    using JWTAuthentication.Services;
    using ServiceStack;
    using ServiceStack.ServiceInterface.Cors;
    using ServiceStack.Text;
    using ServiceStack.WebHost.Endpoints;

    public class AppHost : AppHostBase
    {
        public AppHost() : base("JWTAuthentication", typeof(LoginService).Assembly) { }
        public override void Configure(Container container)
        {

            JsConfig.EmitCamelCaseNames = true;
            Plugins.Add(new CorsFeature());
            RequestFilters.Add((httpReq, httpRes, requestDto) =>
            {
                if (httpReq.HttpMethod == "OPTIONS")
                {
                    httpRes.AddHeader("Access-Control-Allow-Methods", "POST, GET,DELETE, OPTIONS");
                    httpRes.AddHeader("Access-Control-Allow-Headers", "X-Requested-With, Content-Type, Accept, X-ApiKey");
                    httpRes.EndRequest();
                }
            });
        }


    }
}