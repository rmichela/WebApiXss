using System.Web.Http;
using System.Web.Http.Validation;
using JsonXss.Filtering;
using JsonXss.Validation;

namespace JsonXss
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            var strategy = XssStrategy.HtmlSanitizer;
            bool block = false;

            if (block)
            {
                // Invalidate the ModelState if XSS is discovered in a string
                config.Services.Add(typeof (ModelValidatorProvider), new XssModelValidationProvider(strategy));
                // Return a 500 error if the ModelState is invalid
                config.Filters.Add(new ValidateModelAttribute());
            }
            else
            {
                XssFilteringMediaTypeFormatter.Configure(config, strategy);
            }

            // Web API routes
            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}"
            );
        }
    }
}
