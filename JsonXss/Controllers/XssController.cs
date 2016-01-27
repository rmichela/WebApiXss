using System.Web.Http;
using JsonXss.Models;

namespace JsonXss.Controllers
{
    public class XssController : ApiController
    {
        [HttpPost]
        public JsonResponse Post([FromBody] JsonPayload payload, [FromUri] string q)
        {
            if (payload == null)
                return new JsonResponse();

            return new JsonResponse
            {
                NoMarkup = payload.NoMarkup,
                WithMarkup = payload.WithMarkup,
                UrlParam = q
            };
        }
    }
}