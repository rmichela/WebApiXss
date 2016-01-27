namespace JsonXss.Models
{
    public class JsonPayload
    {
        public string NoMarkup { get; set; }

        [AllowHtml(AllowedTags = new[] { "h1" })]
        public string WithMarkup { get; set; }
    }

    public class JsonResponse : JsonPayload
    {
        public string UrlParam { get; set; }
    }
}