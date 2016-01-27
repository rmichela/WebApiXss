using System.Collections.Generic;
using System.Web.Http.Metadata;
using System.Web.Http.Validation;
using CsQuery;
using Ganss.XSS;

namespace JsonXss.Validation
{
    public class HtmlSanitizerModelValidator : ModelValidator
    {
        private readonly AllowHtmlAttribute _attribute;

        public HtmlSanitizerModelValidator(IEnumerable<ModelValidatorProvider> validatorProviders, AllowHtmlAttribute attribute) : base(validatorProviders)
        {
            _attribute = attribute;
        }

        public override IEnumerable<ModelValidationResult> Validate(ModelMetadata metadata, object container)
        {
            if (metadata.Model is string)
            {
                var sanitizer = new HtmlSanitizer(
                    allowedTags: _attribute != null ? _attribute.AllowedTags : new string[0],
                    allowedSchemes: new string[0],
                    allowedAttributes: new string[0],
                    uriAttributes: new string[0],
                    allowedCssProperties: new string[0]);

                var dirty = (string) metadata.Model;
                var sanitized = sanitizer.Sanitize(dirty, outputFormatter: OutputFormatters.HtmlEncodingNone);

                if (!dirty.Equals(sanitized))
                {
                    yield return new ModelValidationResult
                    {
                        MemberName = string.Empty,
                        Message = "A potentially dangerous value was detected from the client."
                    };
                }
            }
        }
    }
}