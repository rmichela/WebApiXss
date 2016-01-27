using System.Collections.Generic;
using System.Web.Http.Metadata;
using System.Web.Http.Validation;
using CsQuery;
using Ganss.XSS;

namespace JsonXss.Validation
{
    public class HtmlSanitizerModelValidator : ModelValidator
    {
        public HtmlSanitizerModelValidator(IEnumerable<ModelValidatorProvider> validatorProviders) : base(validatorProviders)
        {
        }

        public override IEnumerable<ModelValidationResult> Validate(ModelMetadata metadata, object container)
        {
            if (metadata.Model is string)
            {
                var sanitizer = new HtmlSanitizer();

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