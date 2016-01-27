using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Http.Metadata;
using System.Web.Http.Validation;
using Microsoft.Security.Application;

namespace JsonXss.Validation
{
    public class AntiXssModelValidator : ModelValidator
    {
        public AntiXssModelValidator(IEnumerable<ModelValidatorProvider> validatorProviders) : base(validatorProviders)
        {
        }

        public override IEnumerable<ModelValidationResult> Validate(ModelMetadata metadata, object container)
        {
            if (metadata.Model is string)
            {
                var dirty = (string) metadata.Model;
                var sanitized = Sanitizer.GetSafeHtmlFragment(dirty);
                if (!dirty.Equals(sanitized))
                {
                    // Revert HTML encoded special characters
                    sanitized = sanitized.Replace("&lt;", "<");
                    sanitized = sanitized.Replace("&gt;", ">");
                    sanitized = sanitized.Replace("&amp;", "&");
                    sanitized = sanitized.Replace("&quot;", "\"");

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
}