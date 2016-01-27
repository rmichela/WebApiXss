using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Http.Metadata;
using System.Web.Http.Validation;
using System.Web.Util;

namespace JsonXss.Validation
{
    public class AspNetXssModelValidator : ModelValidator
    {
        public AspNetXssModelValidator(IEnumerable<ModelValidatorProvider> validatorProviders)
            : base(validatorProviders)
        {

        }

        public override IEnumerable<ModelValidationResult> Validate(ModelMetadata metadata, object container)
        {
            if (metadata.Model is string)
            {
                return ValidateString((string)metadata.Model, metadata.PropertyName);
            }
            return Enumerable.Empty<ModelValidationResult>();
        }

        private IEnumerable<ModelValidationResult> ValidateString(string value, string collectionKey)
        {
            int validationFailureIndex;
            if (!RequestValidator.Current.InvokeIsValidRequestString(HttpContext.Current, value, RequestValidationSource.Form, collectionKey, out validationFailureIndex))
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