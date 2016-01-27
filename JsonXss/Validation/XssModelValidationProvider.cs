using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Http.Metadata;
using System.Web.Http.Validation;
using System.Web.Http.Validation.Providers;

namespace JsonXss.Validation
{
    public class XssModelValidationProvider : AssociatedValidatorProvider
    {
        private readonly XssModelValidationStrategy _strategy;

        public XssModelValidationProvider(XssModelValidationStrategy strategy)
        {
            _strategy = strategy;
        }

        /// <summary>
        /// Returns additional PF specific model validators
        /// </summary>
        protected override IEnumerable<ModelValidator> GetValidators(ModelMetadata metadata, IEnumerable<ModelValidatorProvider> validatorProviders, IEnumerable<Attribute> attributes)
        {
            // Only apply XSS validation to strings
            if (metadata.Model is string && !attributes.Any(att => att is AllowHtmlAttribute))
            {
                switch (_strategy)
                {
                    case XssModelValidationStrategy.AspNet:                       
                        yield return new AspNetXssModelValidator(validatorProviders);
                        break;
                    case XssModelValidationStrategy.AntiXss:
                        yield return new AntiXssModelValidator(validatorProviders);
                        break;
                    case XssModelValidationStrategy.HtmlSanitizer:
                        yield return new HtmlSanitizerModelValidator(validatorProviders);
                        break;
                }
            }
        }
    }
}