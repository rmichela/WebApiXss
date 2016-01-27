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
        private readonly XssStrategy _strategy;

        public XssModelValidationProvider(XssStrategy strategy)
        {
            _strategy = strategy;
        }

        /// <summary>
        /// Returns additional PF specific model validators
        /// </summary>
        protected override IEnumerable<ModelValidator> GetValidators(ModelMetadata metadata, IEnumerable<ModelValidatorProvider> validatorProviders, IEnumerable<Attribute> attributes)
        {
            // Only apply XSS validation to strings
            if (metadata.Model is string)
            {
                switch (_strategy)
                {
                    case XssStrategy.AspNet:   
                        if (!attributes.Any(att => att is AllowHtmlAttribute)) yield return new AspNetXssModelValidator(validatorProviders);
                        break;
                    case XssStrategy.AntiXss:
                        if (!attributes.Any(att => att is AllowHtmlAttribute)) yield return new AntiXssModelValidator(validatorProviders);
                        break;
                    case XssStrategy.HtmlSanitizer:
                        yield return new HtmlSanitizerModelValidator(validatorProviders, attributes.OfType<AllowHtmlAttribute>().FirstOrDefault());
                        break;
                }
            }
        }
    }
}