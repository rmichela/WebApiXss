using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Formatting;
using System.Net.Http.Headers;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Validation;
using CsQuery;
using Ganss.XSS;
using Microsoft.Security.Application;

namespace JsonXss.Filtering
{
    /// <summary>
    /// Filters suspected XSS out of request fields
    /// </summary>
    public class XssFilteringMediaTypeFormatter : MediaTypeFormatter
    {
        private readonly MediaTypeFormatter _innerFormatter;
        private readonly XssStrategy _strategy;

        public XssFilteringMediaTypeFormatter(MediaTypeFormatter innerFormatter, XssStrategy strategy) : base(innerFormatter)
        {
            _innerFormatter = innerFormatter;
            _strategy = strategy;
        }

        public static void Configure(HttpConfiguration config, XssStrategy strategy)
        {
            var wrappedFormatters = config.Formatters.Select(fmt => new XssFilteringMediaTypeFormatter(fmt, strategy)).ToList();
            config.Formatters.Clear();
            config.Formatters.AddRange(wrappedFormatters);
        }

        public override Task<object> ReadFromStreamAsync(Type type, Stream readStream, HttpContent content, IFormatterLogger formatterLogger)
        {
            return _innerFormatter.ReadFromStreamAsync(type, readStream, content, formatterLogger)
                .ContinueWith(antecedent =>
                {
                    var o = antecedent.Result;
                    FilterObject(o);
                    return o;
                });
        }

        public override Task<object> ReadFromStreamAsync(Type type, Stream readStream, HttpContent content, IFormatterLogger formatterLogger, CancellationToken cancellationToken)
        {
            return _innerFormatter.ReadFromStreamAsync(type, readStream, content, formatterLogger, cancellationToken)
                .ContinueWith(antecedent =>
                {
                    var o = antecedent.Result;
                    FilterObject(o);
                    return o;
                }, cancellationToken);
        }

        private void FilterObject(object obj)
        {
            if (IsIgnoredType(obj.GetType()))
            {
                return;
            }

            IEnumerable<PropertyInfo> properties = obj.GetType().GetProperties().Where(p => p.CanRead && !p.GetGetMethod().IsStatic);
            IEnumerable<FieldInfo> fields = obj.GetType().GetFields().Where(f => !f.IsStatic);

            foreach (var property in properties)
            {
                object value = property.GetValue(obj);
                if (property.PropertyType == typeof(string) && property.CanWrite)
                {
                    var attribute = property.GetCustomAttribute<AllowHtmlAttribute>();
                    string newValue = Sanitize((string) value, attribute, _strategy);
                    property.SetValue(obj, newValue);
                }
                else
                {
                    FilterObject(value);
                }
            }
            foreach (var field in fields)
            {
                object value = field.GetValue(obj);
                if (field.FieldType == typeof (string))
                {
                    var attribute = field.GetCustomAttribute<AllowHtmlAttribute>();
                    string newValue = Sanitize((string) value, attribute, _strategy);
                    field.SetValue(obj, newValue);
                }
                else
                {
                    FilterObject(value);
                }
            }
        }

        private static bool IsIgnoredType(Type propertyType)
        {
            if (propertyType.IsPrimitive)
            {
                return true;
            }
            if (propertyType.IsGenericType)
            {
                if (propertyType.GetGenericArguments().All(IsIgnoredType))
                {
                    return true;
                }
            }
            else
            {
                if (propertyType.Namespace != null && propertyType.Namespace.StartsWith("System"))
                {
                    return true;
                }
                if (propertyType.Namespace != null && propertyType.Namespace.StartsWith("Microsoft"))
                {
                    return true;
                }
            }
            return false;
        }

        private string Sanitize(string dirty, AllowHtmlAttribute attribute, XssStrategy strategy)
        {
            switch (strategy)
            {
                case XssStrategy.AspNet:
                    throw new NotImplementedException();
                case XssStrategy.HtmlSanitizer:
                    return SanitizeHtmlSanitizer(dirty, attribute);
                case XssStrategy.AntiXss:
                    return SanitizeAntiXss(dirty, attribute);
                default:
                    throw new NotImplementedException();
            }
        }

        private string SanitizeHtmlSanitizer(string dirty, AllowHtmlAttribute attribute)
        {
            var sanitizer = new HtmlSanitizer(
                allowedTags: attribute != null ? attribute.AllowedTags : new string[0],
                allowedSchemes: new string[0],
                allowedAttributes: new string[0],
                uriAttributes: new string[0],
                allowedCssProperties: new string[0]);
            return sanitizer.Sanitize(dirty, outputFormatter: OutputFormatters.HtmlEncodingNone);
        }

        private string SanitizeAntiXss(string dirty, AllowHtmlAttribute attribute)
        {
            if (attribute != null) return dirty;

            var sanitized = Sanitizer.GetSafeHtmlFragment(dirty);
            if (!dirty.Equals(sanitized))
            {
                // Revert HTML encoded special characters
                sanitized = sanitized.Replace("&lt;", "<");
                sanitized = sanitized.Replace("&gt;", ">");
                sanitized = sanitized.Replace("&amp;", "&");
                sanitized = sanitized.Replace("&quot;", "\"");   
            }
            return sanitized;
        }

        #region Delegate to innerFormatter
        public override Task WriteToStreamAsync(Type type, object value, Stream writeStream, HttpContent content,
            TransportContext transportContext)
        {
            return _innerFormatter.WriteToStreamAsync(type, value, writeStream, content, transportContext);
        }

        public override Task WriteToStreamAsync(Type type, object value, Stream writeStream, HttpContent content, TransportContext transportContext, CancellationToken cancellationToken)
        {
            return _innerFormatter.WriteToStreamAsync(type, value, writeStream, content, transportContext, cancellationToken);
        }

        public override void SetDefaultContentHeaders(Type type, HttpContentHeaders headers, MediaTypeHeaderValue mediaType)
        {
            _innerFormatter.SetDefaultContentHeaders(type, headers, mediaType);
        }

        public override MediaTypeFormatter GetPerRequestFormatterInstance(Type type, HttpRequestMessage request, MediaTypeHeaderValue mediaType)
        {
            return _innerFormatter.GetPerRequestFormatterInstance(type, request, mediaType);
        }

        public override bool CanReadType(Type type)
        {
            return _innerFormatter.CanReadType(type);
        }

        public override bool CanWriteType(Type type)
        {
            return _innerFormatter.CanWriteType(type);
        }

        public override IRequiredMemberSelector RequiredMemberSelector
        {
            get { return _innerFormatter.RequiredMemberSelector; }
            set { _innerFormatter.RequiredMemberSelector = value; }
        }
#endregion
    }
}