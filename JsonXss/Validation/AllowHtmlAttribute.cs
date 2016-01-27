using System;

/// <summary>
/// Disables XSS protection
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field)]
public sealed class AllowHtmlAttribute : Attribute
{
}