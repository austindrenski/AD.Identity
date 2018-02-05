using System;
using AD.Identity.Extensions;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Mvc.ModelBinding.Metadata;

namespace AD.Identity.Conventions
{
    /// <inheritdoc cref="IBindingMetadataProvider" />
    /// <inheritdoc cref="IDisplayMetadataProvider" />
    [PublicAPI]
    public class KebabBindingMetadataProvider : IBindingMetadataProvider, IDisplayMetadataProvider
    {
        /// <inheritdoc />
        public void CreateBindingMetadata([NotNull] BindingMetadataProviderContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.BindingMetadata.BinderModelName is null)
            {
                context.BindingMetadata.BinderModelName = context.Key.Name?.CamelCaseToKebabCase();
            }
        }

        /// <inheritdoc />
        public void CreateDisplayMetadata([NotNull] DisplayMetadataProviderContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.DisplayMetadata.DisplayName is null)
            {
                context.DisplayMetadata.DisplayName = () => context.Key.Name?.CamelCaseToKebabCase();
            }
        }
    }
}