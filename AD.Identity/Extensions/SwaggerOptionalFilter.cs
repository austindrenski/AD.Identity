using JetBrains.Annotations;
using Swashbuckle.AspNetCore.Swagger;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace AD.Identity.Extensions
{
    /// <inheritdoc />
    [PublicAPI]
    public class SwaggerOptionalFilter : IOperationFilter
    {
        /// <inheritdoc />
        public void Apply([NotNull] Operation operation, [NotNull] OperationFilterContext context)
        {
            if (operation.Parameters is default)
            {
                return;
            }

            foreach (IParameter parameter in operation.Parameters)
            {
                parameter.Required = false;
            }
        }
    }
}