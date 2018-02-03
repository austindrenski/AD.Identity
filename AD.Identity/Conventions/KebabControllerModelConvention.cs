using System;
using AD.Identity.Extensions;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Mvc.ApplicationModels;

namespace AD.Identity.Conventions
{
    // TODO: document KebabControllerModelConventions.
    /// <inheritdoc />
    /// <summary>
    /// 
    /// </summary>
    [PublicAPI]
    public class KebabControllerModelConvention : IControllerModelConvention
    {
        /// <inheritdoc />
        public void Apply([NotNull] ControllerModel controller)
        {
            if (controller is null)
            {
                throw new ArgumentNullException(nameof(controller));
            }

            if (controller.ControllerName == "Home")
            {
                return;
            }

            foreach (SelectorModel selector in controller.Selectors)
            {
                if (selector.AttributeRouteModel is default)
                {
                    selector.AttributeRouteModel = new AttributeRouteModel();
                }
                selector.AttributeRouteModel.Template = controller.ControllerName.CamelCaseToKebabCase();
            }

            foreach (ActionModel action in controller.Actions)
            {
                foreach (SelectorModel selector in action.Selectors)
                {
                    if (selector.AttributeRouteModel is null)
                    {
                        selector.AttributeRouteModel = new AttributeRouteModel();
                    }
                    selector.AttributeRouteModel.Template = action.ActionName.CamelCaseToPathCase();
                }
            }
        }
    }
}