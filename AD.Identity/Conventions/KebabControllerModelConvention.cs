﻿using System;
using System.Text.RegularExpressions;
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
    public sealed class KebabControllerModelConvention : IControllerModelConvention
    {
        /// <summary>
        /// 
        /// </summary>
        [NotNull] private static readonly string Index = "Index";

        /// <summary>
        /// 
        /// </summary>
        [NotNull] private static readonly Regex HomeRegex = new Regex("Api\\b");

        /// <summary>
        /// 
        /// </summary>
        [NotNull] private readonly string _home;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="home">
        /// 
        /// </param>
        /// <exception cref="ArgumentNullException" />
        public KebabControllerModelConvention([NotNull] string home)
        {
            if (home is null)
            {
                throw new ArgumentNullException(nameof(home));
            }

            _home = HomeRegex.Replace(home, string.Empty);
        }

        /// <inheritdoc />
        public void Apply([NotNull] ControllerModel controller)
        {
            if (controller is null)
            {
                throw new ArgumentNullException(nameof(controller));
            }

            foreach (SelectorModel selector in controller.Selectors)
            {
                if (selector.AttributeRouteModel is default)
                {
                    selector.AttributeRouteModel = new AttributeRouteModel();
                }

                selector.AttributeRouteModel.Template =
                    controller.ControllerName.Equals(_home, StringComparison.OrdinalIgnoreCase)
                        ? string.Empty
                        : controller.ControllerName.CamelCaseToKebabCase();
            }

            foreach (ActionModel action in controller.Actions)
            {
                foreach (SelectorModel selector in action.Selectors)
                {
                    if (selector.AttributeRouteModel is null)
                    {
                        selector.AttributeRouteModel = new AttributeRouteModel();
                    }

                    selector.AttributeRouteModel.Template =
                        action.ActionName.Equals(Index, StringComparison.OrdinalIgnoreCase)
                            ? string.Empty
                            : action.ActionName.CamelCaseToPathCase();
                }
            }
        }
    }
}