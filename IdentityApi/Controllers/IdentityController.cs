﻿using JetBrains.Annotations;
using Microsoft.AspNetCore.Mvc;

namespace IdentityApi.Controllers
{
    /// <summary>
    /// 
    /// </summary>
    [PublicAPI]
    public sealed class IdentityController : Controller
    {
        /// <summary>
        /// 
        /// </summary>
        /// <returns>
        /// 
        /// </returns>
        [NotNull]
        [HttpGet]
        public IActionResult Index()
        {
            return View();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns>
        /// 
        /// </returns>
        [HttpGet]
        [NotNull]
        public IActionResult Authenticate()
        {
            return View();
        }
    }
}