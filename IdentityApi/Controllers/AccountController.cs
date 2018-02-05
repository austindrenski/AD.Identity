using System;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using AD.Identity.Models;
using IdentityApi.Models;
using IdentityApi.Services;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace IdentityApi.Controllers
{
    /// <summary>
    /// 
    /// </summary>
    [Authorize]
    public sealed class AccountController : Controller
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly IEmailSender _emailSender;
        private readonly ILogger _logger;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="userManager">
        /// 
        /// </param>
        /// <param name="signInManager">
        /// 
        /// </param>
        /// <param name="emailSender">
        /// 
        /// </param>
        /// <param name="logger">
        /// 
        /// </param>
        public AccountController(
            [NotNull] UserManager<User> userManager,
            [NotNull] SignInManager<User> signInManager,
            [NotNull] IEmailSender emailSender,
            [NotNull] ILogger<AccountController> logger)
        {
            if (userManager is null)
            {
                throw new ArgumentNullException(nameof(userManager));
            }

            if (signInManager is null)
            {
                throw new ArgumentNullException(nameof(signInManager));
            }

            if (emailSender is null)
            {
                throw new ArgumentNullException(nameof(emailSender));
            }

            if (logger is null)
            {
                throw new ArgumentNullException(nameof(logger));
            }

            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
            _logger = logger;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="returnUrl">
        /// 
        /// </param>
        /// <returns>
        /// 
        /// </returns>
        [NotNull]
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Login([NotNull] [FromQuery]string returnUrl)
        {
            if (returnUrl is null)
            {
                throw new ArgumentNullException(nameof(returnUrl));
            }

            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            ViewData["return-url"] = returnUrl;

            return View();
        }

        /// <summary>
        /// </summary>
        /// <param name="model">
        /// </param>
        /// <param name="returnUrl">
        ///
        /// </param>
        /// <returns>
        /// 
        /// </returns>
        /// <exception cref="ArgumentNullException" />
        [NotNull]
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login([NotNull] LoginViewModel model, [NotNull] string returnUrl)
        {
            if (model is null)
            {
                throw new ArgumentNullException(nameof(model));
            }

            if (returnUrl is null)
            {
                throw new ArgumentNullException(nameof(returnUrl));
            }

            ViewData["return-url"] = returnUrl;

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            SignInResult result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberLogin, true);

            if (result.Succeeded)
            {
                _logger.LogInformation("User logged in.");
                return Redirect(returnUrl);
            }

            if (result.IsLockedOut)
            {
                _logger.LogWarning("User locked out.");
                return RedirectToAction(nameof(Lockout));
            }

            if (result.IsNotAllowed)
            {
                _logger.LogWarning("User not allowed.");
                return RedirectToAction(nameof(Lockout));
            }

            ModelState.AddModelError(string.Empty, "Invalid login attempt.");

            return View(model);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        [NotNull]
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Lockout()
        {
            return View();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="returnUrl">
        /// 
        /// </param>
        /// <returns>
        /// 
        /// </returns>
        /// <exception cref="ArgumentNullException" />
        [NotNull]
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register([NotNull] string returnUrl)
        {
            if (returnUrl is null)
            {
                throw new ArgumentNullException(nameof(returnUrl));
            }

            ViewData["return-url"] = returnUrl;

            return View();
        }

        /// <summary>
        /// </summary>
        /// <param name="model">
        /// </param>
        /// <param name="returnUrl">
        ///
        /// </param>
        /// <returns>
        /// 
        /// </returns>
        /// <exception cref="ArgumentNullException" />
        [NotNull]
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register([NotNull] RegisterViewModel model, [NotNull] string returnUrl)
        {
            if (model is null)
            {
                throw new ArgumentNullException(nameof(model));
            }

            if (returnUrl is null)
            {
                throw new ArgumentNullException(nameof(returnUrl));
            }

            ViewData["return-url"] = returnUrl;

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            User user =
                new User
                {
                    UserName = model.Email,
                    Email = model.Email,
                };

            IdentityResult result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                foreach (IdentityError error in result.Errors)
                {
                    ModelState.AddModelError(error.Code, error.Description);
                }

                return View(model);
            }

            _logger.LogInformation("User created a new account with password.");

            string code = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            string callbackUrl = Url.Action(nameof(ConfirmEmail), "Account", new { user.Id, code }, Request.Scheme);

            await _emailSender.SendEmailAsync(
                model.Email,
                "Confirm account email",
                $"<a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>Click to confirm the account.</a>");

            await _signInManager.SignInAsync(user, false);

            return Redirect(returnUrl);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns>
        /// 
        /// </returns>
        [NotNull]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();

            _logger.LogInformation("User logged out.");

            return RedirectToAction(nameof(IdentityController.Index), "Identity");
        }

//        [HttpPost]
//        [AllowAnonymous]
//        [ValidateAntiForgeryToken]
//        public IActionResult ExternalLogin(string provider, string returnUrl = null)
//        {
//            // Request a redirect to the external login provider.
//            var redirectUrl = Url.Action(nameof(ExternalLoginCallback), "Account", new { returnUrl });
//            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
//            return Challenge(properties, provider);
//        }
//
//        [HttpGet]
//        [AllowAnonymous]
//        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
//        {
//            if (remoteError != null)
//            {
//                ErrorMessage = $"Error from external provider: {remoteError}";
//                return RedirectToAction(nameof(Login));
//            }
//
//            var info = await _signInManager.GetExternalLoginInfoAsync();
//            if (info == null)
//            {
//                return RedirectToAction(nameof(Login));
//            }
//
//            // Sign in the user with this external login provider if the user already has a login.
//            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
//            if (result.Succeeded)
//            {
//                _logger.LogInformation("User logged in with {Name} provider.", info.LoginProvider);
//                return RedirectToLocal(returnUrl);
//            }
//
//            if (result.IsLockedOut)
//            {
//                return RedirectToAction(nameof(Lockout));
//            }
//            else
//            {
//                // If the user does not have an account, then ask the user to create an account.
//                ViewData["ReturnUrl"] = returnUrl;
//                ViewData["LoginProvider"] = info.LoginProvider;
//                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
//                return View("ExternalLogin", new ExternalLoginViewModel { Email = email });
//            }
//        }
//
//        [HttpPost]
//        [AllowAnonymous]
//        [ValidateAntiForgeryToken]
//        public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginViewModel model, string returnUrl = null)
//        {
//            if (ModelState.IsValid)
//            {
//                // Get the information about the user from the external login provider
//                var info = await _signInManager.GetExternalLoginInfoAsync();
//                if (info == null)
//                {
//                    throw new ApplicationException("Error loading external login information during confirmation.");
//                }
//
//                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
//                var result = await _userManager.CreateAsync(user);
//                if (result.Succeeded)
//                {
//                    result = await _userManager.AddLoginAsync(user, info);
//                    if (result.Succeeded)
//                    {
//                        await _signInManager.SignInAsync(user, isPersistent: false);
//                        _logger.LogInformation("User created an account using {Name} provider.", info.LoginProvider);
//                        return RedirectToLocal(returnUrl);
//                    }
//                }
//
//                AddErrors(result);
//            }
//
//            ViewData["ReturnUrl"] = returnUrl;
//            return View(nameof(ExternalLogin), model);
//        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="userId">
        /// 
        /// </param>
        /// <param name="code">
        /// 
        /// </param>
        /// <returns>
        /// 
        /// </returns>
        /// <exception cref="ApplicationException" />
        [NotNull]
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail([CanBeNull] string userId, [CanBeNull] string code)
        {
            if (userId is null || code is null)
            {
                return RedirectToAction(nameof(IdentityController.Index), "Identity");
            }

            User user = await _userManager.FindByIdAsync(userId);

            if (user is null)
            {
                throw new ArgumentException();
            }

            IdentityResult result = await _userManager.ConfirmEmailAsync(user, code);

            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns>
        /// 
        /// </returns>
        [NotNull]
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="model">
        /// 
        /// </param>
        /// <returns>
        /// 
        /// </returns>
        [NotNull]
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            User user = await _userManager.FindByEmailAsync(model.Email);

            if (user is null || !await _userManager.IsEmailConfirmedAsync(user))
            {
                return RedirectToAction(nameof(ForgotPasswordConfirmation));
            }

            string code = await _userManager.GeneratePasswordResetTokenAsync(user);

            string callbackUrl = Url.Action(nameof(ResetPassword), "Account", new { user.Id, code }, Request.Scheme);

            await _emailSender.SendEmailAsync(
                model.Email,
                "Reset Password",
                $"Please reset your password by clicking here: <a href='{callbackUrl}'>link</a>");

            return RedirectToAction(nameof(ForgotPasswordConfirmation));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns>
        /// 
        /// </returns>
        [NotNull]
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="code">
        ///
        /// </param>
        /// <returns>
        ///
        /// </returns>
        /// <exception cref="ArgumentNullException" />
        [NotNull]
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword([NotNull] string code)
        {
            if (code is null)
            {
                throw new ArgumentNullException("A code must be supplied for password reset.");
            }

            ResetPasswordViewModel model =
                new ResetPasswordViewModel
                {
                    Code = code
                };

            return View(model);
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="model">
        ///
        /// </param>
        /// <returns>
        ///
        /// </returns>
        /// <exception cref="ArgumentNullException" />
        [NotNull]
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (model is null)
            {
                throw new ArgumentNullException(nameof(model));
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            User user = await _userManager.FindByEmailAsync(model.Email);

            if (user is null)
            {
                return RedirectToAction(nameof(ResetPasswordConfirmation));
            }

            IdentityResult result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);

            if (result.Succeeded)
            {
                return RedirectToAction(nameof(ResetPasswordConfirmation));
            }

            foreach (IdentityError error in result.Errors)
            {
                ModelState.AddModelError(error.Code, error.Description);
            }

            return View();
        }

        /// <summary>
        ///
        /// </summary>
        /// <returns>
        ///
        /// </returns>
        [NotNull]
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns>
        /// 
        /// </returns>
        [NotNull]
        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}