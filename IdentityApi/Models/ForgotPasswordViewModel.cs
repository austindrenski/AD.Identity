using System.ComponentModel.DataAnnotations;
using JetBrains.Annotations;

namespace IdentityApi.Models
{
    /// <summary>
    /// 
    /// </summary>
    [PublicAPI]
    public class ForgotPasswordViewModel
    {
        /// <summary>
        /// 
        /// </summary>
        [Required]
        public string ReturnUrl { get; set; }
        
        /// <summary>
        /// 
        /// </summary>
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}