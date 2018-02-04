using System.ComponentModel.DataAnnotations;
using JetBrains.Annotations;

namespace IdentityApi.Models
{
    /// <summary>
    /// 
    /// </summary>
    [PublicAPI]
    public sealed class LoginViewModel
    {
        /// <summary>
        /// 
        /// </summary>
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        /// <summary>
        /// 
        /// </summary>
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        /// <summary>
        ///  
        /// </summary>
        [Display(Name = "Remember login?")]
        public bool RememberLogin { get; set; }
    }
}