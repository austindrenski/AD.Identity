using System.ComponentModel.DataAnnotations;
using JetBrains.Annotations;

namespace IdentityApi.Models
{
    /// <summary>
    /// 
    /// </summary>
    [PublicAPI]
    public class ResetPasswordViewModel
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
        public string Code { get; set; }

        /// <summary>
        ///
        /// </summary>
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}