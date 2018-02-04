using JetBrains.Annotations;
using Microsoft.AspNetCore.Identity;

namespace AD.Identity.Models
{
    /// <summary>
    /// Represents profile data for application users. 
    /// </summary>
    [PublicAPI]
    public sealed class ApplicationUser : IdentityUser { }
}