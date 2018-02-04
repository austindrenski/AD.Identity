using System;
using AD.Identity.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using JetBrains.Annotations;

namespace AD.Identity
{
    /// <summary>
    /// 
    /// </summary>
    [PublicAPI]
    public sealed class IdentityContext : IdentityDbContext<ApplicationUser>
    {
        /// <summary>
        ///
        /// </summary>
        /// <param name="options">
        /// 
        /// </param>
        /// <exception cref="ArgumentNullException" />
        public IdentityContext([NotNull] DbContextOptions<IdentityContext> options) : base(options)
        {
            if (options is null)
            {
                throw new ArgumentNullException(nameof(options));
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="builder">
        /// 
        /// </param>
        /// <exception cref="ArgumentNullException" />
        protected override void OnModelCreating([NotNull] ModelBuilder builder)
        {
            if (builder is null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            base.OnModelCreating(builder);
        }
    }
}