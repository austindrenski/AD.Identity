using System;
using AD.Identity.Extensions;
using AD.Identity.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Identity;

namespace AD.Identity
{
    /// <summary>
    /// 
    /// </summary>
    [PublicAPI]
    public sealed class IdentityContext : IdentityDbContext<User, Role, Guid>
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

        /// <inheritdoc />
        protected override void OnModelCreating([NotNull] ModelBuilder builder)
        {
            if (builder is null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            base.OnModelCreating(builder);

            builder.HasDefaultSchema("identity");

            builder.Entity<User>().ToTable("users");
            builder.Entity<Role>().ToTable("roles");
            
            builder.Entity<IdentityRoleClaim<Guid>>().ToTable("role_claims");
            builder.Entity<IdentityUserClaim<Guid>>().ToTable("user_claims");
            builder.Entity<IdentityUserLogin<Guid>>().ToTable("user_logins");
            builder.Entity<IdentityUserRole<Guid>>().ToTable("user_roles");
            builder.Entity<IdentityUserToken<Guid>>().ToTable("user_tokens");

            builder.UseSnakeCase();
        }
    }
}