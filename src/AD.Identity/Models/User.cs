using System;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Identity;

namespace AD.Identity.Models
{
    /// <inheritdoc />
    /// <summary>
    /// Represents profile data for application users.
    /// </summary>
    [PublicAPI]
    public sealed class User : IdentityUser<Guid>
    {
        /// <inheritdoc />
        public override Guid Id { get; set; } = Guid.NewGuid();

        /// <inheritdoc />
        public override string UserName { get; set; }

        /// <inheritdoc />
        public override string NormalizedUserName { get; set; }

        /// <inheritdoc />
        public override string Email { get; set; }

        /// <inheritdoc />
        public override string NormalizedEmail { get; set; }

        /// <inheritdoc />
        public override bool EmailConfirmed { get; set; }

        /// <inheritdoc />
        public override string PasswordHash { get; set; }

        /// <inheritdoc />
        public override string SecurityStamp { get; set; }

        /// <inheritdoc />
        public override string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();

        /// <inheritdoc />
        public override string PhoneNumber { get; set; }

        /// <inheritdoc />
        public override bool PhoneNumberConfirmed { get; set; }

        /// <inheritdoc />
        public override bool TwoFactorEnabled { get; set; }

        /// <inheritdoc />
        public override DateTimeOffset? LockoutEnd { get; set; }

        /// <inheritdoc />
        public override bool LockoutEnabled { get; set; }

        /// <inheritdoc />
        public override int AccessFailedCount { get; set; }

        /// <inheritdoc />
        public override string ToString()
        {
            return UserName;
        }
    }
}