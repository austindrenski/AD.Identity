using System;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Identity;

namespace AD.Identity.Models
{
    [PublicAPI]
    public sealed class Role : IdentityRole<Guid>
    {
        /// <inheritdoc />
        public override Guid Id { get; set; } = Guid.NewGuid();

        /// <inheritdoc />
        public override string Name { get; set; }

        /// <inheritdoc />
        public override string NormalizedName { get; set; }

        /// <inheritdoc />
        public override string ConcurrencyStamp { get; set; }

        /// <summary>Returns the name of the role.</summary>
        /// <returns>The name of the role.</returns>
        public override string ToString()
        {
            return Name;
        }
    }
}