using System;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Identity;

namespace AD.Identity.Models
{
    /// <inheritdoc />
    /// <summary>
    /// Inherits <see cref="IdentityRole{TKey}"/> with <see cref="Guid"/>.
    /// </summary>
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

        /// <inheritdoc />
        /// <summary>Returns the name of the role.</summary>
        /// <returns>The name of the role.</returns>
        public override string ToString()
        {
            return Name;
        }
    }
}