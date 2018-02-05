using System.Threading.Tasks;
using JetBrains.Annotations;

namespace IdentityApi.Services
{
    /// <summary>
    /// 
    /// </summary>
    [PublicAPI]
    public interface IEmailSender
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="email">
        /// 
        /// </param>
        /// <param name="subject">
        /// 
        /// </param>
        /// <param name="message">
        /// 
        /// </param>
        /// <returns>
        /// 
        /// </returns>
        [NotNull]
        Task SendEmailAsync([NotNull] string email, [NotNull] string subject, [NotNull] string message);
    }
}