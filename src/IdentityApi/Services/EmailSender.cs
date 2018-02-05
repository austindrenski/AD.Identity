using System.Threading.Tasks;
using JetBrains.Annotations;

namespace IdentityApi.Services
{
    /// <summary>
    /// Represents a way to send emails for account creation and recovery. 
    /// </summary>
    [PublicAPI]
    public sealed class EmailSender : IEmailSender
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="email"></param>
        /// <param name="subject"></param>
        /// <param name="message"></param>
        /// <returns></returns>
        public Task SendEmailAsync(string email, string subject, string message)
        {
            return Task.CompletedTask;
        }
    }
}