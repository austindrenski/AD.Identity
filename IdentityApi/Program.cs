using System;
using System.IO;
using JetBrains.Annotations;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;

namespace IdentityApi
{
    /// <summary>
    /// 
    /// </summary>
    [PublicAPI]
    public sealed class Program
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="args">
        /// 
        /// </param>
        /// <exception cref="ArgumentNullException" />
        public static void Main([NotNull] [ItemNotNull] string[] args)
        {
            if (args is null)
            {
                throw new ArgumentNullException(nameof(args));
            }

            BuildWebHost(args).Run();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="args">
        /// 
        /// </param>
        /// <returns>
        /// 
        /// </returns>
        /// <exception cref="ArgumentNullException" />
        [NotNull]
        private static IWebHost BuildWebHost([NotNull] [ItemNotNull] string[] args)
        {
            if (args is null)
            {
                throw new ArgumentNullException(nameof(args));
            }

            IConfigurationRoot configuration =
                new ConfigurationBuilder()
                    .AddCommandLine(args)
                    .Build();

            return
                WebHost.CreateDefaultBuilder(args)
                       .UseHttpSys()
                       .UseConfiguration(configuration)
                       .UseContentRoot(Directory.GetCurrentDirectory())
                       .UseStartup<Startup>()
                       .Build();
        }
    }
}