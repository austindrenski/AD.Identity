using System;
using System.IO;
using System.IO.Compression;
using AD.Identity.Conventions;
using AD.Identity.Extensions;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.DotNet.PlatformAbstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;
using Swashbuckle.AspNetCore.Swagger;

namespace IdentityApi
{
    /// <summary>
    /// 
    /// </summary>
    [PublicAPI]
    public sealed class Startup
    {
        /// <summary>
        ///
        /// </summary>
        public IConfigurationRoot Configuration { get; }

        /// <summary>
        ///
        /// </summary>
        public string EnvironmentName { get; }

        /// <summary>
        ///
        /// </summary>
        /// <param name="environment">
        /// 
        /// </param>
        /// <exception cref="ArgumentNullException" />
        public Startup([NotNull] IHostingEnvironment environment)
        {
            if (environment is null)
            {
                throw new ArgumentNullException(nameof(environment));
            }

            EnvironmentName = environment.EnvironmentName;

            Configuration =
                new ConfigurationBuilder()
                    .SetBasePath(environment.ContentRootPath)
                    .AddEnvironmentVariables()
                    .AddUserSecrets<Startup>()
                    .Build();
        }

        /// <summary>
        /// This method gets called by the runtime. Use this method to add services to the container.
        /// </summary>
        /// <param name="services">
        /// 
        /// </param>
        public void ConfigureServices([NotNull] IServiceCollection services)
        {
            if (services is null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            //.AddScoped<IIdentityContext, IdentityContext>(_ => new IdentityContext(Configuration[$"ConnectionStrings:{EnvironmentName}:identity_db"]))

            services.AddApiVersioning(
                        x =>
                        {
                            x.AssumeDefaultVersionWhenUnspecified = true;
                            x.DefaultApiVersion = new ApiVersion(1, 0);
                        })
                    .AddMemoryCache()
                    .AddResponseCompression(x => x.Providers.Add<GzipCompressionProvider>())
                    .Configure<GzipCompressionProviderOptions>(x => x.Level = CompressionLevel.Fastest)
                    .AddRouting(x => x.LowercaseUrls = true)
                    .AddAntiforgery(
                        x =>
                        {
                            x.HeaderName = "x-xsrf-token";
                            x.Cookie.HttpOnly = true;
                            x.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                        })
                    .AddMvc(
                        x =>
                        {
                            x.Conventions.Add(new KebabControllerModelConvention(nameof(IdentityApi)));
                            x.ModelMetadataDetailsProviders.Add(new KebabBindingMetadataProvider());
                            x.RespectBrowserAcceptHeader = true;
                        })
                    .AddJsonOptions(
                        x =>
                        {
                            x.SerializerSettings.ReferenceLoopHandling = ReferenceLoopHandling.Serialize;
                            x.SerializerSettings.PreserveReferencesHandling = PreserveReferencesHandling.Objects;
                        })
                    .Services
                    .AddSwaggerGen(
                        x =>
                        {
                            x.DescribeAllEnumsAsStrings();
                            x.IncludeXmlComments($"{Path.Combine(ApplicationEnvironment.ApplicationBasePath, nameof(IdentityApi))}.xml");
                            x.IgnoreObsoleteActions();
                            x.IgnoreObsoleteProperties();
                            x.SwaggerDoc("v1", new Info { Title = "IdentityAPI", Version = "v1" });
                            x.OperationFilter<SwaggerOptionalFilter>();
                        });
        }

        /// <summary>
        /// This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        /// </summary>
        /// <param name="app">
        /// 
        /// </param>
        public void Configure([NotNull] IApplicationBuilder app)
        {
            if (app is null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            app.Use(
                   async (context, next) =>
                   {
                       context.Response.Headers.Add("referrer-policy", "no-referrer");
                       context.Response.Headers.Add("x-content-type-options", "nosniff");
                       context.Response.Headers.Add("x-frame-options", "deny");
                       context.Response.Headers.Add("x-xss-protection", "1; mode=block");
                       await next();
                   })
               .UseResponseCompression()
               .UseStaticFiles()
               .UseSwagger(x => x.RouteTemplate = "docs/{documentName}/swagger.json")
               .UseSwaggerUI(
                   x =>
                   {
                       x.RoutePrefix = "docs";
                       x.DocumentTitle("Identity API Documentation");
                       x.InjectStylesheet("swagger-ui/swagger.css");
                       x.ShowJsonEditor();
                       x.ShowRequestHeaders();
                       x.SwaggerEndpoint("v1/swagger.json", "Identity API Documentation");
                   })
               .UseMvc();
        }
    }
}