using LetsEncrypt.Func.Config;
using LetsEncrypt.Logic;
using LetsEncrypt.Logic.Config;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using ExecutionContext = Microsoft.Azure.WebJobs.ExecutionContext;

namespace LetsEncrypt.Func.Functions
{
    public class AutoRenewal
    {
        private readonly IRenewalService _renewalService;
        private readonly ILogger _logger;
        private readonly IConfigurationLoader _configurationLoader;

        public AutoRenewal(
            IConfigurationLoader configurationLoader,
            IRenewalService renewalService,
            ILogger<AutoRenewal> logger)
        {
            _configurationLoader = configurationLoader;
            _renewalService = renewalService;
            _logger = logger;
        }

        /// <summary>
        /// Wrapper function that allows manual execution via http with optional override parameters.
        /// </summary>
        [FunctionName("execute")]
        public async Task<IActionResult> ExecuteManuallyAsync(
            [HttpTrigger(AuthorizationLevel.Function, "POST", Route = "")] HttpRequestMessage req,
            CancellationToken cancellationToken,
            ExecutionContext executionContext)
        {
            var q = req.RequestUri.ParseQueryString();
            var overrides = new Overrides
            {
                NewCertificate = "true".Equals(q.GetValues(nameof(Overrides.NewCertificate))?.FirstOrDefault(), StringComparison.OrdinalIgnoreCase)
            };
            try
            {
                await RenewAsync(overrides, executionContext, cancellationToken);
                return new AcceptedResult();
            }
            catch (Exception)
            {
                return new BadRequestObjectResult(new
                {
                    message = "Certificate renewal failed, check appinsights for details"
                });
            }
        }

        /// <summary>
        /// Time triggered function that reads config files from storage
        /// and renews certificates accordingly if needed.
        /// </summary>
        [FunctionName("renew")]
        public Task RenewAsync(
            [TimerTrigger(Schedule.Daily, RunOnStartup = true)] TimerInfo timer,
            CancellationToken cancellationToken,
            ExecutionContext executionContext)
            => RenewAsync((Overrides)null, executionContext, cancellationToken);

        private async Task RenewAsync(
            Overrides overrides,
            ExecutionContext executionContext,
            CancellationToken cancellationToken)
        {
            var configurations = await _configurationLoader.LoadConfigFilesAsync(executionContext, cancellationToken);
            var stopwatch = new Stopwatch();
            // with lots of certificate renewals this could run into function timeout (10mins)
            // with 30 days to expiry (default setting) this isn't a big problem as next day all unfinished renewals are continued
            // user will only get email <= 14 days before expiry so acceptable for now
            var errors = new List<Exception>();
            foreach ((var name, var config) in configurations)
            {
                using (_logger.BeginScope($"Working on certificates from {name}"))
                {
                    foreach (var cert in config.Certificates)
                    {
                        stopwatch.Restart();
                        var hostNames = string.Join(";", cert.HostNames);
                        cert.Overrides = overrides ?? Overrides.None;
                        try
                        {
                            _logger.LogInformation($"await _renewalService.RenewCertificateAsync(config.Acme, cert, cancellationToken) ${cert.TargetResource.Type.ToLowerInvariant()}");
                            var result = await _renewalService.RenewCertificateAsync(config.Acme, cert, cancellationToken);
                            switch (result)
                            {
                                case RenewalResult.NoChange:
                                    _logger.LogInformation($"Certificate renewal skipped for: {hostNames} (no change required yet)");
                                    break;
                                case RenewalResult.Success:
                                    _logger.LogInformation($"Certificate renewal succeeded for: {hostNames}");
                                    break;
                                default:
                                    throw new ArgumentOutOfRangeException(result.ToString());
                            }
                        }
                        catch (Exception e)
                        {
                            _logger.LogError(e, $"Certificate renewal failed for: {hostNames}!");
                            errors.Add(e);
                        }
                        _logger.LogInformation($"Renewing certificates for {hostNames} took: {stopwatch.Elapsed}");
                    }
                }
            }
            if (!configurations.Any())
            {
                _logger.LogWarning("No configurations where processed, refere to the sample on how to set up configs!");
            }
            if (errors.Any())
                throw new AggregateException("Failed to process all certificates", errors);
        }
    }
}
