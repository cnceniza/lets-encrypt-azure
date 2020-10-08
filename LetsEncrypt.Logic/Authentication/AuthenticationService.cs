using Certes;
using LetsEncrypt.Logic.Acme;
using LetsEncrypt.Logic.Config;
using LetsEncrypt.Logic.Storage;
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace LetsEncrypt.Logic.Authentication
{
    public class AuthenticationService : IAuthenticationService
    {
        private readonly IStorageProvider _storageProvider;
        private const string AccountKeyFilenamePattern = "{0}--{1}.pem";
        private readonly IAcmeContextFactory _contextFactory;
        private readonly IAcmeKeyFactory _keyFactory;
        private readonly ILogger _logger;

        public AuthenticationService(
            IStorageProvider storageProvider,
            ILogger<AuthenticationService> logger,
            IAcmeContextFactory contextFactory = null,
            IAcmeKeyFactory keyFactory = null)
        {
            _storageProvider = storageProvider ?? throw new ArgumentNullException(nameof(storageProvider));
            _contextFactory = contextFactory ?? new AcmeContextFactory();
            _keyFactory = keyFactory ?? new AcmeKeyFactory();
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<AuthenticationContext> AuthenticateAsync(
            IAcmeOptions options,
            CancellationToken cancellationToken)
        {
            _logger.LogInformation($"starting -> AuthenticationService.AuthenticateAsync");
            if (options == null)
                throw new ArgumentNullException(nameof(options));
            _logger.LogInformation($"done -> AuthenticationService.AuthenticateAsync");

            IAcmeContext acme;
            _logger.LogInformation($"starting -> LoadExistingAccountKey");
            var existingKey = await LoadExistingAccountKey(options, cancellationToken);
            _logger.LogInformation($"done -> LoadExistingAccountKey");
            if (existingKey == null)
            {
                _logger.LogInformation($"starting -> _contextFactory.GetContext(options.CertificateAuthorityUri)");
                acme = _contextFactory.GetContext(options.CertificateAuthorityUri);
                _logger.LogInformation($"done -> _contextFactory.GetContext(options.CertificateAuthorityUri)");
                // as far as I understand there is a penalty for calling NewAccount too often
                // thus storing the key is encouraged
                // however a keyloss is "non critical" as NewAccount can be called on any existing account without problems
                _logger.LogInformation($"starting -> await acme.NewAccount(options.Email, true);");
                await acme.NewAccount(options.Email, true);
                _logger.LogInformation($"done -> await acme.NewAccount(options.Email, true);");

                _logger.LogInformation($"starting ->  existingKey = acme.AccountKey;");
                existingKey = acme.AccountKey;
                _logger.LogInformation($"done ->  existingKey = acme.AccountKey;");

                _logger.LogInformation($"starting -> await StoreAccountKeyAsync(options, existingKey, cancellationToken)");
                await StoreAccountKeyAsync(options, existingKey, cancellationToken);
                _logger.LogInformation($"done -> await StoreAccountKeyAsync(options, existingKey, cancellationToken)");
            }
            else
            {
                _logger.LogInformation($"starting -> acme = _contextFactory.GetContext(options.CertificateAuthorityUri, existingKey);");
                acme = _contextFactory.GetContext(options.CertificateAuthorityUri, existingKey);
                _logger.LogInformation($"done -> acme = _contextFactory.GetContext(options.CertificateAuthorityUri, existingKey);");
            }
            return new AuthenticationContext(acme, options);
        }

        private async Task<IKey> LoadExistingAccountKey(
            IAcmeOptions options,
            CancellationToken cancellationToken)
        {
            _logger.LogInformation($"starting -> LoadExistingAccountKey var fileName = GetAccountKeyFilename(options);");
            var fileName = GetAccountKeyFilename(options);
            _logger.LogInformation($"done -> var fileName = GetAccountKeyFilename(options);");

            _logger.LogInformation($"starting -> if (!await _storageProvider.ExistsAsync(fileName, cancellationToken))");
            if (!await _storageProvider.ExistsAsync(fileName, cancellationToken))
                return null;
            _logger.LogInformation($"done -> if (!await _storageProvider.ExistsAsync(fileName, cancellationToken))");

            _logger.LogInformation($"starting -> await _storageProvider.GetAsync(fileName, cancellationToken);");
            var content = await _storageProvider.GetAsync(fileName, cancellationToken);
            _logger.LogInformation($"done -> await _storageProvider.GetAsync(fileName, cancellationToken);");

            _logger.LogInformation($"starting -> awaitvar result = _keyFactory.FromPem(content);");
            var result = _keyFactory.FromPem(content);
            _logger.LogInformation($"done -> awaitvar result = _keyFactory.FromPem(content);");
            return result;
        }

        private Task StoreAccountKeyAsync(
            IAcmeOptions options,
            IKey existingKey,
            CancellationToken cancellationToken)
        {
            _logger.LogInformation($"starting -> StoreAccountKeyAsync var filename = GetAccountKeyFilename(options);");
            var filename = GetAccountKeyFilename(options);
            _logger.LogInformation($"done -> StoreAccountKeyAsync var filename = GetAccountKeyFilename(options);");

            _logger.LogInformation($"starting -> var content = existingKey.ToPem();");
            var content = existingKey.ToPem();
            _logger.LogInformation($"done -> var content = existingKey.ToPem();");

            _logger.LogInformation($"starting -> _storageProvider.SetAsync(filename, content, cancellationToken);");
            var result = _storageProvider.SetAsync(filename, content, cancellationToken);
            _logger.LogInformation($"done -> _storageProvider.SetAsync(filename, content, cancellationToken);");
            return result;
        }

        private string GetAccountKeyFilename(IAcmeOptions options)
        {
            _logger.LogInformation($"starting -> AuthenticationService.GetAccountKeyFilename");
            var result = "account/" + _storageProvider.Escape(string.Format(AccountKeyFilenamePattern, options.CertificateAuthorityUri.Host, options.Email));
            _logger.LogInformation($"starting -> AuthenticationService.GetAccountKeyFilename {result}");
            return result;
        }
    }
}
