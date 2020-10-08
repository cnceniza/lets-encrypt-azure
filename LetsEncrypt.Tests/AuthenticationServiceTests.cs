using Certes;
using Certes.Acme;
using FluentAssertions;
using LetsEncrypt.Logic.Acme;
using LetsEncrypt.Logic.Authentication;
using LetsEncrypt.Logic.Storage;
using LetsEncrypt.Tests.Extensions;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace LetsEncrypt.Tests
{
    public class AuthenticationServiceTests
    {
        [Test]
        public async Task ShouldAskForANewAccountIfNotCachedAndStoreAccountKey()
        {
            // arrange
            var storageMock = new Mock<IStorageProvider>();
            storageMock.Setup(x => x.ExistsAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.FromResult(false));

            const string keyInPemFormat = "--- not actually a pem ---";
            var keyMock = new Mock<IKey>();
            keyMock.Setup(x => x.ToPem())
                .Returns(keyInPemFormat);

            var acmeContextMock = new Mock<IAcmeContext>();
            acmeContextMock.SetupGet(x => x.AccountKey)
                .Returns(keyMock.Object);
            acmeContextMock.Setup(x => x.NewAccount(It.IsAny<IList<string>>(), true))
                .Returns(Task.FromResult((IAccountContext)null));

            var factoryMock = acmeContextMock.Object.CreateFactoryMock();

            var options = TestHelper.GetStagingOptions();
            var log = new Mock<ILogger<AuthenticationService>>();
            IAuthenticationService authenticationService = new AuthenticationService(storageMock.Object, log.Object, factoryMock.Object);

            // act
            var context = await authenticationService.AuthenticateAsync(options, CancellationToken.None);

            // assert
            context.Should().NotBeNull();
            context.AcmeContext.Should().Be(acmeContextMock.Object);
            context.Options.Should().Be(options);

            // ensure account wasn't read from disk
            storageMock.Verify(x => x.GetAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
            factoryMock.Verify(x => x.GetContext(options.CertificateAuthorityUri, null));

            // extension methods adds mailto to emailbefore calling the actual method
            acmeContextMock.Verify(x => x.NewAccount(It.Is<IList<string>>(list => list.Count == 1 && list[0] == $"mailto:{options.Email}"), true));

            storageMock.Verify(x => x.SetAsync(It.IsAny<string>(), keyInPemFormat, It.IsAny<CancellationToken>()));
        }

        [Test]
        public async Task ShouldLoadExistingAccountIfCached()
        {
            const string keyInPemFormat = "--- not actually a pem ---";

            var options = TestHelper.GetStagingOptions();
            var accountFilename = $"{options.CertificateAuthorityUri.Host}--{options.Email}.pem";

            // arrange

            // verify key is pulled from storage
            var storageMock = new Mock<IStorageProvider>();
            storageMock.Setup(x => x.Escape(It.IsAny<string>()))
                .Returns(accountFilename);
            storageMock.Setup(x => x.ExistsAsync("account/" + accountFilename, It.IsAny<CancellationToken>()))
                .Returns(Task.FromResult(true));
            storageMock.Setup(x => x.GetAsync("account/" + accountFilename, It.IsAny<CancellationToken>()))
                .Returns(Task.FromResult(keyInPemFormat));

            var keyMock = new Mock<IKey>();
            keyMock.Setup(x => x.ToPem())
                .Returns(keyInPemFormat);

            var acmeContextMock = new Mock<IAcmeContext>();
            acmeContextMock.SetupGet(x => x.AccountKey)
                .Returns(keyMock.Object);
            acmeContextMock.Setup(x => x.NewAccount(It.IsAny<IList<string>>(), true))
                .Returns(Task.FromResult((IAccountContext)null));

            var contextFactoryMock = acmeContextMock.Object.CreateFactoryMock();
            var keyFactoryMock = new Mock<IAcmeKeyFactory>();
            keyFactoryMock.Setup(x => x.FromPem(keyInPemFormat))
                .Returns(keyMock.Object);

            var log = new Mock<ILogger<AuthenticationService>>();
            IAuthenticationService authenticationService = new AuthenticationService(storageMock.Object, log.Object, contextFactoryMock.Object, keyFactoryMock.Object);

            // act
            var context = await authenticationService.AuthenticateAsync(options, CancellationToken.None);

            // assert
            context.Should().NotBeNull();
            context.AcmeContext.Should().Be(acmeContextMock.Object);
            context.Options.Should().Be(options);

            // account was read from disk
            storageMock.Verify(x => x.GetAsync("account/" + accountFilename, It.IsAny<CancellationToken>()));
            // account was restored from key
            contextFactoryMock.Verify(x => x.GetContext(options.CertificateAuthorityUri, keyMock.Object));
            // key was not written back to storage
            storageMock.Verify(x => x.SetAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }
}
