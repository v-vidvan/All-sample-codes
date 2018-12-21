# Introduction 
PowerShell to request Jit access to VSTS Support Tool (https://app.csstool.visualstudio.com)

# Getting Started
Initial commit works if uou use a physical smart card, but not with Windows Hello PIN (which is odd, because the WH pin _does_ work if I use it for Jit in a browser). If you have a physical sc attached to your machine all the time, you might like to use this approach to Jit. Simply run the PS1 then auth when prompted. And if you can get this working a Windows Hello PIN, I'd love to see it. :-)

~Trev

#Investigation
-- We decompile the failing class method on 
```C#
DstsClientHelper.JITApiHelper.<CreateAuthenticationContext>
 protected async Task<CompleteWebAuthenticationContext> CreateAuthenticationContext(HttpRequestMessage request)
    {
      AuthenticationMetadata localMetadata = await this.GetAuthenticationMetadata();
      CompleteWebAuthenticationContext completeContext = (CompleteWebAuthenticationContext) null;
      try
      {
        completeContext = this.DstsWebAuthClient.CreateContext(this.ServiceName, request.RequestUri.Host, localMetadata);
      }
      catch (Exception ex)
      {
        Exception exception = ex;
        if (ex is AggregateException)
          exception = (ex as AggregateException).InnerExceptions[0];
        else if (ex.InnerException != null)
          exception = ex.InnerException;
        while (exception.InnerException != null)
          exception = exception.InnerException;
        throw new dstsClientException(string.Format((IFormatProvider) CultureInfo.InvariantCulture, "Failed to create CompleteWebAuthenticationContext, Exception: {0}, InnerException: {1}", new object[2]
        {
          (object) ex,
          (object) exception
        }), dstsClientErrorCategory.MetaDataError, ex);
      }
      DstsConfigHelper.Helpers.TryAdd(this.ServiceBaseUrl, this);
      return completeContext;
    }
```
# TODO
- Decompile the whole project
- maybe create a VS Project

# Exception

```Exception
New-JITRequest : Failed to create CompleteWebAuthenticationContext, Exception:
System.Security.Cryptography.CryptographicException: Invalid provider type specified.
Server stack trace:
   at System.Security.Cryptography.Utils.CreateProvHandle(CspParameters parameters, Boolean randomKeyContainer)
   at System.Security.Cryptography.Utils.GetKeyPairHelper(CspAlgorithmType keyType, CspParameters parameters, Boolean
randomKeyContainer, Int32 dwKeySize, SafeProvHandle& safeProvHandle, SafeKeyHandle& safeKeyHandle)
   at System.Security.Cryptography.RSACryptoServiceProvider.GetKeyPair()
   at System.Security.Cryptography.RSACryptoServiceProvider..ctor(Int32 dwKeySize, CspParameters parameters, Boolean
useDefaultKeySize)
   at System.Security.Cryptography.X509Certificates.X509Certificate2.get_PrivateKey()
   at System.IdentityModel.Tokens.X509AsymmetricSecurityKey.get_PrivateKey()
   at System.IdentityModel.Tokens.X509AsymmetricSecurityKey.GetSignatureFormatter(String algorithm)
   at System.IdentityModel.SignedXml.ComputeSignature(SecurityKey signingKey)
   at System.ServiceModel.Security.WSSecurityOneDotZeroSendSecurityHeader.CompletePrimarySignatureCore(SendSecurityHead
erElement[] signatureConfirmations, SecurityToken[] signedEndorsingTokens, SecurityToken[] signedTokens,
SendSecurityHeaderElement[] basicTokens, Boolean isPrimarySignature)
   at System.ServiceModel.Security.WSSecurityOneDotZeroSendSecurityHeader.CreateSupportingSignature(SecurityToken
token, SecurityKeyIdentifier identifier)
   at System.ServiceModel.Security.SendSecurityHeader.SignWithSupportingToken(SecurityToken token,
SecurityKeyIdentifierClause identifierClause)
   at System.ServiceModel.Security.SendSecurityHeader.SignWithSupportingTokens()
   at System.ServiceModel.Security.SendSecurityHeader.CompleteSecurityApplication()
   at System.ServiceModel.Security.SecurityAppliedMessage.OnWriteMessage(XmlDictionaryWriter writer)
   at System.ServiceModel.Channels.BufferedMessageWriter.WriteMessage(Message message, BufferManager bufferManager,
Int32 initialOffset, Int32 maxSizeQuota)
   at System.ServiceModel.Channels.TextMessageEncoderFactory.TextMessageEncoder.WriteMessage(Message message, Int32
maxMessageSize, BufferManager bufferManager, Int32 messageOffset)
   at System.ServiceModel.Channels.HttpOutput.SerializeBufferedMessage(Message message, Boolean shouldRecycleBuffer)
   at System.ServiceModel.Channels.HttpOutput.Send(TimeSpan timeout)
   at System.ServiceModel.Channels.HttpChannelFactory`1.HttpRequestChannel.HttpChannelRequest.SendRequest(Message
message, TimeSpan timeout)
   at System.ServiceModel.Channels.RequestChannel.Request(Message message, TimeSpan timeout)
   at System.ServiceModel.Channels.SecurityChannelFactory`1.SecurityRequestChannel.Request(Message message, TimeSpan
timeout)
   at System.ServiceModel.Dispatcher.RequestChannelBinder.Request(Message message, TimeSpan timeout)
   at System.ServiceModel.Channels.ServiceChannel.Call(String action, Boolean oneway, ProxyOperationRuntime operation,
Object[] ins, Object[] outs, TimeSpan timeout)
   at System.ServiceModel.Channels.ServiceChannelProxy.InvokeService(IMethodCallMessage methodCall,
ProxyOperationRuntime operation)
   at System.ServiceModel.Channels.ServiceChannelProxy.Invoke(IMessage message)
Exception rethrown at [0]:
   at Microsoft.WindowsAzure.Security.Authentication.AuthenticationClient.ExecuteGetSecurityToken(IEnumerable`1
proxyList, SecurityTokenIssuanceRequest request)
   at Microsoft.WindowsAzure.Security.Authentication.AuthenticationClient.GetSecurityToken(Uri serviceRealmUri, String
dnsHostName, AuthenticationMetadata authenticationMetadata, ICertificateSelector certificateSelector)
   at Microsoft.WindowsAzure.Security.Authentication.AuthenticationClient.GetSecurityToken(String serviceName, String
dnsHostName, AuthenticationMetadata authenticationMetadata)
   at Microsoft.WindowsAzure.Security.Authentication.WebAuthenticationClient.CreateContext(String serviceName, String
serviceDnsName, AuthenticationMetadata authenticationMetadata)
   at Microsoft.WindowsAzure.Wapd.JIT.DstsClientHelper.JITApiHelper.<CreateAuthenticationContext>d__1.MoveNext() in
x:\btsdx\779776\services\wapd\ACIS\AzurePortal\Tools\dSTSClientHelper\JITHelper.cs:line 65, InnerException:
System.Security.Cryptography.CryptographicException: Invalid provider type specified.
Server stack trace:
   at System.Security.Cryptography.Utils.CreateProvHandle(CspParameters parameters, Boolean randomKeyContainer)
   at System.Security.Cryptography.Utils.GetKeyPairHelper(CspAlgorithmType keyType, CspParameters parameters, Boolean
randomKeyContainer, Int32 dwKeySize, SafeProvHandle& safeProvHandle, SafeKeyHandle& safeKeyHandle)
   at System.Security.Cryptography.RSACryptoServiceProvider.GetKeyPair()
   at System.Security.Cryptography.RSACryptoServiceProvider..ctor(Int32 dwKeySize, CspParameters parameters, Boolean
useDefaultKeySize)
   at System.Security.Cryptography.X509Certificates.X509Certificate2.get_PrivateKey()
   at System.IdentityModel.Tokens.X509AsymmetricSecurityKey.get_PrivateKey()
   at System.IdentityModel.Tokens.X509AsymmetricSecurityKey.GetSignatureFormatter(String algorithm)
   at System.IdentityModel.SignedXml.ComputeSignature(SecurityKey signingKey)
   at System.ServiceModel.Security.WSSecurityOneDotZeroSendSecurityHeader.CompletePrimarySignatureCore(SendSecurityHead
erElement[] signatureConfirmations, SecurityToken[] signedEndorsingTokens, SecurityToken[] signedTokens,
SendSecurityHeaderElement[] basicTokens, Boolean isPrimarySignature)
   at System.ServiceModel.Security.WSSecurityOneDotZeroSendSecurityHeader.CreateSupportingSignature(SecurityToken
token, SecurityKeyIdentifier identifier)
   at System.ServiceModel.Security.SendSecurityHeader.SignWithSupportingToken(SecurityToken token,
SecurityKeyIdentifierClause identifierClause)
   at System.ServiceModel.Security.SendSecurityHeader.SignWithSupportingTokens()
   at System.ServiceModel.Security.SendSecurityHeader.CompleteSecurityApplication()
   at System.ServiceModel.Security.SecurityAppliedMessage.OnWriteMessage(XmlDictionaryWriter writer)
   at System.ServiceModel.Channels.BufferedMessageWriter.WriteMessage(Message message, BufferManager bufferManager,
Int32 initialOffset, Int32 maxSizeQuota)
   at System.ServiceModel.Channels.TextMessageEncoderFactory.TextMessageEncoder.WriteMessage(Message message, Int32
maxMessageSize, BufferManager bufferManager, Int32 messageOffset)
   at System.ServiceModel.Channels.HttpOutput.SerializeBufferedMessage(Message message, Boolean shouldRecycleBuffer)
   at System.ServiceModel.Channels.HttpOutput.Send(TimeSpan timeout)
   at System.ServiceModel.Channels.HttpChannelFactory`1.HttpRequestChannel.HttpChannelRequest.SendRequest(Message
message, TimeSpan timeout)
   at System.ServiceModel.Channels.RequestChannel.Request(Message message, TimeSpan timeout)
   at System.ServiceModel.Channels.SecurityChannelFactory`1.SecurityRequestChannel.Request(Message message, TimeSpan
timeout)
   at System.ServiceModel.Dispatcher.RequestChannelBinder.Request(Message message, TimeSpan timeout)
   at System.ServiceModel.Channels.ServiceChannel.Call(String action, Boolean oneway, ProxyOperationRuntime operation,
Object[] ins, Object[] outs, TimeSpan timeout)
   at System.ServiceModel.Channels.ServiceChannelProxy.InvokeService(IMethodCallMessage methodCall,
ProxyOperationRuntime operation)
   at System.ServiceModel.Channels.ServiceChannelProxy.Invoke(IMessage message)
Exception rethrown at [0]:
   at Microsoft.WindowsAzure.Security.Authentication.AuthenticationClient.ExecuteGetSecurityToken(IEnumerable`1
proxyList, SecurityTokenIssuanceRequest request)
   at Microsoft.WindowsAzure.Security.Authentication.AuthenticationClient.GetSecurityToken(Uri serviceRealmUri, String
dnsHostName, AuthenticationMetadata authenticationMetadata, ICertificateSelector certificateSelector)
   at Microsoft.WindowsAzure.Security.Authentication.AuthenticationClient.GetSecurityToken(String serviceName, String
dnsHostName, AuthenticationMetadata authenticationMetadata)
   at Microsoft.WindowsAzure.Security.Authentication.WebAuthenticationClient.CreateContext(String serviceName, String
serviceDnsName, AuthenticationMetadata authenticationMetadata)
   at Microsoft.WindowsAzure.Wapd.JIT.DstsClientHelper.JITApiHelper.<CreateAuthenticationContext>d__1.MoveNext() in
x:\btsdx\779776\services\wapd\ACIS\AzurePortal\Tools\dSTSClientHelper\JITHelper.cs:line 65
At D:\repo\jithit\SuppToolJitPowerShell\SuppToolJitSuper.ps1:2 char:7
+ $id = New-JITRequest -env product -src TFS:RD -wid 1924273 -Justifica ...
+       ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [New-JITRequest], dstsClientException
    + FullyQualifiedErrorId : Failed to create CompleteWebAuthenticationContext, Exception: System.Security.Cryptograp
   hy.CryptographicException: Invalid provider type specified.
Server stack trace:
   at System.Security.Cryptography.Utils.CreateProvHandle(CspParameters parameters, Boolean randomKeyContainer)
       at System.Security.Cryptography.Utils.GetKeyPairHelper(CspAlgorithmType keyType, CspParameters parameters, Bool
   ean randomKeyContainer, Int32 dwKeySize, SafeProvHandle& safeProvHandle, SafeKeyHandle& safeKeyHandle)
   at System.Security.Cryptography.RSACryptoServiceProvider.GetKeyPair()
       at System.Security.Cryptography.RSACryptoServiceProvider..ctor(Int32 dwKeySize, CspParameters parameters, Boole
   an useDefaultKeySize)
   at System.Security.Cryptography.X509Certificates.X509Certificate2.get_PrivateKey()
   at System.IdentityModel.Tokens.X509AsymmetricSecurityKey.get_PrivateKey()
   at System.IdentityModel.Tokens.X509AsymmetricSecurityKey.GetSignatureFormatter(String algorithm)
   at System.IdentityModel.SignedXml.ComputeSignature(SecurityKey signingKey)
       at System.ServiceModel.Security.WSSecurityOneDotZeroSendSecurityHeader.CompletePrimarySignatureCore(SendSecurit
   yHeaderElement[] signatureConfirmations, SecurityToken[] signedEndorsingTokens, SecurityToken[] signedTokens, Send
  SecurityHeaderElement[] basicTokens, Boolean isPrimarySignature)
       at System.ServiceModel.Security.WSSecurityOneDotZeroSendSecurityHeader.CreateSupportingSignature(SecurityToken
   token, SecurityKeyIdentifier identifier)
       at System.ServiceModel.Security.SendSecurityHeader.SignWithSupportingToken(SecurityToken token, SecurityKeyIden
   tifierClause identifierClause)
   at System.ServiceModel.Security.SendSecurityHeader.SignWithSupportingTokens()
   at System.ServiceModel.Security.SendSecurityHeader.CompleteSecurityApplication()
   at System.ServiceModel.Security.SecurityAppliedMessage.OnWriteMessage(XmlDictionaryWriter writer)
       at System.ServiceModel.Channels.BufferedMessageWriter.WriteMessage(Message message, BufferManager bufferManager
   , Int32 initialOffset, Int32 maxSizeQuota)
       at System.ServiceModel.Channels.TextMessageEncoderFactory.TextMessageEncoder.WriteMessage(Message message, Int3
   2 maxMessageSize, BufferManager bufferManager, Int32 messageOffset)
       at System.ServiceModel.Channels.HttpOutput.SerializeBufferedMessage(Message message, Boolean shouldRecycleBuffe
   r)
   at System.ServiceModel.Channels.HttpOutput.Send(TimeSpan timeout)
       at System.ServiceModel.Channels.HttpChannelFactory`1.HttpRequestChannel.HttpChannelRequest.SendRequest(Message
   message, TimeSpan timeout)
   at System.ServiceModel.Channels.RequestChannel.Request(Message message, TimeSpan timeout)
       at System.ServiceModel.Channels.SecurityChannelFactory`1.SecurityRequestChannel.Request(Message message, TimeSp
   an timeout)
   at System.ServiceModel.Dispatcher.RequestChannelBinder.Request(Message message, TimeSpan timeout)
       at System.ServiceModel.Channels.ServiceChannel.Call(String action, Boolean oneway, ProxyOperationRuntime operat
   ion, Object[] ins, Object[] outs, TimeSpan timeout)
       at System.ServiceModel.Channels.ServiceChannelProxy.InvokeService(IMethodCallMessage methodCall, ProxyOperation
   Runtime operation)
   at System.ServiceModel.Channels.ServiceChannelProxy.Invoke(IMessage message)
Exception rethrown at [0]:
       at Microsoft.WindowsAzure.Security.Authentication.AuthenticationClient.ExecuteGetSecurityToken(IEnumerable`1 pr
   oxyList, SecurityTokenIssuanceRequest request)
       at Microsoft.WindowsAzure.Security.Authentication.AuthenticationClient.GetSecurityToken(Uri serviceRealmUri, St
   ring dnsHostName, AuthenticationMetadata authenticationMetadata, ICertificateSelector certificateSelector)
       at Microsoft.WindowsAzure.Security.Authentication.AuthenticationClient.GetSecurityToken(String serviceName, Str
   ing dnsHostName, AuthenticationMetadata authenticationMetadata)
       at Microsoft.WindowsAzure.Security.Authentication.WebAuthenticationClient.CreateContext(String serviceName, Str
   ing serviceDnsName, AuthenticationMetadata authenticationMetadata)
       at Microsoft.WindowsAzure.Wapd.JIT.DstsClientHelper.JITApiHelper.<CreateAuthenticationContext>d__1.MoveNext() i
   n x:\btsdx\779776\services\wapd\ACIS\AzurePortal\Tools\dSTSClientHelper\JITHelper.cs:line 65, InnerException: Syst
  em.Security.Cryptography.CryptographicException: Invalid provider type specified.
Server stack trace:
   at System.Security.Cryptography.Utils.CreateProvHandle(CspParameters parameters, Boolean randomKeyContainer)
       at System.Security.Cryptography.Utils.GetKeyPairHelper(CspAlgorithmType keyType, CspParameters parameters, Bool
   ean randomKeyContainer, Int32 dwKeySize, SafeProvHandle& safeProvHandle, SafeKeyHandle& safeKeyHandle)
   at System.Security.Cryptography.RSACryptoServiceProvider.GetKeyPair()
       at System.Security.Cryptography.RSACryptoServiceProvider..ctor(Int32 dwKeySize, CspParameters parameters, Boole
   an useDefaultKeySize)
   at System.Security.Cryptography.X509Certificates.X509Certificate2.get_PrivateKey()
   at System.IdentityModel.Tokens.X509AsymmetricSecurityKey.get_PrivateKey()
   at System.IdentityModel.Tokens.X509AsymmetricSecurityKey.GetSignatureFormatter(String algorithm)
   at System.IdentityModel.SignedXml.ComputeSignature(SecurityKey signingKey)
       at System.ServiceModel.Security.WSSecurityOneDotZeroSendSecurityHeader.CompletePrimarySignatureCore(SendSecurit
   yHeaderElement[] signatureConfirmations, SecurityToken[] signedEndorsingTokens, SecurityToken[] signedTokens, Send
  SecurityHeaderElement[] basicTokens, Boolean isPrimarySignature)
       at System.ServiceModel.Security.WSSecurityOneDotZeroSendSecurityHeader.CreateSupportingSignature(SecurityToken
   token, SecurityKeyIdentifier identifier)
       at System.ServiceModel.Security.SendSecurityHeader.SignWithSupportingToken(SecurityToken token, SecurityKeyIden
   tifierClause identifierClause)
   at System.ServiceModel.Security.SendSecurityHeader.SignWithSupportingTokens()
   at System.ServiceModel.Security.SendSecurityHeader.CompleteSecurityApplication()
   at System.ServiceModel.Security.SecurityAppliedMessage.OnWriteMessage(XmlDictionaryWriter writer)
       at System.ServiceModel.Channels.BufferedMessageWriter.WriteMessage(Message message, BufferManager bufferManager
   , Int32 initialOffset, Int32 maxSizeQuota)
       at System.ServiceModel.Channels.TextMessageEncoderFactory.TextMessageEncoder.WriteMessage(Message message, Int3
   2 maxMessageSize, BufferManager bufferManager, Int32 messageOffset)
       at System.ServiceModel.Channels.HttpOutput.SerializeBufferedMessage(Message message, Boolean shouldRecycleBuffe
   r)
   at System.ServiceModel.Channels.HttpOutput.Send(TimeSpan timeout)
       at System.ServiceModel.Channels.HttpChannelFactory`1.HttpRequestChannel.HttpChannelRequest.SendRequest(Message
   message, TimeSpan timeout)
   at System.ServiceModel.Channels.RequestChannel.Request(Message message, TimeSpan timeout)
       at System.ServiceModel.Channels.SecurityChannelFactory`1.SecurityRequestChannel.Request(Message message, TimeSp
   an timeout)
   at System.ServiceModel.Dispatcher.RequestChannelBinder.Request(Message message, TimeSpan timeout)
       at System.ServiceModel.Channels.ServiceChannel.Call(String action, Boolean oneway, ProxyOperationRuntime operat
   ion, Object[] ins, Object[] outs, TimeSpan timeout)
       at System.ServiceModel.Channels.ServiceChannelProxy.InvokeService(IMethodCallMessage methodCall, ProxyOperation
   Runtime operation)
   at System.ServiceModel.Channels.ServiceChannelProxy.Invoke(IMessage message)
Exception rethrown at [0]:
       at Microsoft.WindowsAzure.Security.Authentication.AuthenticationClient.ExecuteGetSecurityToken(IEnumerable`1 pr
   oxyList, SecurityTokenIssuanceRequest request)
       at Microsoft.WindowsAzure.Security.Authentication.AuthenticationClient.GetSecurityToken(Uri serviceRealmUri, St
   ring dnsHostName, AuthenticationMetadata authenticationMetadata, ICertificateSelector certificateSelector)
       at Microsoft.WindowsAzure.Security.Authentication.AuthenticationClient.GetSecurityToken(String serviceName, Str
   ing dnsHostName, AuthenticationMetadata authenticationMetadata)
       at Microsoft.WindowsAzure.Security.Authentication.WebAuthenticationClient.CreateContext(String serviceName, Str
   ing serviceDnsName, AuthenticationMetadata authenticationMetadata)
       at Microsoft.WindowsAzure.Wapd.JIT.DstsClientHelper.JITApiHelper.<CreateAuthenticationContext>d__1.MoveNext() i
   n x:\btsdx\779776\services\wapd\ACIS\AzurePortal\Tools\dSTSClientHelper\JITHelper.cs:line 65,Microsoft.WindowsAzur
  e.JIT.PowerShell.Commands.NewJITRequestCommand
```