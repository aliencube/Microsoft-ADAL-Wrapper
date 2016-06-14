# Microsoft ADAL Wrapper #

This provides a wrapper library for ADAL - [https://www.nuget.org/packages/Microsoft.IdentityModel.Clients.ActiveDirectory](https://www.nuget.org/packages/Microsoft.IdentityModel.Clients.ActiveDirectory).

ADAL provides many classes marked as `sealed`. This doesn't only prevent us from inheriting, but also blocks mocking. In order to mock those classes, we need wrapper classes for them. This library provides wrapper classes for those defined in ADAL.


## Getting Started ##

The `AuthenticationContext` is the main class most frequently used in ADAL, which is marked as `sealed`. Therefore, it order to use a wrapper for this, simply follow the step below:

```csharp
var authority = "https://login.microsoftonline.com/[TENANT_NAME].onmicrosoft.com";
var resource = "https://management.core.windows.net/";

var clientId = "[CLIENT_ID]";
var clientSecret = "[CLIENT_SECRET]";
var credential = new ClientCredential(clientId, clientSecret);

using (var context = new AuthenticationContextWrapper(authority))
{
  var result = await context.AcquireTokenAsync(resource, credential);
}
```

This offers the same development experience as existing ADAL's `AuthenticationContext` class. However, if you need to mock `AuthenticationContext`, this wrapper library will offer you powerful development experiences like:

```csharp
var result = new Mock<IAuthenticationResultWrapper>();
result.SetupGet(p => p.AccessToken).Returns("[ACCESS_TOKEN]");

var wrapper = new Mock<IAuthenticationContextWrapper>();
wrapper.Setup(p => p.AcquireTokenAsync(It.IsAny<string>(), It.IsAny<ClientCredential>())).ReturnsAsync(result.Object).
```

By doing so, those `AuthenticationContext` and `AuthenticationResult` are under our control for mocking by their wrapping classes.


## Contribution ##

Your contributions are always welcome! All your work should be done in your forked repository. Once you finish your work with corresponding tests, please send us a pull request onto our `dev` branch for review.


## License ##

**Microsoft ADAL Wrapper** is released under [MIT License](http://opensource.org/licenses/MIT)

> The MIT License (MIT)
>
> Copyright (c) 2014 [aliencube.org](http://aliencube.org)
> 
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
> 
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
> 
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
