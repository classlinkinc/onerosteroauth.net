# OneRoster OAuth .NET Plugin

#### Usage:
```c#
// include the library
using OneRosterOAuth;

// Initialize new OneRosterConnection, inputting your Key and Secret
var connection = new OneRosterConnection(oneRosterKey, oneRosterSecret);

// Hit users endpoint, requesting only 1 active user
// use OneRosterConnection.urlEncode for OAuth-safe url encoding
var filter = "filter=" + connection.urlEncode("status='active'");
var url = "https://example.oneroster.com/learningdata/v1/users?limit=1&" + filter;
HttpResponseMessage response = await connection.makeRequest(url);

// Get response status code
var statusCode = response.StatusCode;

// Get response content
var content = await response.Content.ReadAsStringAsync();
```