# OneRoster OAuth .NET Plugin
[![NuGet](https://img.shields.io/nuget/v/Nuget.Core.svg)](https://www.nuget.org/packages/OneRosterOAuth/)
#### Usage:
```c#
Install using Nuget package manager:
	PM> Install-Package OneRosterOAuth

// include the library
using OneRosterOAuth;

// Initialize new OneRosterConnection, inputting your Key and Secret
var connection = new OneRosterConnection(oneRosterKey, oneRosterSecret);

// Hit users endpoint, requesting only 1 active user
// use OneRosterConnection.urlEncode for OAuth-safe url encoding
var filter = "filter=" + connection.urlEncode("status='active'");
var url = "https://example.oneroster.com/learningdata/v1/users?limit=1&" + filter;

// Can use either await or Task.WaitAll

	// using await 
	HttpResponseMessage response = await connection.makeRequest(url);
	
	// using Task.WaitAll
	var task = connection.makeRequest(url);
	Task.WaitAll(task);
	HttpResponseMessage response = task.Result;

// Get response status code
var statusCode = response.StatusCode;

// Get response content
var content = await response.Content.ReadAsStringAsync();
```