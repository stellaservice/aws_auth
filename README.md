HmacAuth
=======

A small library used to sign request urls using HMAC SHA1

Takes some inspiration from the [Simplex](https://github.com/adamkittelson/simplex) Library, forked from [AWSAuth](https://github.com/bryanjos/aws_auth)

Does both URL and Authorization Header signing.

`HmacAuth.sign_url(secret, http_method, url, headers \\ Map.new)`


`secret`: Your secret

`http_method`: "GET","POST","PUT","DELETE", etc

`url`: The url you want to sign

`headers` (optional): The headers that will be used in the request. Used for signing the request. For signing, host is the only one required.  If host is present here, it will override using the host in the url to attempt signing. If only the host is needed, then you don't have to supply it and the host from the url will be used.

In most cases, you would probably call it like this:

```elixir
signed_request = HmacAuth.sign_url("correct staple battery horse",
  "GET",
  "https://example.com/test.txt")
"https://example.com/test.txt?Authorization={calculated sha}
```