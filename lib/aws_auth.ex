defmodule HmacAuth do

  @moduledoc """
  Signs urls or authentication headers for use with AWS requests
  """

  @doc """
  `HmacAuth.sign_url(secret, http_method, url, headers)`

  `secret`: Your secret key

  `http_method`: "GET","POST","PUT","DELETE", etc

  `url`: The AWS url you want to sign

  `headers` (optional. defaults to `Map.new`): The headers that will be used in the request. Used for signing the request.
  For signing, host is the only one required.
  If host is present here, it will override using the host in the url to attempt signing.
  If only the host is needed, then you don't have to supply it and the host from the url will be used.
   """
  def sign_url(secret, http_method, url) do
    sign_url(secret, http_method, url, Map.new)
  end

  def sign_url(secret, http_method, url, headers) do
    sign_url(secret, http_method, url, headers, current_time)
  end

  def sign_url(secret, http_method, url, headers, request_time) do
    sign_url(secret, http_method, url, headers, request_time, "")
  end

  def sign_url(secret, http_method, url, headers, request_time, payload) do
    HmacAuth.QueryParameters.sign(secret, http_method, url, headers, request_time, payload)
  end


  @doc """
  `AWSAuth.sign_authorization_header(access_key, secret_key, http_method, url, region, service, headers, payload)`

  `access_key`: Your AWS Access key

  `secret_key`: Your AWS secret key

  `http_method`: "GET","POST","PUT","DELETE", etc

  `url`: The AWS url you want to sign

  `region`: The AWS name for the region you want to access (i.e. us-east-1). Check [here](http://docs.aws.amazon.com/general/latest/gr/rande.html) for the region names

  `service`: The AWS service you are trying to access (i.e. s3). Check the url above for names as well.

  `headers` (optional. defaults to `Map.new`): The headers that will be used in the request. Used for signing the request.
  For signing, host is the only one required unless using any other x-amx-* headers.
  If host is present here, it will override using the host in the url to attempt signing.
  Same goes for the x-amz-content-sha256 headers
  If only the host and x-amz-content-sha256 headers are needed, then you don't have to supply it and the host from the url will be used and
  the payload will be hashed to get the x-amz-content-sha256 header.

  `payload` (optional. defaults to `""`): The contents of the payload if there is one.
  """
  def sign_authorization_header(secret, http_method, url) do
    sign_authorization_header(secret, http_method, url, Map.new)
  end

  def sign_authorization_header(secret, http_method, url, headers) do
    sign_authorization_header(secret, http_method, url, headers, "")
  end

  def sign_authorization_header(secret, http_method, url, headers, payload) do
    sign_authorization_header(secret, http_method, url, headers, payload, current_time)
  end

  def sign_authorization_header(secret, http_method, url, headers, payload, request_time) do
    HmacAuth.AuthorizationHeader.sign(secret, http_method, url, payload, headers, request_time)
  end

  defp current_time do
    DateTime.utc_now |> DateTime.to_naive
  end
end
