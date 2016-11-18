defmodule HmacAuth.QueryParameters do
  @moduledoc false

  #http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
  def sign(secret, http_method, url, headers, request_time, payload) do
    uri = URI.parse(url)

    http_method = String.upcase(http_method)

    headers = Map.put_new(headers, "host", uri.host)

    datetime = request_time |> HmacAuth.Utils.format_time
    date = request_time |> HmacAuth.Utils.format_date

    params = case uri.query do
               nil ->
                 Map.new
               _ ->
                 URI.decode_query(uri.query)
             end

    params = params
    |> Map.put("Date", datetime)

    hashed_payload = HmacAuth.Utils.hash_sha(payload)

    string_to_sign = HmacAuth.Utils.build_canonical_request(http_method, uri.path, params, headers, hashed_payload)
    |> HmacAuth.Utils.build_string_to_sign(datetime)

    signature = HmacAuth.Utils.build_signing_key(secret, date)
    |> HmacAuth.Utils.build_signature(string_to_sign)

    params = params |> Map.put("X-Amz-Signature", signature)
    query_string = URI.encode_query(params) |> String.replace("+", "%20")

    "#{uri.scheme}://#{uri.authority}#{uri.path || "/"}?#{query_string}"
  end
end
