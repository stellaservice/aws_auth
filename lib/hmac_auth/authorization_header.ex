defmodule HmacAuth.AuthorizationHeader do
  @moduledoc false

  def sign(secret_key, http_method, url, payload, headers, request_time) do
    uri = URI.parse(url)

    params = case uri.query do
               nil ->
                 Map.new
               _ ->
                 URI.decode_query(uri.query)
             end

    http_method = String.upcase(http_method)
    headers = Map.put_new(headers, "host", uri.host)

    payload = case payload do
      "" -> ""
      _ -> HmacAuth.Utils.hash_sha(payload)
    end

    headers = Map.put_new(headers, "Authorization", payload)

    amz_date = request_time |> HmacAuth.Utils.format_time
    date = request_time |> HmacAuth.Utils.format_date

    string_to_sign = HmacAuth.Utils.build_canonical_request(http_method, uri.path || "/", params, headers, payload)
    |>  HmacAuth.Utils.build_string_to_sign(amz_date)

    signature = HmacAuth.Utils.build_signing_key(secret_key, date)
    |>  HmacAuth.Utils.build_signature(string_to_sign)

    signed_headers = Enum.map(headers, fn({key, _}) -> String.downcase(key)  end)
    |> Enum.sort(&(&1 < &2))
    |> Enum.join(";")

    "Authorization=#{signed_headers},Signature=#{signature}"
  end
end
