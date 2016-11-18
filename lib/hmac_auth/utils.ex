defmodule HmacAuth.Utils do
  @moduledoc false

  def build_canonical_request(http_method, url, params, headers, hashed_payload) do

    query_params = URI.encode_query(params) |> String.replace("+", "%20")

    header_params = Enum.map(headers, fn({key, value}) -> "#{String.downcase(key)}:#{String.strip(value)}"  end)
    |> Enum.sort(&(&1 < &2))
    |> Enum.join("\n")

    signed_header_params = Enum.map(headers, fn({key, _}) -> String.downcase(key)  end)
    |> Enum.sort(&(&1 < &2))
    |> Enum.join(";")

    hashed_payload = if hashed_payload == :unsigned,
      do: "UNSIGNED-PAYLOAD",
      else: hashed_payload

    "#{http_method}\n#{URI.encode(url) |> String.replace("$", "%24")}\n#{query_params}\n#{header_params}\n\n#{signed_header_params}\n#{hashed_payload}"
  end

  def build_string_to_sign(canonical_request, timestamp) do
    hashed_canonical_request = hash_sha(canonical_request)
    "#{timestamp}\n#{hashed_canonical_request}"
  end

  def build_signing_key(secret, date) do
    hmac_sha(secret, date)
  end

  def build_signature(signing_key, string_to_sign) do
    hmac_sha(signing_key, string_to_sign)
    |> bytes_to_string
  end

  def hash_sha(data) do
    :crypto.hash(:sha, data)
    |> bytes_to_string
  end

  def hmac_sha(key, data) do
    :crypto.hmac(:sha, key, data)
  end

  def bytes_to_string(bytes) do
    Base.encode64(bytes)
  end

  def format_time(time) do
    formatted_time = time
    |> NaiveDateTime.to_iso8601
    |> String.split(".")
    |> List.first
    |> String.replace("-", "")
    |> String.replace(":", "")
    formatted_time <> "Z"
  end

  def format_date(date) do
    date
    |> NaiveDateTime.to_date
    |> Date.to_iso8601
    |> String.replace("-", "")
  end
end
