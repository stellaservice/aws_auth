defmodule HmacAuthTest do
  use ExUnit.Case

  @time ~N[2013-05-24 01:23:45]

  test "url signing" do
    signed_request = HmacAuth.sign_url("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "GET",
      "https://examplebucket.s3.amazonaws.com/test.txt",
      Map.new,
      @time) |> URI.parse

    assert signed_request.host == "examplebucket.s3.amazonaws.com"
    assert signed_request.scheme == "https"
    assert signed_request.path == "/test.txt"

    expected_query_parts = [
      {"Date", "20130524T012345Z"},
    ]

    query_parts = URI.query_decoder(signed_request.query) |> Enum.to_list
    assert query_parts == expected_query_parts
  end

  test "sign_authorization_header PUT" do
    headers = Map.new
    |> Map.put("Date", "Fri, 24 May 2013 00:00:00 GMT")

    signed_request = HmacAuth.sign_authorization_header("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "PUT",
      "https://examplebucket.s3.amazonaws.com/test$file.text",
      headers,
      "Welcome to Amazon S3.",
      @time)

    request_parts = signed_request

    request_parts = String.split(request_parts, ",") |> Enum.map(&(String.split(&1, "=")))
    assert request_parts == [
      ["Credential", "AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request"],
      ["SignedHeaders", "date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class"],
      ["Signature", "cb26a806062d11d1ba2debc79cfebbe2bae32c39f039cbb4f7df09e9450c9caa"]
    ]
  end

  test "sign_query_parameters_request_with_multiple_headers" do
    headers = Map.new
    |> Map.put("x-amz-acl", "public-read")

    signed_request = HmacAuth.sign_url("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "PUT",
      "https://examplebucket.s3.amazonaws.com/test.txt",
      headers,
      @time) |> URI.parse

    assert signed_request.host == "examplebucket.s3.amazonaws.com"
    assert signed_request.scheme == "https"
    assert signed_request.path == "/test.txt"

    expected_query_parts = [
      {"Date", "20130524T012345Z"},
    ]

    query_parts = URI.query_decoder(signed_request.query) |> Enum.to_list
    assert query_parts == expected_query_parts
  end
end
