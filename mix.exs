defmodule AWSAuth.Mixfile do
  use Mix.Project

  def project do
    [app: :hmac_auth,
     version: "0.1.0",
     elixir: "~> 1.3",
     description: description,
     package: package,
     deps: deps,
     test_coverage: [tool: ExCoveralls],
     preferred_cli_env: [coveralls: :test]
    ]
  end

  def application do
    [applications: [:logger]]
  end

  defp deps do
    [
      {:earmark, "~> 0.2", only: :dev },
      {:ex_doc, "~> 0.11", only: :dev },
      {:excoveralls, "~> 0.4", only: :test},
      {:credo, "~> 0.2.0", only: [:dev, :test]}
    ]
  end

  defp description do
    """
    General HMAC SHA1 signature calculation based on aws_auth library
    """
  end

  defp package do
    [
     files: ["lib", "mix.exs", "README*"],
     maintainers: ["Bryan Glusman"],
     licenses: ["Apache 2.0"],
     links: %{"GitHub" => "https://github.com/stellaservice/hmac_auth"}
    ]
  end
end
