# based on Mint.Core.Transport.SSL
# https://github.com/elixir-mint/mint/blob/371f4d7bffc26a779ac7675ae75f89d17519bfa9/lib/mint/core/transport/ssl.ex
# and Secure Coding and Deployment Hardening: SSL
# https://erlef.github.io/security-wg/secure_coding_and_deployment_hardening/ssl.html
defmodule Mua.SSL do
  @moduledoc false
  require Record

  # From RFC7540 appendix A
  @blocked_ciphers [
    {:null, :null, :null},
    {:rsa, :null, :md5},
    {:rsa, :null, :sha},
    {:rsa_export, :rc4_40, :md5},
    {:rsa, :rc4_128, :md5},
    {:rsa, :rc4_128, :sha},
    {:rsa_export, :rc2_cbc_40, :md5},
    {:rsa, :idea_cbc, :sha},
    {:rsa_export, :des40_cbc, :sha},
    {:rsa, :des_cbc, :sha},
    {:rsa, :"3des_ede_cbc", :sha},
    {:dh_dss_export, :des40_cbc, :sha},
    {:dh_dss, :des_cbc, :sha},
    {:dh_dss, :"3des_ede_cbc", :sha},
    {:dh_rsa_export, :des40_cbc, :sha},
    {:dh_rsa, :des_cbc, :sha},
    {:dh_rsa, :"3des_ede_cbc", :sha},
    {:dhe_dss_export, :des40_cbc, :sha},
    {:dhe_dss, :des_cbc, :sha},
    {:dhe_dss, :"3des_ede_cbc", :sha},
    {:dhe_rsa_export, :des40_cbc, :sha},
    {:dhe_rsa, :des_cbc, :sha},
    {:dhe_rsa, :"3des_ede_cbc", :sha},
    {:dh_anon_export, :rc4_40, :md5},
    {:dh_anon, :rc4_128, :md5},
    {:dh_anon_export, :des40_cbc, :sha},
    {:dh_anon, :des_cbc, :sha},
    {:dh_anon, :"3des_ede_cbc", :sha},
    {:krb5, :des_cbc, :sha},
    {:krb5, :"3des_ede_cbc", :sha},
    {:krb5, :rc4_128, :sha},
    {:krb5, :idea_cbc, :sha},
    {:krb5, :des_cbc, :md5},
    {:krb5, :"3des_ede_cbc", :md5},
    {:krb5, :rc4_128, :md5},
    {:krb5, :idea_cbc, :md5},
    {:krb5_export, :des_cbc_40, :sha},
    {:krb5_export, :rc2_cbc_40, :sha},
    {:krb5_export, :rc4_40, :sha},
    {:krb5_export, :des_cbc_40, :md5},
    {:krb5_export, :rc2_cbc_40, :md5},
    {:krb5_export, :rc4_40, :md5},
    {:psk, :null, :sha},
    {:dhe_psk, :null, :sha},
    {:rsa_psk, :null, :sha},
    {:rsa, :aes_128_cbc, :sha},
    {:dh_dss, :aes_128_cbc, :sha},
    {:dh_rsa, :aes_128_cbc, :sha},
    {:dhe_dss, :aes_128_cbc, :sha},
    {:dhe_rsa, :aes_128_cbc, :sha},
    {:dh_anon, :aes_128_cbc, :sha},
    {:rsa, :aes_256_cbc, :sha},
    {:dh_dss, :aes_256_cbc, :sha},
    {:dh_rsa, :aes_256_cbc, :sha},
    {:dhe_dss, :aes_256_cbc, :sha},
    {:dhe_rsa, :aes_256_cbc, :sha},
    {:dh_anon, :aes_256_cbc, :sha},
    {:rsa, :null, :sha256},
    {:rsa, :aes_128_cbc, :sha256},
    {:rsa, :aes_256_cbc, :sha256},
    {:dh_dss, :aes_128_cbc, :sha256},
    {:dh_rsa, :aes_128_cbc, :sha256},
    {:dhe_dss, :aes_128_cbc, :sha256},
    {:rsa, :camellia_128_cbc, :sha},
    {:dh_dss, :camellia_128_cbc, :sha},
    {:dh_rsa, :camellia_128_cbc, :sha},
    {:dhe_dss, :camellia_128_cbc, :sha},
    {:dhe_rsa, :camellia_128_cbc, :sha},
    {:dh_anon, :camellia_128_cbc, :sha},
    {:dhe_rsa, :aes_128_cbc, :sha256},
    {:dh_dss, :aes_256_cbc, :sha256},
    {:dh_rsa, :aes_256_cbc, :sha256},
    {:dhe_dss, :aes_256_cbc, :sha256},
    {:dhe_rsa, :aes_256_cbc, :sha256},
    {:dh_anon, :aes_128_cbc, :sha256},
    {:dh_anon, :aes_256_cbc, :sha256},
    {:rsa, :camellia_256_cbc, :sha},
    {:dh_dss, :camellia_256_cbc, :sha},
    {:dh_rsa, :camellia_256_cbc, :sha},
    {:dhe_dss, :camellia_256_cbc, :sha},
    {:dhe_rsa, :camellia_256_cbc, :sha},
    {:dh_anon, :camellia_256_cbc, :sha},
    {:psk, :rc4_128, :sha},
    {:psk, :"3des_ede_cbc", :sha},
    {:psk, :aes_128_cbc, :sha},
    {:psk, :aes_256_cbc, :sha},
    {:dhe_psk, :rc4_128, :sha},
    {:dhe_psk, :"3des_ede_cbc", :sha},
    {:dhe_psk, :aes_128_cbc, :sha},
    {:dhe_psk, :aes_256_cbc, :sha},
    {:rsa_psk, :rc4_128, :sha},
    {:rsa_psk, :"3des_ede_cbc", :sha},
    {:rsa_psk, :aes_128_cbc, :sha},
    {:rsa_psk, :aes_256_cbc, :sha},
    {:rsa, :seed_cbc, :sha},
    {:dh_dss, :seed_cbc, :sha},
    {:dh_rsa, :seed_cbc, :sha},
    {:dhe_dss, :seed_cbc, :sha},
    {:dhe_rsa, :seed_cbc, :sha},
    {:dh_anon, :seed_cbc, :sha},
    {:rsa, :aes_128_gcm, :sha256},
    {:rsa, :aes_256_gcm, :sha384},
    {:dh_rsa, :aes_128_gcm, :sha256},
    {:dh_rsa, :aes_256_gcm, :sha384},
    {:dh_dss, :aes_128_gcm, :sha256},
    {:dh_dss, :aes_256_gcm, :sha384},
    {:dh_anon, :aes_128_gcm, :sha256},
    {:dh_anon, :aes_256_gcm, :sha384},
    {:psk, :aes_128_gcm, :sha256},
    {:psk, :aes_256_gcm, :sha384},
    {:rsa_psk, :aes_128_gcm, :sha256},
    {:rsa_psk, :aes_256_gcm, :sha384},
    {:psk, :aes_128_cbc, :sha256},
    {:psk, :aes_256_cbc, :sha384},
    {:psk, :null, :sha256},
    {:psk, :null, :sha384},
    {:dhe_psk, :aes_128_cbc, :sha256},
    {:dhe_psk, :aes_256_cbc, :sha384},
    {:dhe_psk, :null, :sha256},
    {:dhe_psk, :null, :sha384},
    {:rsa_psk, :aes_128_cbc, :sha256},
    {:rsa_psk, :aes_256_cbc, :sha384},
    {:rsa_psk, :null, :sha256},
    {:rsa_psk, :null, :sha384},
    {:rsa, :camellia_128_cbc, :sha256},
    {:dh_dss, :camellia_128_cbc, :sha256},
    {:dh_rsa, :camellia_128_cbc, :sha256},
    {:dhe_dss, :camellia_128_cbc, :sha256},
    {:dhe_rsa, :camellia_128_cbc, :sha256},
    {:dh_anon, :camellia_128_cbc, :sha256},
    {:rsa, :camellia_256_cbc, :sha256},
    {:dh_dss, :camellia_256_cbc, :sha256},
    {:dh_rsa, :camellia_256_cbc, :sha256},
    {:dhe_dss, :camellia_256_cbc, :sha256},
    {:dhe_rsa, :camellia_256_cbc, :sha256},
    {:dh_anon, :camellia_256_cbc, :sha256},
    {:ecdh_ecdsa, :null, :sha},
    {:ecdh_ecdsa, :rc4_128, :sha},
    {:ecdh_ecdsa, :"3des_ede_cbc", :sha},
    {:ecdh_ecdsa, :aes_128_cbc, :sha},
    {:ecdh_ecdsa, :aes_256_cbc, :sha},
    {:ecdhe_ecdsa, :null, :sha},
    {:ecdhe_ecdsa, :rc4_128, :sha},
    {:ecdhe_ecdsa, :"3des_ede_cbc", :sha},
    {:ecdhe_ecdsa, :aes_128_cbc, :sha},
    {:ecdhe_ecdsa, :aes_256_cbc, :sha},
    {:ecdh_rsa, :null, :sha},
    {:ecdh_rsa, :rc4_128, :sha},
    {:ecdh_rsa, :"3des_ede_cbc", :sha},
    {:ecdh_rsa, :aes_128_cbc, :sha},
    {:ecdh_rsa, :aes_256_cbc, :sha},
    {:ecdhe_rsa, :null, :sha},
    {:ecdhe_rsa, :rc4_128, :sha},
    {:ecdhe_rsa, :"3des_ede_cbc", :sha},
    {:ecdhe_rsa, :aes_128_cbc, :sha},
    {:ecdhe_rsa, :aes_256_cbc, :sha},
    {:ecdh_anon, :null, :sha},
    {:ecdh_anon, :rc4_128, :sha},
    {:ecdh_anon, :"3des_ede_cbc", :sha},
    {:ecdh_anon, :aes_128_cbc, :sha},
    {:ecdh_anon, :aes_256_cbc, :sha},
    {:srp_sha, :"3des_ede_cbc", :sha},
    {:srp_sha_rsa, :"3des_ede_cbc", :sha},
    {:srp_sha_dss, :"3des_ede_cbc", :sha},
    {:srp_sha, :aes_128_cbc, :sha},
    {:srp_sha_rsa, :aes_128_cbc, :sha},
    {:srp_sha_dss, :aes_128_cbc, :sha},
    {:srp_sha, :aes_256_cbc, :sha},
    {:srp_sha_rsa, :aes_256_cbc, :sha},
    {:srp_sha_dss, :aes_256_cbc, :sha},
    {:ecdhe_ecdsa, :aes_128_cbc, :sha256},
    {:ecdhe_ecdsa, :aes_256_cbc, :sha384},
    {:ecdh_ecdsa, :aes_128_cbc, :sha256},
    {:ecdh_ecdsa, :aes_256_cbc, :sha384},
    {:ecdhe_rsa, :aes_128_cbc, :sha256},
    {:ecdhe_rsa, :aes_256_cbc, :sha384},
    {:ecdh_rsa, :aes_128_cbc, :sha256},
    {:ecdh_rsa, :aes_256_cbc, :sha384},
    {:ecdh_ecdsa, :aes_128_gcm, :sha256},
    {:ecdh_ecdsa, :aes_256_gcm, :sha384},
    {:ecdh_rsa, :aes_128_gcm, :sha256},
    {:ecdh_rsa, :aes_256_gcm, :sha384},
    {:ecdhe_psk, :rc4_128, :sha},
    {:ecdhe_psk, :"3des_ede_cbc", :sha},
    {:ecdhe_psk, :aes_128_cbc, :sha},
    {:ecdhe_psk, :aes_256_cbc, :sha},
    {:ecdhe_psk, :aes_128_cbc, :sha256},
    {:ecdhe_psk, :aes_256_cbc, :sha384},
    {:ecdhe_psk, :null, :sha},
    {:ecdhe_psk, :null, :sha256},
    {:ecdhe_psk, :null, :sha384},
    {:rsa, :aria_128_cbc, :sha256},
    {:rsa, :aria_256_cbc, :sha384},
    {:dh_dss, :aria_128_cbc, :sha256},
    {:dh_dss, :aria_256_cbc, :sha384},
    {:dh_rsa, :aria_128_cbc, :sha256},
    {:dh_rsa, :aria_256_cbc, :sha384},
    {:dhe_dss, :aria_128_cbc, :sha256},
    {:dhe_dss, :aria_256_cbc, :sha384},
    {:dhe_rsa, :aria_128_cbc, :sha256},
    {:dhe_rsa, :aria_256_cbc, :sha384},
    {:dh_anon, :aria_128_cbc, :sha256},
    {:dh_anon, :aria_256_cbc, :sha384},
    {:ecdhe_ecdsa, :aria_128_cbc, :sha256},
    {:ecdhe_ecdsa, :aria_256_cbc, :sha384},
    {:ecdh_ecdsa, :aria_128_cbc, :sha256},
    {:ecdh_ecdsa, :aria_256_cbc, :sha384},
    {:ecdhe_rsa, :aria_128_cbc, :sha256},
    {:ecdhe_rsa, :aria_256_cbc, :sha384},
    {:ecdh_rsa, :aria_128_cbc, :sha256},
    {:ecdh_rsa, :aria_256_cbc, :sha384},
    {:rsa, :aria_128_gcm, :sha256},
    {:rsa, :aria_256_gcm, :sha384},
    {:dh_rsa, :aria_128_gcm, :sha256},
    {:dh_rsa, :aria_256_gcm, :sha384},
    {:dh_dss, :aria_128_gcm, :sha256},
    {:dh_dss, :aria_256_gcm, :sha384},
    {:dh_anon, :aria_128_gcm, :sha256},
    {:dh_anon, :aria_256_gcm, :sha384},
    {:ecdh_ecdsa, :aria_128_gcm, :sha256},
    {:ecdh_ecdsa, :aria_256_gcm, :sha384},
    {:ecdh_rsa, :aria_128_gcm, :sha256},
    {:ecdh_rsa, :aria_256_gcm, :sha384},
    {:psk, :aria_128_cbc, :sha256},
    {:psk, :aria_256_cbc, :sha384},
    {:dhe_psk, :aria_128_cbc, :sha256},
    {:dhe_psk, :aria_256_cbc, :sha384},
    {:rsa_psk, :aria_128_cbc, :sha256},
    {:rsa_psk, :aria_256_cbc, :sha384},
    {:psk, :aria_128_gcm, :sha256},
    {:psk, :aria_256_gcm, :sha384},
    {:rsa_psk, :aria_128_gcm, :sha256},
    {:rsa_psk, :aria_256_gcm, :sha384},
    {:ecdhe_psk, :aria_128_cbc, :sha256},
    {:ecdhe_psk, :aria_256_cbc, :sha384},
    {:ecdhe_ecdsa, :camellia_128_cbc, :sha256},
    {:ecdhe_ecdsa, :camellia_256_cbc, :sha384},
    {:ecdh_ecdsa, :camellia_128_cbc, :sha256},
    {:ecdh_ecdsa, :camellia_256_cbc, :sha384},
    {:ecdhe_rsa, :camellia_128_cbc, :sha256},
    {:ecdhe_rsa, :camellia_256_cbc, :sha384},
    {:ecdh_rsa, :camellia_128_cbc, :sha256},
    {:ecdh_rsa, :camellia_256_cbc, :sha384},
    {:rsa, :camellia_128_gcm, :sha256},
    {:rsa, :camellia_256_gcm, :sha384},
    {:dh_rsa, :camellia_128_gcm, :sha256},
    {:dh_rsa, :camellia_256_gcm, :sha384},
    {:dh_dss, :camellia_128_gcm, :sha256},
    {:dh_dss, :camellia_256_gcm, :sha384},
    {:dh_anon, :camellia_128_gcm, :sha256},
    {:dh_anon, :camellia_256_gcm, :sha384},
    {:ecdh_ecdsa, :camellia_128_gcm, :sha256},
    {:ecdh_ecdsa, :camellia_256_gcm, :sha384},
    {:ecdh_rsa, :camellia_128_gcm, :sha256},
    {:ecdh_rsa, :camellia_256_gcm, :sha384},
    {:psk, :camellia_128_gcm, :sha256},
    {:psk, :camellia_256_gcm, :sha384},
    {:rsa_psk, :camellia_128_gcm, :sha256},
    {:rsa_psk, :camellia_256_gcm, :sha384},
    {:psk, :camellia_128_cbc, :sha256},
    {:psk, :camellia_256_cbc, :sha384},
    {:dhe_psk, :camellia_128_cbc, :sha256},
    {:dhe_psk, :camellia_256_cbc, :sha384},
    {:rsa_psk, :camellia_128_cbc, :sha256},
    {:rsa_psk, :camellia_256_cbc, :sha384},
    {:ecdhe_psk, :camellia_128_cbc, :sha256},
    {:ecdhe_psk, :camellia_256_cbc, :sha384},
    {:rsa, :aes_128, :ccm},
    {:rsa, :aes_256, :ccm},
    {:rsa, :aes_128, :ccm_8},
    {:rsa, :aes_256, :ccm_8},
    {:psk, :aes_128, :ccm},
    {:psk, :aes_256, :ccm},
    {:psk, :aes_128, :ccm_8},
    {:psk, :aes_256, :ccm_8}
  ]

  @default_versions [:"tlsv1.3", :"tlsv1.2"]

  Record.defrecordp(
    :certificate,
    :Certificate,
    Record.extract(:Certificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecordp(
    :tbs_certificate,
    :OTPTBSCertificate,
    Record.extract(:OTPTBSCertificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  def opts(address, opts \\ []) do
    hostname(address, opts)
    |> default_opts()
    |> Keyword.merge(opts)
    |> Keyword.drop([:timeout])
    |> add_verify_opts()
    |> remove_incompatible_opts()
    |> add_ciphers_opt()
  end

  defp hostname(address, opts) when is_list(opts) do
    case Keyword.fetch(opts, :hostname) do
      {:ok, hostname} ->
        hostname

      :error when is_binary(address) ->
        address

      :error ->
        raise ArgumentError, "the :hostname option is required when address is not a binary"
    end
  end

  defp add_verify_opts(opts) do
    verify = Keyword.get(opts, :verify)

    if verify == :verify_peer do
      opts
      |> add_cacerts()
      |> add_partial_chain_fun()
      |> add_customize_hostname_check()
    else
      opts
    end
  end

  defp remove_incompatible_opts(opts) do
    # These are the TLS versions that are compatible with :reuse_sessions and :secure_renegotiate
    # If none of the compatible TLS versions are present in the transport options, then
    # :reuse_sessions and :secure_renegotiate will be removed from the transport options.
    compatible_versions = [:tlsv1, :"tlsv1.1", :"tlsv1.2"]
    versions_opt = Keyword.get(opts, :versions, [])

    if Enum.any?(compatible_versions, &(&1 in versions_opt)) do
      opts
    else
      opts
      |> Keyword.delete(:reuse_sessions)
      |> Keyword.delete(:secure_renegotiate)
    end
  end

  defp add_customize_hostname_check(opts) do
    match_fun = :public_key.pkix_verify_hostname_match_fun(:https)
    Keyword.put_new(opts, :customize_hostname_check, match_fun: match_fun)
  end

  defp add_ciphers_opt(opts) do
    Keyword.put_new_lazy(opts, :ciphers, fn ->
      versions = opts[:versions]
      get_ciphers_for_versions(versions)
    end)
  end

  defp default_opts(hostname) do
    # TODO: Add revocation check

    # Note: the :ciphers option is added once the :versions option
    # has been merged with the user-specified value
    [
      server_name_indication: String.to_charlist(hostname),
      versions: versions(),
      verify: :verify_peer,
      depth: 4,
      secure_renegotiate: true,
      reuse_sessions: true
    ]
  end

  ssl_version =
    Application.spec(:ssl, :vsn)
    |> List.to_string()
    |> String.split(".")
    |> Enum.map(&String.to_integer/1)

  @doc false
  if ssl_version < [10, 0] do
    def versions do
      available_versions = :ssl.versions()[:available]
      versions = Enum.filter(@default_versions, &(&1 in available_versions))
      # Remove buggy TLS 1.3 versions
      versions -- [:"tlsv1.3"]
    end
  else
    def versions do
      available_versions = :ssl.versions()[:available]
      Enum.filter(@default_versions, &(&1 in available_versions))
    end
  end

  defp add_cacerts(opts) do
    if Keyword.has_key?(opts, :cacertfile) or Keyword.has_key?(opts, :cacerts) do
      opts
    else
      try do
        Keyword.put(opts, :cacerts, :public_key.cacerts_get())
      rescue
        _ ->
          raise_on_missing_castore!()
          Keyword.put(opts, :cacertfile, CAStore.file_path())
      end
    end
  end

  defp add_partial_chain_fun(opts) do
    if Keyword.has_key?(opts, :partial_chain) do
      opts
    else
      case Keyword.fetch(opts, :cacerts) do
        {:ok, cacerts} ->
          cacerts = decode_cacerts(cacerts)
          fun = &partial_chain(cacerts, &1)
          Keyword.put(opts, :partial_chain, fun)

        :error ->
          path = Keyword.fetch!(opts, :cacertfile)
          cacerts = get_cacertfile(path)
          fun = &partial_chain(cacerts, &1)
          Keyword.put(opts, :partial_chain, fun)
      end
    end
  end

  defp get_cacertfile(path) do
    if Application.get_env(:mua, :persistent_term) do
      case :persistent_term.get({:mua, {:cacertfile, path}}, :error) do
        {:ok, cacerts} ->
          cacerts

        :error ->
          cacerts = decode_cacertfile(path)
          :persistent_term.put({:mua, {:cacertfile, path}}, {:ok, cacerts})
          cacerts
      end
    else
      decode_cacertfile(path)
    end
  end

  defp decode_cacertfile(path) do
    File.read!(path)
    |> :public_key.pem_decode()
    |> Enum.filter(&match?(certificate(signature: :not_encrypted), &1))
    |> Enum.map(&:public_key.pem_entry_decode/1)
  end

  defp decode_cacerts(certs) do
    Enum.map(certs, fn
      cert when is_binary(cert) -> :public_key.pkix_decode_cert(cert, :plain)
      {:cert, _, otp_certificate} -> otp_certificate
    end)
  end

  def partial_chain(cacerts, certs) do
    # TODO: Shim this with OTP 21.1 implementation?

    certs =
      certs
      |> Enum.map(&{&1, :public_key.pkix_decode_cert(&1, :plain)})
      |> Enum.drop_while(&cert_expired?/1)

    trusted =
      Enum.find_value(certs, fn {der, cert} ->
        trusted? =
          Enum.find(cacerts, fn cacert ->
            extract_public_key_info(cacert) == extract_public_key_info(cert)
          end)

        if trusted?, do: der
      end)

    if trusted do
      {:trusted_ca, trusted}
    else
      :unknown_ca
    end
  end

  defp cert_expired?({_der, cert}) do
    now = DateTime.utc_now()
    {not_before, not_after} = extract_validity(cert)

    DateTime.compare(now, not_before) == :lt or
      DateTime.compare(now, not_after) == :gt
  end

  defp extract_validity(cert) do
    {:Validity, not_before, not_after} =
      cert
      |> certificate(:tbsCertificate)
      |> tbs_certificate(:validity)

    {to_datetime!(not_before), to_datetime!(not_after)}
  end

  defp extract_public_key_info(cert) do
    cert
    |> certificate(:tbsCertificate)
    |> tbs_certificate(:subjectPublicKeyInfo)
  end

  defp to_datetime!({:utcTime, time}) do
    "20#{time}"
    |> to_datetime!()
  end

  defp to_datetime!({:generalTime, time}) do
    time
    |> to_string()
    |> to_datetime!()
  end

  defp to_datetime!(
         <<year::binary-size(4), month::binary-size(2), day::binary-size(2), hour::binary-size(2),
           minute::binary-size(2), second::binary-size(2), "Z"::binary>>
       ) do
    {:ok, datetime, _} =
      DateTime.from_iso8601("#{year}-#{month}-#{day}T#{hour}:#{minute}:#{second}Z")

    datetime
  end

  @doc false
  def blocked_cipher?(%{key_exchange: kex, cipher: cipher, prf: prf}) do
    blocked_cipher?(kex, cipher, prf)
  end

  def blocked_cipher?({kex, cipher, _mac, prf}), do: blocked_cipher?(kex, cipher, prf)
  def blocked_cipher?({kex, cipher, prf}), do: blocked_cipher?(kex, cipher, prf)

  for {kex, cipher, prf} <- @blocked_ciphers do
    defp blocked_cipher?(unquote(kex), unquote(cipher), unquote(prf)), do: true
  end

  defp blocked_cipher?(_kex, _cipher, _prf), do: false

  defp raise_on_missing_castore! do
    Code.ensure_loaded?(CAStore) ||
      raise """
      default CA trust store not available; please add `:castore` to your project's \
      dependencies or specify the trust store using the :cacertfile/:cacerts option \
      within :ssl options list. From OTP 25, you can also use:

        * :public_key.cacerts_get/0 to get certificates that you loaded from files or
        * from the OS with :public_key.cacerts_load/0,1

      See: https://www.erlang.org/blog/my-otp-25-highlights/#ca-certificates-can-be-fetched-from-the-os-standard-place
      """
  end

  @doc false
  def get_ciphers_for_versions(versions) do
    versions
    |> Enum.flat_map(&:ssl.filter_cipher_suites(:ssl.cipher_suites(:all, &1), []))
    |> Enum.uniq()
    |> Enum.reject(&__MODULE__.blocked_cipher?/1)
  end
end
