defmodule Mua do
  @moduledoc """
  Minimal SMTP client.
  """

  import Kernel, except: [send: 2]

  @dialyzer :no_improper_lists

  @type host :: :inet.socket_address() | :inet.hostname() | String.t()
  @type socket :: :gen_tcp.socket() | :ssl.sslsocket()
  @type error :: {:error, Mua.SMTPError.t() | Mua.TransportError.t()}
  @type auth_method :: :login | :plain
  @type auth_credentials :: [username: String.t(), password: String.t()]
  @type option ::
          {:timeout, timeout}
          | {:mx, boolean}
          | {:protocol, :tcp | :ssl}
          | {:auth, auth_credentials}
          | {:port, :inet.port_number()}
          | {:tcp, [:gen_tcp.connect_option()]}
          | {:ssl, [:ssl.tls_client_option()]}

  @default_timeout :timer.seconds(30)

  @doc """
  Utility function to lookup MX servers for a domain.

      ["gmail-smtp-in.l.google.com" | _rest] = mxlookup("gmail.com")

  """
  @spec mxlookup(String.t()) :: [String.t()]
  def mxlookup(domain) when is_binary(domain) do
    # TODO need it?
    # case :lists.keyfind(:nameserver, 1, :inet_db.get_rc()) do
    #   false ->
    #     # we got no nameservers configured, suck in resolv.conf
    #     :inet_config.do_load_resolv(:os.type(), :longnames)
    #   _ ->
    #     :ok
    # end

    :inet_res.lookup(to_charlist(domain), :in, :mx)
    |> :lists.sort()
    |> Enum.map(fn {_, host} -> List.to_string(host) end)
  end

  @doc """
  Utility function to send a message to a list of recipients on a host.

      # sending via a relay
      {:ok, _receipt} =
        easy_send(
          _host = "icloud.com",
          _sender = "ruslandoga+mua@icloud.com",
          _recipients = ["support@gmail.com"],
          _message = "Date: Sat, 24 Jun 2023 13:43:57 +0000\\r\\n...",
          auth: [username: "ruslandoga+mua@icloud.com", password: "some-app-password"],
          port: 587
        )

      # sending directly (usually requires SPF/DKIM/DMARC on the sender domain)
      {:ok, _receipt} =
        easy_send(
          _host = "gmail.com",
          _sender = "ruslandoga+mua@domain.com",
          _recipients = ["support@gmail.com"],
          _message = "Date: Sat, 24 Jun 2023 13:43:57 +0000\\r\\n...",
          port: 25
        )

  """
  @spec easy_send(String.t() | :inet.ip_address(), String.t(), [String.t()], iodata, [option]) ::
          {:ok, receipt :: String.t()} | error
  def easy_send(host, sender, recipients, message, opts \\ []) do
    [_, sender_hostname] = String.split(sender, "@")

    hosts =
      if opts[:mx] do
        with [] <- mxlookup(host), do: [host]
      else
        [host]
      end

    easy_send_any(hosts, sender_hostname, sender, recipients, message, opts)
  end

  defp easy_send_any([host | hosts], helo, sender, recipients, message, opts) do
    case easy_send_one(host, helo, sender, recipients, message, opts) do
      {:ok, _receipt} = ok ->
        ok

      {:error, %Mua.SMTPError{code: code}}
      when hosts != [] and code in [421, 450, 451, 452] ->
        easy_send_any(hosts, helo, sender, recipients, message, opts)

      # other smtp errors are not retriable
      {:error, %Mua.SMTPError{}} = error ->
        error

      # transport errors can be retried
      {:error, %Mua.TransportError{}} when hosts != [] ->
        easy_send_any(hosts, helo, sender, recipients, message, opts)

      # if there are no more hosts to try, we return the error
      {:error, %Mua.TransportError{}} = error ->
        error
    end
  end

  # TODO build %Mua.Result{} with what has happened on the connection (tls or not, etc.)

  defp easy_send_one(host, helo, sender, recipients, message, opts) do
    port = opts[:port] || 25
    proto = opts[:protocol] || :tcp
    timeout = opts[:timeout] || @default_timeout

    tcp_opts = opts[:tcp] || []
    ssl_opts = opts[:ssl] || []

    sock_opts =
      case proto do
        :ssl -> tcp_opts ++ ssl_opts
        :tcp -> tcp_opts
      end

    auth_creds = opts[:auth]

    with {:ok, socket, _banner} <- connect(proto, host, port, sock_opts, timeout) do
      try do
        with {:ok, extensions} <- ehlo_or_helo(socket, helo, timeout),
             {:ok, socket} <- maybe_starttls(socket, extensions, host, ssl_opts, timeout),
             {:ok, extensions} <- ehlo_or_helo(socket, helo, timeout),
             :ok <- maybe_auth(extensions, socket, auth_creds, timeout),
             :ok <- mail_from(socket, sender, timeout),
             :ok <- many_rcpt_to(recipients, socket, timeout),
             {:ok, _receipt} = ok <- data(socket, message, timeout) do
          _ = quit(socket, timeout)
          ok
        end
      after
        close(socket)
      end
    end
  end

  defp many_rcpt_to([address | addresses], socket, timeout) do
    with :ok <- rcpt_to(socket, address, timeout), do: many_rcpt_to(addresses, socket, timeout)
  end

  defp many_rcpt_to([], _socket, _timeout), do: :ok

  @spec ehlo_or_helo(socket, String.t(), timeout) :: {:ok, [String.t()]} | error
  defp ehlo_or_helo(socket, hostname, timeout) do
    with {:error, %Mua.SMTPError{code: 500}} <- ehlo(socket, hostname, timeout),
         :ok <- helo(socket, hostname, timeout),
         do: {:ok, []}
  end

  @spec maybe_starttls(socket, [String.t()], String.t(), [:ssl.tls_client_option()], timeout) ::
          {:ok, socket} | error
  defp maybe_starttls(socket, extensions, host, opts, timeout) do
    if is_port(socket) and "STARTTLS" in extensions do
      starttls(socket, host, opts, timeout)
    else
      {:ok, socket}
    end
  end

  @spec maybe_auth([String.t()], socket, keyword | nil, timeout) :: :ok | error
  defp maybe_auth(_extensions, _socket, _no_auth = nil, _timeout), do: :ok

  defp maybe_auth(extensions, socket, auth_creds, timeout) do
    method = pick_auth_method(extensions) || :plain
    auth(socket, method, auth_creds, timeout)
  end

  @doc """
  Connects to an SMTP server and receives its banner.

      {:ok, socket, _banner} = connect(:tcp, host, _port = 25)
      {:ok, socket, _banner} = connect(:ssl, host, _port = 465, versions: [:"tlsv1.3"])

  """
  @spec connect(:tcp, host, :inet.port_number(), [:gen_tcp.connect_option()], timeout) ::
          {:ok, :gen_tcp.socket(), banner :: String.t()} | error
  @spec connect(:ssl, host, :inet.port_number(), [:ssl.tls_client_option()], timeout) ::
          {:ok, :ssl.sslsocket(), banner :: String.t()} | error
  def connect(protocol, address, port, opts \\ [], timeout \\ @default_timeout) do
    opts = Keyword.drop(opts, [:timeout, :mode, :active, :packet])
    opts = [{:mode, :binary}, {:active, false}, {:packet, :line} | opts]

    inet_address =
      case address do
        _ when is_binary(address) -> String.to_charlist(address)
        _ -> address
      end

    connect_result =
      case protocol do
        :tcp -> :gen_tcp.connect(inet_address, port, opts, timeout)
        :ssl -> :ssl.connect(inet_address, port, Mua.SSL.opts(address, opts), timeout)
      end

    with {:ok, socket} <- connect_result,
         {:ok, received} <- recv_all(socket, timeout) do
      case received do
        [220 | lines] ->
          {:ok, socket, IO.iodata_to_binary(lines)}

        [code | lines] ->
          :ok = close(socket)
          smtp_error(code, lines)
      end
    else
      {:error, reason} -> transport_error(reason)
    end
  end

  @doc """
  Closes connection to the SMTP server.

      :ok = close(socket)

  """
  @spec close(socket) :: :ok | {:error, Mua.TransportError.t()}
  def close(socket) when is_port(socket), do: :gen_tcp.close(socket)

  def close(socket) do
    case :ssl.close(socket) do
      :ok = ok -> ok
      {:error, reason} -> transport_error(reason)
    end
  end

  @doc """
  Sends `EHLO` command which provides the identification of the sender i.e. the host name,
  and receives the list of extensions the server supports.

      {:ok, _extensions = ["STARTTLS" | _rest]} = ehlo(socket, _our_hostname = "icloud.com")

  """
  @spec ehlo(socket, String.t(), timeout) :: {:ok, [String.t()]} | error
  def ehlo(socket, hostname, timeout \\ @default_timeout) when is_binary(hostname) do
    with {:ok, response} <- request(socket, ["EHLO ", hostname | "\r\n"], timeout) do
      case response do
        [250, _greeting | extensions] -> {:ok, Enum.map(extensions, &__MODULE__.trim_extension/1)}
        [code | lines] -> smtp_error(code, lines)
      end
    end
  end

  @doc false
  if Version.compare(System.version(), "1.14.0") in [:eq, :gt] do
    def trim_extension(<<_::4-bytes, line::bytes>>) do
      size = byte_size(line)

      case line do
        <<extension::size(size - 2)-bytes, "\r\n">> -> extension
        <<extension::size(size - 1)-bytes, ?\n>> -> extension
        <<extension::size(size - 1)-bytes, ?\r>> -> extension
      end
    end
  else
    def trim_extension(<<_::4-bytes, line::bytes>>) do
      size = byte_size(line)
      size_2 = size - 2
      size_1 = size - 1

      case line do
        <<extension::size(size_2)-bytes, "\r\n">> -> extension
        <<extension::size(size_1)-bytes, ?\n>> -> extension
        <<extension::size(size_1)-bytes, ?\r>> -> extension
      end
    end
  end

  @doc """
  Sends `HELO` command which provides the identification of the sender i.e. the host name.

      :ok = helo(socket, _our_hostname = "icloud.com")

  """
  @spec helo(socket, String.t(), timeout) :: :ok | error
  def helo(socket, hostname, timeout \\ @default_timeout) when is_binary(hostname) do
    with {:ok, response} <- request(socket, ["HELO ", hostname | "\r\n"], timeout) do
      case response do
        [250 | _lines] -> :ok
        [code | lines] -> smtp_error(code, lines)
      end
    end
  end

  @doc """
  Sends `STARTTLS` extension command and starts TLS session negotiation.

      {:ok, sslsocket} = starttls(socket, host, versions: [:"tlsv1.3"], middlebox_comp_mode: false)

  """
  @spec starttls(:ssl.socket(), host, [:ssl.tls_client_option()], timeout) ::
          {:ok, :ssl.sslsocket()} | error
  def starttls(socket, address, opts \\ [], timeout \\ @default_timeout) when is_port(socket) do
    with {:ok, response} <- request(socket, "STARTTLS\r\n", timeout) do
      case response do
        [220 | _lines] ->
          with :ok <- :inet.setopts(socket, active: false),
               {:ok, _socket} = ok <- :ssl.connect(socket, Mua.SSL.opts(address, opts), timeout) do
            ok
          else
            {:error, reason} -> transport_error(reason)
          end

        [code | lines] ->
          smtp_error(code, lines)
      end
    end
  end

  @doc """
  Utility function to pick a supported auth method from a list of extensions.

      {:ok, extensions} = ehlo(socket, hostname)
      maybe_method = pick_auth_method(extensions)
      true = maybe_method in [nil, :plain, :login]

  """
  @spec pick_auth_method([String.t()]) :: auth_method | nil
  def pick_auth_method(extensions) when is_list(extensions) do
    auth_extension = Enum.find(extensions, &String.starts_with?(&1, "AUTH "))

    if auth_extension do
      ["AUTH" | methods] = String.split(auth_extension)

      Enum.find_value(methods, fn method ->
        case String.upcase(method) do
          "PLAIN" -> :plain
          "LOGIN" -> :login
          _other -> nil
        end
      end)
    end
  end

  @doc """
  Sends `AUTH` extension command and authenticates the sender.

      :ok = auth(socket, :login, username: username, password: password)
      :ok = auth(socket, :plain, username: username, password: password)

  """
  @spec auth(socket, auth_method, auth_credentials, timeout) :: :ok | error
  def auth(socket, kind, opts \\ [], timeout \\ @default_timeout)

  def auth(socket, :login, opts, timeout) do
    username = Keyword.fetch!(opts, :username)
    password = Keyword.fetch!(opts, :password)
    username64 = [Base.encode64(username) | "\r\n"]
    password64 = [Base.encode64(password) | "\r\n"]

    with {:ok, [334, "334 VXNlcm5hbWU6\r\n"]} <- request(socket, "AUTH LOGIN\r\n", timeout),
         {:ok, [334, "334 UGFzc3dvcmQ6\r\n"]} <- request(socket, username64, timeout),
         {:ok, [235 | _lines]} <- request(socket, password64, timeout) do
      :ok
    else
      {:ok, [code | lines]} -> smtp_error(code, lines)
      {:error, _reason} = error -> error
    end
  end

  def auth(socket, :plain, opts, timeout) do
    username = Keyword.fetch!(opts, :username)
    password = Keyword.fetch!(opts, :password)

    cmd = ["AUTH PLAIN ", Base.encode64(<<0, username::bytes, 0, password::bytes>>) | "\r\n"]

    with {:ok, response} <- request(socket, cmd, timeout) do
      case response do
        [235 | _lines] -> :ok
        [code | lines] -> smtp_error(code, lines)
      end
    end
  end

  @doc """
  Sends `MAIL FROM` command that specifies the originator of the mail.

      :ok = mail_from(socket, "ruslandoga+mua@icloud.com")

  """
  @spec mail_from(socket, String.t(), timeout) :: :ok | error
  def mail_from(socket, address, timeout \\ @default_timeout) do
    with {:ok, response} <- request(socket, ["MAIL FROM: ", quoteaddr(address) | "\r\n"], timeout) do
      case response do
        [250 | _lines] -> :ok
        [code | lines] -> smtp_error(code, lines)
      end
    end
  end

  @doc """
  Sends `RCPT TO` command that specify the recipient of the mail.

      :ok = rcpt_to(socket, "world@hey.com")

  """
  @spec rcpt_to(socket, String.t(), timeout) :: :ok | error
  def rcpt_to(socket, address, timeout \\ @default_timeout) do
    with {:ok, response} <- request(socket, ["RCPT TO: ", quoteaddr(address) | "\r\n"], timeout) do
      case response do
        [code | _lines] when code in [250, 251] -> :ok
        [code | lines] -> smtp_error(code, lines)
      end
    end
  end

  @doc """
  Sends `DATA` command that specifies the beginning of the mail, and then sends the message.

      {:ok, _receipt} = data(socket, "Date: Sat, 24 Jun 2023 13:43:57 +0000\\r\\n...")

  """
  @spec data(socket, iodata, timeout) :: {:ok, receipt :: String.t()} | error
  def data(socket, message, timeout \\ @default_timeout) do
    # TODO implement proper
    message = do_dot_stuffing(message)

    with {:ok, [354 | _lines]} <- request(socket, "DATA\r\n", timeout),
         {:ok, [250 | lines]} <- request(socket, [message | "\r\n.\r\n"], timeout) do
      {:ok, IO.iodata_to_binary(lines)}
    else
      {:ok, [code | lines]} -> smtp_error(code, lines)
      {:error, _reason} = error -> error
    end
  end

  @doc false
  def do_dot_stuffing(message) do
    message
    |> IO.iodata_to_binary()
    |> :binary.replace("\n.", "\n..", [:global])
  end

  @doc """
  Sends `VRFY` command that confirms or verifies the user name.

      {:ok, true} = vrfy(socket, "ruslandoga+mua@icloud.com")

  """
  @spec vrfy(socket, String.t(), timeout) :: {:ok, boolean} | error
  def vrfy(socket, address, timeout \\ @default_timeout) do
    with {:ok, response} <- request(socket, ["VRFY ", quoteaddr(address) | "\r\n"], timeout) do
      case response do
        [250 | _lines] -> {:ok, true}
        [code | _lines] when code in [251, 252, 551] -> {:ok, false}
        [code | lines] -> smtp_error(code, lines)
      end
    end
  end

  @doc """
  Sends `RSET` command that aborts the current mail transaction but keeps the socket open.

      :ok = rset(socket)

  """
  @spec rset(socket, timeout) :: :ok | error
  def rset(socket, timeout \\ @default_timeout) do
    with {:ok, response} <- request(socket, "RSET\r\n", timeout) do
      case response do
        [250 | _lines] -> :ok
        [code | lines] -> smtp_error(code, lines)
      end
    end
  end

  @doc """
  Sends `NOOP` command that does nothing.

      :ok = noop(socket)

  """
  @spec noop(socket, timeout) :: :ok | error
  def noop(socket, timeout \\ @default_timeout) do
    with {:ok, response} <- request(socket, "NOOP\r\n", timeout) do
      case response do
        [250 | _lines] -> :ok
        [code | lines] -> smtp_error(code, lines)
      end
    end
  end

  @doc """
  Sends `QUIT` command that make the server close the connection.

      :ok = quit(socket)

  """
  @spec quit(socket, timeout) :: :ok | error
  def quit(socket, timeout \\ @default_timeout) do
    with {:ok, response} <- request(socket, "QUIT\r\n", timeout) do
      case response do
        [221 | _lines] -> :ok
        [code | lines] -> smtp_error(code, lines)
      end
    end
  end

  @compile inline: [send: 2]
  defp send(socket, data) when is_port(socket), do: :gen_tcp.send(socket, data)
  defp send(socket, data), do: :ssl.send(socket, data)

  @compile inline: [recv: 3]
  defp recv(socket, size, timeout) when is_port(socket), do: :gen_tcp.recv(socket, size, timeout)
  defp recv(socket, size, timeout), do: :ssl.recv(socket, size, timeout)

  defp recv_all(socket, timeout) do
    with {:ok, line} <- recv(socket, 0, timeout) do
      case line do
        <<status::3-bytes, ?\s, _::bytes>> = line ->
          {:ok, [String.to_integer(status), line]}

        <<status::3-bytes, ?-, _::bytes>> = line ->
          recv_all_cont(socket, timeout, status, [line])
      end
    end
  end

  defp recv_all_cont(socket, timeout, status, acc) do
    with {:ok, line} <- recv(socket, 0, timeout) do
      case line do
        <<^status::3-bytes, ?-, _::bytes>> = line ->
          recv_all_cont(socket, timeout, status, [line | acc])

        <<^status::3-bytes, ?\s, _::bytes>> = line ->
          {:ok, [String.to_integer(status) | :lists.reverse([line | acc])]}
      end
    end
  end

  @compile inline: [request: 3]
  defp request(socket, data, timeout) do
    with :ok <- send(socket, data), {:ok, _lines} = ok <- recv_all(socket, timeout) do
      ok
    else
      {:error, reason} -> transport_error(reason)
    end
  end

  @compile inline: [smtp_error: 2]
  defp smtp_error(code, lines) do
    {:error, Mua.SMTPError.exception(code: code, lines: lines)}
  end

  @compile inline: [transport_error: 1]
  defp transport_error(reason) do
    {:error, Mua.TransportError.exception(reason: reason)}
  end

  # TODO implement proper RFC2822
  defp quoteaddr(address) when is_binary(address) do
    if String.ends_with?(address, ">") do
      address
    else
      [?<, address, ?>]
    end
  end
end
