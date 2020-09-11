require 'net/https'
require 'uri'

module JIRA
  class AccessTokenClient < RequestClient
    DEFAULT_OPTIONS = {
      access_token: nil
    }.freeze

    attr_reader :options

    def initialize(options)
      @options = DEFAULT_OPTIONS.merge(options)
      @headers = { 'Authorization' => "Bearer #{@options[:access_token]}" }
    end

    def make_request(http_method, url, body = '', headers = {})
      # When a proxy is enabled, Net::HTTP expects that the request path omits the domain name
      # this whole freakin gem is convoluted.
      # the process to even build a url is abstracted to a dozen different condition and wrapped in arbitrary methods.
      # overriding most of it for now and just building a proper url. bah
      path = @options[:site] + request_path(url)
      puts 'path in make request', path
      request = Net::HTTP.const_get(http_method.to_s.capitalize).new(path, headers.merge(@headers))
      request.body = body unless body.nil?

      execute_request(request)
    end

    def make_multipart_request(url, body, headers = {})
      path = request_path(url)
      request = Net::HTTP::Post::Multipart.new(path, body, headers.merge(@headers))

      execute_request(request)
    end

    def access_token_http_conn
      http_conn(uri)
    end

    def http_conn(uri)
      http_class = Net::HTTP
      http_conn = http_class.new(uri.host, uri.port)
      http_conn.use_ssl = @options[:use_ssl]
      http_conn.verify_mode = @options[:ssl_verify_mode]
      http_conn.ssl_version = @options[:ssl_version] if @options[:ssl_version]
      http_conn.read_timeout = @options[:read_timeout]
      http_conn
    end

    def uri
      URI.parse(@options[:site])
    end

    def authenticated?
      @authenticated
    end

    private

    def execute_request(request)
      response = access_token_http_conn.request(request)

      @authenticated = response.is_a? Net::HTTPOK

      response
    end

    def request_path(url)
      parsed_uri = URI(url)

      puts 'uri in request_path:', parsed_uri
      return url unless parsed_uri.is_a?(URI::HTTP)

      parsed_uri.request_uri
    end
  end
end
