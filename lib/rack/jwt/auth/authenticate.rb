module Rack
  module Jwt
    module Auth

      class Authenticate

        def initialize(app, opts = {})
          @app  = app
          @opts = opts

          raise 'Secret must be provided' if opts[:secret].nil?

          @secret = opts[:secret]

          @authenticated_routes   = compile_paths(opts[:only])
          @unauthenticated_routes = compile_paths(opts[:except])
        end

        def call(env)
          with_authorization(env) do |payload|
            env['rack.jwt.session'] = payload
            @app.call(env)
          end
        end

        private

        def authenticated_route?(env)
          if @authenticated_routes.length > 0
            @authenticated_routes.find { |route| route =~ env['PATH_INFO'] }
          else
            !@unauthenticated_routes.find { |route| route =~ env['PATH_INFO'] }
          end
        end

        def with_authorization(env)
          if authenticated_route?(env)
            header  = env['HTTP_AUTHORIZATION']

            return [401, {}, [{message: 'Missing Authorization header'}.to_json]] if header.nil?

            scheme, token = header.split(" ")

            return [401, {}, [{message: 'Format is Authorization: Bearer [token]'}.to_json]] unless scheme.match(/^Bearer$/i) && !token.nil?

            payload = AuthToken.valid?(token, @secret)

            return [401, {}, [{message: 'Invalid Authorization'}.to_json]] unless payload
          end

          yield payload
        end

        def compile_paths(paths)
          return [] if paths.nil?

          paths.map do |path|
            compile(path)
          end
        end

        def compile(path)
          if path.respond_to? :to_str
            special_chars = %w{. + ( )}
            pattern =
              path.to_str.gsub(/((:\w+)|[\*#{special_chars.join}])/) do |match|
                case match
                when "*"
                  "(.*?)"
                when *special_chars
                  Regexp.escape(match)
                else
                  "([^/?&#]+)"
                end
              end
            /^#{pattern}$/
          elsif path.respond_to? :match
            path
          else
            raise TypeError, path
          end
        end
      end

    end
  end
end
