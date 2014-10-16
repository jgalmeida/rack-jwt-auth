module Rack
  module Jwt
    module Auth

      module AuthToken

        def self.issue_token(payload, secret)
          JWT.encode(payload, secret)
        end

        def self.valid?(token, secret)
          begin
            JWT.decode(token, secret)
          rescue
            false
          end
        end

      end

    end
  end
end