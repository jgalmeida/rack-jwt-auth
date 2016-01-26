module Rack
  module Jwt
    module Auth

      module AuthToken

        # Note: this method is only used by specs
        def self.issue_token(payload, secret)
          JWT.encode(payload, secret)
        end

        def self.valid?(token, secret, opts = {})
          begin
            JWT.decode(token, secret, true, opts)
          rescue
            false
          end
        end

      end

    end
  end
end
