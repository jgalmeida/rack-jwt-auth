require 'spec_helper'

describe Rack::Jwt::Auth::AuthToken do

  let(:secret) { 'supertestsecret' }
  let(:data) { { user_id: 1, username: 'test' } }

  describe '.issue_token' do

    it 'issues a token' do
      token = subject.issue_token(data, secret)

      expect(token).to be
    end

  end

  describe '.valid?' do

    it 'checks if the provided token is valid' do
      token   = subject.issue_token(data, secret)
      payload = subject.valid?(token, secret)

      meta, data = payload

      expect(payload).to be
      expect(data['user_id']).to  eql(data[:user_id])
      expect(data['username']).to eql(data[:username])
    end

    it 'supports options to verify the token' do
      token = JWT.encode(data, secret, 'HS256')
      payload = subject.valid?(token, secret, { algorithm: 'RS256' })

      expect(payload).not_to be
    end

    it 'checks if the provided token is invalid when decoded with other secret' do
      token   = subject.issue_token(data, secret)
      payload = subject.valid?(token, 'secret')

      expect(payload).not_to be
    end

  end

end
