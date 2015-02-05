require 'spec_helper'

describe Rack::Jwt::Auth::Authenticate do
  include Rack::Test::Methods

  let(:issuer) { Rack::Jwt::Auth::AuthToken }

  let(:app) do
    main_app = lambda { |env| [200, env, ['Hello']] }
    Rack::Jwt::Auth::Authenticate.new(main_app, {secret: 'supertestsecret'})
  end

  it 'raises an exception if no secret if provided' do
    expect{ Rack::Jwt::Auth::Authenticate.new(main_app, {}) }.to raise_error
  end

  it 'returns 200 ok if the request is authenticated' do
    token = issuer.issue_token({user_id: 1, username: 'test'}, 'supertestsecret')
    get('/', {}, {'HTTP_AUTHORIZATION' => "Bearer #{token}"})

    expect(last_response.status).to eql(200)
    expect(last_response.body).to   eql('Hello')

    session = last_response.header['rack.jwt.session'][0]

    expect(session['user_id']).to  eql(1)
    expect(session['username']).to eql('test')
  end

  it 'returns 401 if the authorization header is missing' do
    get('/')

    jsonResponse = JSON.parse(last_response.body)

    expect(last_response.status).to eql(401)
    expect(jsonResponse["message"]).to eql("Missing Authorization header")
  end

  it 'returns 401 if the authorization header signature is invalid' do
    token = issuer.issue_token({user_id: 1}, 'invalid_secret')
    get('/', {}, {'HTTP_AUTHORIZATION' => "Bearer #{token}"})

    jsonResponse = JSON.parse(last_response.body)

    expect(last_response.status).to eql(401)
    expect(jsonResponse["message"]).to eql("Invalid Authorization")
  end

  it 'returns 401 if the header format is not Authorization: Bearer [token]' do
    token = issuer.issue_token({user_id: 1}, 'supertestsecret')
    get('/', {}, {'HTTP_AUTHORIZATION' => "#{token}"})

    jsonResponse = JSON.parse(last_response.body)

    expect(last_response.status).to eql(401)
    expect(jsonResponse["message"]).to eql("Format is Authorization: Bearer [token]")
  end

  it 'returns 401 if authorization scheme is not Bearer' do
    token = issuer.issue_token({user_id: 1}, 'supertestsecret')
    get('/', {}, {'HTTP_AUTHORIZATION' => "WrongScheme #{token}"})

    jsonResponse = JSON.parse(last_response.body)

    expect(last_response.status).to eql(401)
    expect(jsonResponse["message"]).to eql("Format is Authorization: Bearer [token]")
  end

end
