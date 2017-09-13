require 'spec_helper'

describe Rack::Jwt::Auth::Authenticate do
  include Rack::Test::Methods

  let(:issuer) {Rack::Jwt::Auth::AuthToken}

  context "Except routes" do

    let(:app) do
      main_app = lambda {|env| [200, env, ['Hello']]}
      Rack::Jwt::Auth::Authenticate.new(main_app,
                                        {
                                          except: ['/not_authenticated', '/not_authenticated/*'],
                                          secret: 'supertestsecret',
                                          algorithm: 'HS256'
                                        })
    end

    it 'returns 200 ok if the request is for a route that is not authenticated' do
      get('/not_authenticated')

      expect(last_response.status).to eql(200)
      expect(last_response.body).to eql('Hello')

      get('/not_authenticated/other')

      expect(last_response.status).to eql(200)
      expect(last_response.body).to eql('Hello')

      get('/not_authenticated/other/test')

      expect(last_response.status).to eql(200)
      expect(last_response.body).to eql('Hello')
    end

    it 'returns 401 ok if the request is for a route that is authenticated' do
      get('/authenticated')
      expect(last_response.status).to eql(401)

      get('/authenticated/other')
      expect(last_response.status).to eql(401)

      get('/authenticated/other/test')
      expect(last_response.status).to eql(401)
    end

  end

  context "Only routes" do

    let(:app) do
      main_app = lambda {|env| [200, env, ['Hello']]}
      Rack::Jwt::Auth::Authenticate.new(main_app, {
        only: ['/authenticated', '/authenticated/*'], secret: 'supertestsecret', algorithm: 'HS256'
      })
    end

    it 'returns 200 ok if the request is for a route that is not authenticated' do
      get('/not_authenticated')

      expect(last_response.status).to eql(200)
      expect(last_response.body).to eql('Hello')

      get('/not_authenticated/other')

      expect(last_response.status).to eql(200)
      expect(last_response.body).to eql('Hello')

      get('/not_authenticated/other/test')

      expect(last_response.status).to eql(200)
      expect(last_response.body).to eql('Hello')
    end

    it 'returns 401 ok if the request is for a route that is authenticated' do
      get('/authenticated')
      expect(last_response.status).to eql(401)

      get('/authenticated/other')
      expect(last_response.status).to eql(401)

      get('/authenticated/other/test')
      expect(last_response.status).to eql(401)
    end

  end

  context "Only with except routes" do

    let(:app) do
      main_app = lambda {|env| [200, env, ['Hello']]}
      Rack::Jwt::Auth::Authenticate.new(main_app, {only: ['/authenticated', '/authenticated/*'], secret: 'supertestsecret',
                                                   algorithm: 'HS256'})
    end

    it 'returns 200 ok if the request is for a route that is not authenticated' do
      get('/not_authenticated')

      expect(last_response.status).to eql(200)
      expect(last_response.body).to eql('Hello')

      get('/not_authenticated/other')

      expect(last_response.status).to eql(200)
      expect(last_response.body).to eql('Hello')

      get('/not_authenticated/other/test')

      expect(last_response.status).to eql(200)
      expect(last_response.body).to eql('Hello')
    end

    it 'returns 401 ok if the request is for a route that is authenticated' do
      get('/authenticated')
      expect(last_response.status).to eql(401)

      get('/authenticated/other')
      expect(last_response.status).to eql(401)

      get('/authenticated/other/test')
      expect(last_response.status).to eql(401)
    end

  end

  context "with options for decode" do
    let(:secret) {'supertestsecret'}
    let(:app) do
      main_app = lambda {|env| [200, env, ['Hello']]}
      described_class.new(main_app, {secret: secret, algorithm: 'RS256'})
    end

    it 'calls AuthToken.valid? with decode options' do
      allow(Rack::Jwt::Auth::AuthToken).to receive(:valid?).and_call_original
      token = JWT.encode({user_id: 1, username: 'test'}, secret, 'HS256')
      get('/', {}, {'HTTP_AUTHORIZATION' => "Bearer #{token}"})

      expect(Rack::Jwt::Auth::AuthToken).to have_received(:valid?)
                                              .with(token, secret, {algorithm: 'RS256'})
    end
  end


end
