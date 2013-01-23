require 'net/http'
require 'cgi'
require 'json'

# This is the first, barely tested pass at creating a set of Ruby functions to authenticate to, search, and retrieve from the EDS API.
# Once this gem is installed, you can find demo code that makes use of the gem here:
# http://www.lh2cc.net/dse/efrierson/ruby/eds-alpha-demo.zip

module EDSApi
	API_URL = "http://eds-api.ebscohost.com/"
	API_URL_S = "https://eds-api.ebscohost.com/"
	
	# Connection object. Does what it says. ConnectionHandler is what is usually desired and wraps auto-reonnect features, etc.
	class Connection
	  attr_accessor :auth_token
	  attr_writer :userid, :password
	  
	  # Init the object with userid and pass.
		def uid_init(userid, password, profile)
			@userid = userid
			@password = password
			@profile = profile
			return self
		end
		def ip_init(profile)
			@profile = profile
			return self
		end
		# Auth with the server. Currently only uid auth is supported.
		def uid_authenticate(format = :xml)
			xml = "<UIDAuthRequestMessage xmlns='http://www.ebscohost.com/services/public/AuthService/Response/2012/06/01'><UserId>#{@userid}</UserId><Password>#{@password}</Password></UIDAuthRequestMessage>"
			uri = URI "#{API_URL_S}authservice/rest/uidauth"
			req = Net::HTTP::Post.new(uri.request_uri)
			req["Content-Type"] = "application/xml"
			req["Accept"] = "application/json" #if format == :json
			req.body = xml
			https = Net::HTTP.new(uri.hostname, uri.port)
			https.use_ssl = true
			https.verify_mode = OpenSSL::SSL::VERIFY_NONE
			doc = JSON.parse(https.request(req).body)
			if doc.has_key?('ErrorNumber')
			   abort "Bad response from server - error code #{result['ErrorNumber']}"
			else
			   @auth_token = doc['AuthToken']
			end			
		end
		def ip_authenticate(format = :xml)
			uri = URI "#{API_URL_S}authservice/rest/ipauth"
			req = Net::Http:Post.new(uri.request_uri)
			req["Accept"] = "application/json" #if format == :json
			https = Net::HTTP.new(uri.hostname, uri.port)
			https.use_ssl = true
			https.verify_mode = OpenSSL::SSL::VERIFY_NONE
			doc = JSON.parse(https.request(req).body)
			@auth_token = doc['AuthToken']
		end
		# Create the session
		def create_session
			uri = URI "#{API_URL}edsapi/rest/createsession?profile=#{@profile}"
			req = Net::HTTP::Get.new(uri.request_uri)
			req['x-authenticationToken'] = @auth_token
			req['Accept'] = "application/json"
			Net::HTTP.start(uri.hostname, uri.port) { |http|
  			doc = JSON.parse(http.request(req).body)
				return doc['SessionToken']
			}
		end
		# End the session
		def end_session(session_token)
			uri = URI "#{API_URL}edsapi/rest/endsession?sessiontoken=#{CGI::escape(session_token)}"
			req = Net::HTTP::Get.new(uri.request_uri)
			req['x-authenticationToken'] = @auth_token
			Net::HTTP.start(uri.hostname, uri.port) { |http|
  			http.request(req)
			}
			return true
		end
		# Run a search query, XML results are returned
        def search(options, session_token, format = :xml)
			uri = URI "#{API_URL}edsapi/rest/Search?#{options}"
			req = Net::HTTP::Get.new(uri.request_uri)
			req['x-authenticationToken'] = @auth_token
			req['x-sessionToken'] = session_token
			req['Accept'] = 'application/json' #if format == :json
			Net::HTTP.start(uri.hostname, uri.port) { |http|
  			return http.request(req).body
			}
        end
	  # Retrieve specific information
		def retrieve(dbid, an, session_token, format = :xml)
			uri = URI "#{API_URL}edsapi/rest/retrieve?dbid=#{dbid}&an=#{an}"
			req = Net::HTTP::Get.new(uri.request_uri)
			req['x-authenticationToken'] = @auth_token
			req['x-sessionToken'] = session_token
			req['Accept'] = 'application/json' #if format == :json
			Net::HTTP.start(uri.hostname, uri.port) { |http|
  			return http.request(req).body
			}
		end
		# Info method
		def info(session_token, format = :xml)
			uri = URI "#{API_URL}edsapi/rest/Info"
			req = Net::HTTP::Get.new(uri.request_uri)
			req['x-authenticationToken'] = @auth_token
			req['x-sessionToken'] = session_token
			req['Accept'] = 'application/json' #if format == :json
			Net::HTTP.start(uri.hostname, uri.port) { |http|
  			return http.request(req).body
			}
		end
	end
	# Handles connections - retries failed connections, passes commands along
	class ConnectionHandler < Connection
		attr_accessor :max_retries
		def initialize(max_retries = 2)
			@max_retries = max_retries
		end
		def search(options, session_token, format = :xml)
			attempts = 0
			loop do
				result = JSON.parse(super(options, session_token, format))
			  if result.has_key?('ErrorNumber')
				  case result['ErrorNumber']
				  	when "108"
				  		session_token = self.create_session
				  	when "104"
				  		self.uid_authenticate(:json)
				  end
				  if ++attempts == @max_retries
				  		abort "Bad response from server - error code #{result['ErrorNumber']}"
				  end
			  else
			  	return result
			  end
			end
		end
	    def info (session_token, format= :xml)
		   attempts = 0
			loop do
				result = JSON.parse(super(session_token, format)) # JSON Parse
			  if result.has_key?('ErrorNumber')
				  case result['ErrorNumber']
				  	when "108"
				  		session_token = self.create_session
				  	when "104"
				  		self.uid_authenticate(:json)
				  end
				  if ++attempts == @max_retries
				  		abort "Bad response from server - error code #{result['ErrorNumber']}"
				  end
			  else
			  	return result
			  end
		  end
		end
		def retrieve(dbid, an, session_token, format = :xml)
			attempts = 0
			loop do
				result = JSON.parse(super(dbid, an, session_token, format))
			  if result.has_key?('ErrorNumber')
				  case result['ErrorNumber']
				  	when "108"
				  		session_token = self.create_session
				  	when "104"
				  		self.uid_authenticate(:json)
				  end
				  if ++attempts == @max_retries
				  		abort "Bad response from server - error code #{result['ErrorNumber']}"
				  end
			  else
			  	return result
			  end
		  end
		end
	end
end

# Benchmark response times
def benchmark(q = false)
	start = Time.now
	connection = EDSApi::ConnectionHandler.new(2)
	connection.uid_init('USERID', 'PASSWORD', 'PROFILEID')
	connection.uid_authenticate(:json)
	puts((start - Time.now).abs) unless q
	connection.create_session
	puts((start - Time.now).abs) unless q
	connection.search('query-1=AND,galapagos+hawk', :json)
	puts((start - Time.now).abs) unless q
	connection.end_session
	puts((start - Time.now).abs) unless q
end

# Run benchmark with warm up run; only if file was called directly and not required
if __FILE__ == $0
	benchmark(true)
	benchmark
end