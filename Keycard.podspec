Pod::Spec.new do |spec|
	spec.name = 'Keycard'
	spec.version = '3.1.0'
	spec.authors = {'Bitgamma' => 'opensource@bitgamma.com'}
	spec.homepage = 'https://github.com/status-im/Keycard.swift'
	spec.license = { :type => 'Apache' }
	spec.source = { :git => 'https://github.com/status-im/Keycard.swift.git', :tag => 'v0.0.0'}
	spec.source_files = 'Sources/Keycard/*.swift'
	spec.summary = 'Keycard'
	spec.swift_version = '4.2'
	spec.platforms = { :ios => '10.0' }
	spec.frameworks = 'CoreNFC'
	spec.dependency 'CryptoSwift'
	spec.dependency 'secp256k1'
	spec.dependency 'SSZipArchive'
	spec.dependency 'BigInt'
end
