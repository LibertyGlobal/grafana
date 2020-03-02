def run(*args)
  args.flatten!
  puts "* RUN: #{args.join ' '}"
  system *args
  $?.exitstatus == 0
end

task :variables do
  ENV['GRAFANA_VERSION'] = '7.3.7' unless ENV['GRAFANA_VERSION']
  ENV['GO_PIPELINE_LABEL'] = "dev" unless ENV['GO_PIPELINE_LABEL']

  ENV['PROXY_URL'] = "http://172.31.101.80:8888" unless ENV['PROXY_URL']
  ENV['PROXY_EXCLUDE'] = "" unless ENV['PROXY_EXCLUDE']

  ENV['BUILD_BRANCH'] = `git rev-parse --abbrev-ref HEAD`.chomp.strip unless ENV['BUILD_BRANCH']
  ENV['BUILD_COMMIT'] = `git rev-parse --short HEAD`.chomp.strip unless ENV['BUILD_COMMIT']
  ENV['BUILD_TIMESTAMP'] = `git show -s --format=%ct`.chomp.strip unless ENV['BUILD_TIMESTAMP']

  unless ENV['BUILD_BRANCH'] and ENV['BUILD_COMMIT'] and ENV['BUILD_TIMESTAMP']
    puts "Could not get the git build information!"
    exit 1
  end

  ENV['IMAGE_NAME'] = "docker.horizon.tv/dataops/grafana" unless ENV['IMAGE_NAME']
  ENV['IMAGE_VERSION'] = "#{ENV['GRAFANA_VERSION']}-#{ENV['GO_PIPELINE_LABEL']}-#{ENV['BUILD_COMMIT']}"
end

task :build => :variables do
  puts "* Start building the Grafana image '#{ENV['IMAGE_NAME']}:#{ENV['IMAGE_VERSION']}'"

  build_args = {
      'HTTP_PROXY' => ENV['PROXY_URL'],
      'HTTPS_PROXY' => ENV['PROXY_URL'],
      'NO_PROXY' => ENV['PROXY_EXCLUDE'],

      'http_proxy' => ENV['PROXY_URL'],
      'https_proxy' => ENV['PROXY_URL'],
      'no_proxy' => ENV['PROXY_EXCLUDE'],

      'BUILD_BRANCH' => ENV['BUILD_BRANCH'],
      'BUILD_COMMIT' => ENV['BUILD_COMMIT'],
      'BUILD_TIMESTAMP' => ENV['BUILD_TIMESTAMP'],
  }

  cmd = %w(docker build . --no-cache --network host)

  build_args.each do |variable, value|
    cmd << '--build-arg'
    cmd << "#{variable}=#{value}"
  end
  cmd << '--tag'
  cmd << "#{ENV['IMAGE_NAME']}:#{ENV['IMAGE_VERSION']}"

  success = run cmd
  unless success
    puts "Grafana build have FAILED!"
    exit 1
  end
end

task :upload => :build do
  puts "* Uploading the Grafana image '#{ENV['IMAGE_NAME']}:#{ENV['IMAGE_VERSION']}'"
  success = run 'docker', 'push', "#{ENV['IMAGE_NAME']}:#{ENV['IMAGE_VERSION']}"
  unless success
    puts "Grafana docker upload have FAILED!"
    exit 1
  end
end

task :default => :upload
