require 'open-uri'

class Preview
  def fetch
    # ruleid: traust-ruby-injection-kernel-open
    body = open(link.target).read
    # ruleid: traust-ruby-injection-kernel-open
    data = URI.open(params[:source]).read
    # ruleid: traust-ruby-injection-kernel-open
    URI.parse(target_url).open
  end

  def render_banner(theme)
    template = theme.fetch('banner')
    # ruleid: traust-ruby-injection-erb-template
    ERB.new(template).result(binding)
  end

  def fine(path)
    # ok: traust-ruby-injection-kernel-open
    File.open(path).read
    # ok: traust-ruby-injection-kernel-open
    open("/etc/app/defaults.yml").read
    # ok: traust-ruby-injection-erb-template
    ERB.new("Hello <%= name %>").result(binding)
    # ok: traust-ruby-injection-erb-template
    ERB.new(File.read(TEMPLATE)).result(binding)
  end
end
