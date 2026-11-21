require File.expand_path('bfd/version', __dir__)

Gem::Specification.new do |s|
  s.name = 'bfd4r'
  s.version = BFD::VERSION
  s.authors = ['Jean-Michel Esnault']
  s.summary = 'BFD in Ruby: build, parse and check BFD Control packets'
  s.description = 'A pure Ruby library to build, parse and send BFD (RFC 5880, 5881), ' \
                  'valid or not, for routing labs and protocol tests.'
  s.homepage = 'https://github.com/jeanmichel-gh/bfd4r'
  s.license = 'GPL-3.0-or-later'
  s.require_paths = ['.']
  s.bindir = 'exe'
  s.executables = %w[bfdd4r bfd4r-cli bfd4r-sim with-bfdd4r]
  # 3.2: bfdd4r's loop waits with Thread::Queue#pop(timeout:), new in 3.2.
  s.required_ruby_version = '>= 3.2'
  # A test must not load this file: git ls-files fails where there is
  # no .git, as in a Docker image (bgp4r CLAUDE.md).
  s.files = `git ls-files -z`.split("\x0")
end
