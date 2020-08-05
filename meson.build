project('kissnet_ci', 'cpp',
default_options : ['cpp_std=c++17'])

ssl = dependency('OpenSSL')
output_exe = executable('output', 'kissnet.cpp', dependencies: ssl)
