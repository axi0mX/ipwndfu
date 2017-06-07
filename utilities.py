import subprocess, sys

def apply_patches(binary, patches):
    for (offset, data) in patches:
        binary = binary[:offset] + data + binary[offset + len(data):]
    return binary

def aes_decrypt(data, iv, key):
  if len(key) == 32:
    aes = 128
  elif len(key) == 64:
    aes = 256
  else:
    print 'ERROR: Bad AES key given to aes_decrypt. Exiting.'
    sys.exit(1)

  p = subprocess.Popen(['openssl', 'enc', '-aes-%s-cbc' % aes, '-d', '-nopad', '-iv', iv, '-K', key],
                       stdout=subprocess.PIPE,
                       stdin=subprocess.PIPE,
                       stderr=subprocess.PIPE)
  (stdout, stderr) = p.communicate(input=data)

  if p.returncode != 0 or len(stderr) > 0:
    print 'ERROR: openssl failed: %s' % stderr
    sys.exit(1)

  return stdout

def hex_dump(data, address):
  p = subprocess.Popen(['xxd', '-o', str(address)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  (stdout, stderr) = p.communicate(input=data)

  if p.returncode != 0 or len(stderr) > 0:
    print 'ERROR: xxd failed: %s' % stderr
    sys.exit(1)

  return stdout
