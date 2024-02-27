from phe import paillier

#Un conglomerado empresarial de 5000 miembros esta decidiendo sobre la absorcion de alguna de las siguientes empresas.
#ACME-INC
#ACME-SL
#ACME-FACTORY
#La decision se realiza sobre las votaciones realizadas en las diferentes sedes pertenecientes al grupo (8 sedes de 625 miembros)
#Tras realizar la votacion en cada sede, los datos son enviados y almacenados para su recuento
#Se ha detectado un ataque a los datos almacenados y se ha filtrado la informacion sobre las votaciones
#Debido a esto, el atacante posee informacion privilegiada sobre la decision del conglomerado

#Se sabe que los datos estan cifrados utilizando cifrado homomorfico de pailier (phe)
#pub,priv = paillier.generate_paillier_keypair(n_length=40)

# N = P * Q
pub = paillier.PaillierPublicKey(615701807411) # N
#Priv debe averiguarlo el usuario
priv = paillier.PaillierPrivateKey(pub,603689,1019899) # P, Q


emp1 = [273195769081857674763628,192055108622984958392709,30762392720345566919956,81892798556741346154699,271252275147035049408427,273187728605463057361201,277504895961873757239899,68201346047604445407416]
emp2 = [109823343090092953944017,134763215821147930810032,261150449722032877761616,283828298375388671142705,202204298264366473030119,375743045956376781795663,69837982904912717819653,35543821145848117671864]
emp3 = [153929295867379237096604,96299509908795079099099,30600080377616556113514,103326410116509808354965,352697367762765440362691,95660357923520475332996,69754211356009554787800,81917985040501402624682]



c_emp1 = [paillier.EncryptedNumber(pub,x) for x in emp1]
c_emp2 = [paillier.EncryptedNumber(pub,x) for x in emp2]
c_emp3 = [paillier.EncryptedNumber(pub,x) for x in emp3]

list1 = [priv.decrypt(x) for x in c_emp1]
list2 = [priv.decrypt(x) for x in c_emp2]
list3 = [priv.decrypt(x) for x in c_emp3]

print(list1)
print(list2)
print(list3)

c_a = c_emp1[0]
c_b = c_emp2[0]
c_c = c_emp3[0]

for i in range(1,8):
    c_a = c_a._add_encrypted(c_emp1[i])
    c_b = c_b._add_encrypted(c_emp2[i])
    c_c = c_c._add_encrypted(c_emp3[i])

print(priv.decrypt(c_a))
print(priv.decrypt(c_b))
print(priv.decrypt(c_c))

import hashlib
h = hashlib.md5()
h.update(b"ACME-INC")
print(h.hexdigest())