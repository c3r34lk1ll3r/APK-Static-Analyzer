#READ CLASS.DEX

import binascii
import math
from .btcodedict import ByteCodeDictionary
from .bgcolors import bcolors
from .type import *

#Modify Read Byte in utility class
def from_bytes(data,endianess):
	if endianess=="little":
		data.reverse()
	return int(binascii.hexlify(data),16)

class DexFile:

	def __init__(self,f=None):
		if f!=None:
			self.dexFl=f
		self.__Head=Header()
		self.__String=[]
		self.__TypeIDS=[]
		self.__ProtoIDS=[]
		self.__FieldIDS=[]
		self.__MethodIDS=[]
		self.__ClassDEF={}
		if f!=None:
			self.ReadDex()

	def PrintCodeClass(self,cod):
		print (bcolors.HEADER+"%-30s"+bcolors.ENDC+bcolors.BOLD+"%-30s") % ("Registers",str(cod.registers_size))
		print (bcolors.HEADER+"%-30s"+bcolors.ENDC+bcolors.BOLD+"%-30s") % ("Words incoming",str(cod.ins_size))
		print (bcolors.HEADER+"%-30s"+bcolors.ENDC+bcolors.BOLD+"%-30s") % ("Words outgoing",str(cod.outs_size))
		print (bcolors.HEADER+"%-30s"+bcolors.ENDC+bcolors.BOLD+"%-30s") % ("Try items",str(cod.tries_size))
		if cod.debug_info_off == 0:
			print (bcolors.HEADER+"%-30s"+bcolors.ENDC+bcolors.BOLD+"%-30s") % ("Debug information","None")
		else:
			print (bcolors.HEADER+"%-30s"+bcolors.ENDC+bcolors.BOLD+"%-30s") %("Debug information","Inserted")
		print (bcolors.HEADER+"%-30s"+bcolors.ENDC+bcolors.BOLD+"%-30s") % ("LoC",str(cod.insns_size))

		#Convert Bytecode into Human Readable Format
		print(bcolors.RED+"\n\n \t\t#---CODE BEGIN---#\n\n"+bcolors.ENDC)
		codex=self.ByteCodeToString(cod)
		indx=0
		#const for now
		numb=8
		bytec=0
		while indx<len(codex):
			number=len(codex[indx].split())
			line=bcolors.CYAN+"0x"
			#Offset
			line+=format(bytec,'0'+str(numb)+'x')+bcolors.ENDC+"\t"
			#For each type of instruction we need a color
			line+=(bcolors.BLUE+"%-30s"+bcolors.ENDC+bcolors.BOLD+"%-100s") % (codex[indx],codex[indx+1])
			indx+=2
			bytec+=(number)*2
			print (line)

	def getCode(self,indx):
		self.dexFl.seek(indx)
		code=CClassDEF.code_item()
		code.registers_size=self.from_bytes(bytearray(self.dexFl.read(2)),"little")
		code.ins_size=self.from_bytes(bytearray(self.dexFl.read(2)),"little")
		code.outs_size=self.from_bytes(bytearray(self.dexFl.read(2)),"little")
		code.tries_size=self.from_bytes(bytearray(self.dexFl.read(2)),"little")
		code.debug_info_off=self.from_bytes(bytearray(self.dexFl.read(4)),"little")
		code.insns_size=self.from_bytes(bytearray(self.dexFl.read(4)),"little")

		#reading bytecode
		indx=0
		while indx < (code.insns_size*2):
			cx=int(binascii.hexlify(self.dexFl.read(1)),16)
			code.insns.append(cx)
			indx+=1
		return code

	def ByteCodeToString(self,cod):
		returned=[]
		indx=0
		dy=ByteCodeDictionary()
		while indx<(cod.insns_size*2):
			opc=cod.insns[indx]
			oper=cod.insns[indx+1]
			indx+=2
			opers=""
			type=dy.oper[opc]
			#print bcolors.RED+"OPCODE:"+str(hex(opc))
			#print "TIPO:"+str(hex(oper))+bcolors.ENDC
			hexc="0x"+format(opc,'02x')+format(oper,'02x')+" "
			if type == 0:
				#ident	ushort = 0x0200	identifying pseudo-opcode Switch
				if oper == 0x02:
					returned.append(hexc)
					returned.append("Switch table:")
					#Size	ushort	number of entries in the table
					by=bytearray()
					by.append(cod.insns[indx])
					by.append(cod.insns[indx+1])
					indx+=2
					size=from_bytes(by,"little")
					hexc="0x"+binascii.hexlify(by)
					returned.append(hexc)
					returned.append("Size:"+str(size))
					#Keys	int[]	list of size key values, sorted low-to-high
					indice=0
					key=[]
					while indice<size:
						by=bytearray()
						by.append(cod.insns[indx])
						by.append(cod.insns[indx+1])
						by.append(cod.insns[indx+2])
						by.append(cod.insns[indx+3])
						indx+=4
						by.reverse()
						key.append(by)
						#hexc="0x"+binascii.hexlify(by)
						#returned.append(hexc)
						#returned.append("Key:"+str(key))
						indice+=1
					#targets	int[]	list of size relative branch targets, each corresponding to
					#the key value at the same index. The targets are relative to the address of
					#the switch opcode, not of this table.
					indice=0
					while indice<size:
						by=bytearray()
						by.append(cod.insns[indx])
						by.append(cod.insns[indx+1])
						by.append(cod.insns[indx+2])
						by.append(cod.insns[indx+3])
						indx+=4
						item=from_bytes(by,"little")
						hexc="---- ----"
						returned.append(hexc)
						returned.append("0x"+binascii.hexlify(key[indice])+" -> "+str(item))
						indice+=1
					continue

				#ident	ushort = 0x0100	identifying pseudo-opcode Packed Switch
				elif oper == 0x01:
					returned.append(hexc)
					returned.append("Packed Swtich Table:")
					#Size	ushort	number of entries in the table
					by=bytearray()
					by.append(cod.insns[indx])
					by.append(cod.insns[indx+1])
					indx+=2
					size=from_bytes(by,"little")
					hexc="0x"+binascii.hexlify(by)
					returned.append(hexc)
					returned.append("Size:"+str(size))
					#First_key	int	first (and lowest) switch case value
					key=0
					by=bytearray()
					by.append(cod.insns[indx])
					by.append(cod.insns[indx+1])
					by.append(cod.insns[indx+2])
					by.append(cod.insns[indx+3])
					indx+=4
					hexc="0x"+binascii.hexlify(by)
					by.reverse()
					key=by
					returned.append(hexc)
					returned.append("Key:0x"+binascii.hexlify(key))
					#targets	int[]	list of size relative branch targets. The targets are relative to
					#the address of the switch opcode, not of this table.
					indice=0
					while indice<size:
						by=bytearray()
						by.append(cod.insns[indx])
						by.append(cod.insns[indx+1])
						by.append(cod.insns[indx+2])
						by.append(cod.insns[indx+3])
						indx+=4
						item=from_bytes(by,"little")
						hexc="0x"+binascii.hexlify(by)
						returned.append(hexc)
						returned.append(str(item))
						indice+=1
					continue

				#ident ushort = 0x0300	identifying pseudo-opcode Array Data
				elif oper == 0x03:
					returned.append(hexc)
					returned.append("Array Data:")
					print (bcolors.RED+hexc+bcolors.ENDC)
					#Element_width	ushort	number of bytes in each element
					by=bytearray()
					by.append(cod.insns[indx])
					by.append(cod.insns[indx+1])
					indx+=2
					width=from_bytes(by,"little")
					hexc="0x"+binascii.hexlify(by)
					print (bcolors.RED+hexc+bcolors.ENDC)
					returned.append(hexc)
					returned.append("Element width:"+str(width))
					#size	uint	number of elements in the table
					by=bytearray()
					by.append(cod.insns[indx])
					by.append(cod.insns[indx+1])
					by.append(cod.insns[indx+2])
					by.append(cod.insns[indx+3])
					indx+=4
					hexc="0x"+binascii.hexlify(by)
					print (bcolors.RED+hexc+bcolors.ENDC)
					size=from_bytes(by,"little")
					returned.append(hexc)
					returned.append("Size:"+str(size))
					#data	ubyte[]	data values
					indice=0
					back=indx
					while indice<size:
						by=bytearray()
						dt=0
						while dt < width:
							by.append(cod.insns[back])
							dt+=1
							back+=1
						item=from_bytes(by,"little")
						hexc="0x"+binascii.hexlify(by)
						print (bcolors.RED+hexc+bcolors.ENDC)
						returned.append(hexc)
						returned.append("Value:"+str(item))
						indice+=1
					indx+=int((size * width+1)/2)*2

					continue
				opers=""
			elif type == 1:
				#VA 4 bits, VB 4 bits
				va=(oper & 0xF0) >> 4
				vb=oper &  0x0F
				opers="v"+str(va)+", v"+str(vb)
			elif type == 2:
				#VA 8 bits, VB 16 bits
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				vb=self.from_bytes(by,"little")
				va=oper
				opers="v"+str(va)+", v"+str(vb)
				indx+=2
				hexc+=binascii.hexlify(by)
			elif type == 3:
				#VA 16 bits, VB 16 bits -> NOT ALLIGNED!
				by=bytearray()
				by.append(oper)
				by.append(cod.insns[indx+1])
				hexc+=binascii.hexlify(by)+" "
				indx+=2
				va=self.from_bytes(by,"little")
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				indx+=2
				vb=self.from_bytes(by,"little")
				opers="v"+str(va)+", v"+str(vb)
				hexc+=binascii.hexlify(by)
			elif type == 4:
				#VA 8 bits
				opers="v"+str(oper)
			elif type == 5:
				#VA 4 bits, signed int 4 bits
				value=(oper & 0xF0) >> 4
				if value > 0x07:
					oper -= 0x10
				va=oper &  0x0F
				opers="v"+str(va)+" = "+str(value)
			elif type == 6:
				#VA 8 bits, signed int 16 bits
				by=bytearray()
				by.append(0x00)
				by.append(0x00)
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				hexc+=binascii.hexlify(by[2:])
				value=from_bytes(by,"little")
				if value > 0x7FFF:
					value -= 0x10000
				indx+=2
				va=oper
				opers="v"+str(va)+" = "+str(value)
			elif type == 7:
				#VA 8 bits, signed int 32 bits
				va=oper
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				by.append(cod.insns[indx+2])
				by.append(cod.insns[indx+3])
				indx+=4
				value=from_bytes(by,"little")
				if value > 0x7FFFFFFF:
					value -= 0x100000000
				opers="v"+str(va)+" = "+str(value)
				hexc+=binascii.hexlify(by)
			elif type == 8:
				#VA 8 bits, signed int 64 bits
				va=oper
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				hexc+=binascii.hexlify(by)+" "
				by.append(cod.insns[indx+2])
				by.append(cod.insns[indx+3])
				hexc+=binascii.hexlify(by[2:])+" "
				indx+=4
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				hexc+=binascii.hexlify(by[4:])+" "
				by.append(cod.insns[indx+2])
				by.append(cod.insns[indx+3])
				hexc+=binascii.hexlify(by[6:])
				indx+=4
				value=from_bytes(by,"little")
				if value > 0x7FFFFFFFFFFFFFFF:
					value -= 0x10000000000000000
				opers="v"+str(va)+" = "+str(value)
			elif type == 9:
				#VA 8 bits, string index 16 bits
				va=oper
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				hexc+=binascii.hexlify(by)
				indx+=2
				value=from_bytes(by,"little")
				string=self.__String[value].string_data_data
				opers="v"+str(va)+" = \""+string+"\""
			elif type == 10:
				#VA 8 bits, string index 32 bits
				va=oper
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				hexc+=binascii.hexlify(by)+" "
				by.append(cod.insns[indx+2])
				by.append(cod.insns[indx+3])
				hexc+=binascii.hexlify(by[2:])
				indx+=4
				value=from_bytes(by,"little")
				string=self.__String[value].string_data_data
				opers="v"+str(va)+" = \""+string+"\""
			elif type == 11:
				#VA 8 bits, type index 16 bits
				va=oper
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				hexc+=binascii.hexlify(by)
				indx+=2
				value=from_bytes(by,"little")
				string=self.__String[self.__TypeIDS[value]].string_data_data
				opers="v"+str(va)+" , "+string
			elif type == 12:
				#VA 4 bits, VB 4 bits, type index 16 bits
				va=(oper & 0xF0) >> 4
				vb=oper &  0x0F
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				hexc+=binascii.hexlify(by)
				indx+=2
				value=from_bytes(by,"little")
				string=self.__String[self.__TypeIDS[value]].string_data_data
				opers="v"+str(va)+", v"+str(vb)+" , "+string
			elif type == 13:
				#24 VA 4 bits MSB operator word counts, VB 16 bits method index, VC VD VE VF 4 bits each -> INVOKE
				va=(oper & 0xF0) >> 4
				i=0
				v=[]
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				hexc+=binascii.hexlify(by)+" "
				vb=from_bytes(by,"little")
				string=self.__String[self.__TypeIDS[vb]].string_data_data
				indx+=2
				par=bytearray()
				par.append(cod.insns[indx])
				par.append(cod.insns[indx+1])
				hexc+=binascii.hexlify(par)
				indx+=2
				inc=0
				while i < va and i != 4:
					if i%2==0:
						by=par[inc]
						inc+=1
						#print bcolors.RED+str(i)+":"+str(by & 0x0F)+bcolors.ENDC
						v.append((by & 0x0F))
						i+=1
					else:
						#print bcolors.RED+str(i)+":"+str((by & 0xF0) >> 4)+bcolors.ENDC
						v.append((by & 0xF0) >> 4)
						i+=1
				if va == 5:
					v.append(oper & 0x0F)
				opers="{"
				for item in v:
					if item == v[-1]:
						opers+="v"+str(item)
					else:
						opers+="v"+str(item)+", "
				opers+="} "+string
			elif type == 14:
				#signed brach 8 bits
				if oper > 0x7F:
					oper -= 0x100
				opers=(indx-2)+oper
				opers="0x"+format(opers,'08x')
			elif type == 15:
				#signed brach 16 bits -> NOT ALLIGNED ->Aligned  by indx+=1
				by=bytearray()
				by.append(oper)
				by.append(cod.insns[indx])
				hexc+=binascii.hexlify(by)+" "
				oper=from_bytes(by,"little")
				indx+=2
				if oper > 0x7FFF:
					oper -= 0x10000
				opers=(indx-4)+oper
				opers="0x"+format(opers,'08x')
			elif type == 16:
				#signed brach 32 bits
				by=bytearray()
				by.append(oper)
				by.append(cod.insns[indx])
				hexc+=binascii.hexlify(by)+" "
				by.append(cod.insns[indx+1])
				by.append(cod.insns[indx+2])
				hexc+=binascii.hexlify(by[2:])
				indx+=3
				oper=from_bytes(by,"little")
				if oper > 0x7FFFFFFF:
					oper -= 0x100000000
				opers=(indx-4)+oper
				opers="0x"+format(opers,'08x')
			elif type == 17:
				#17 VA 8 bits, VB 32 bits
				va=oper
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				hexc+=binascii.hexlify(by)+" "
				by.append(cod.insns[indx+2])
				by.append(cod.insns[indx+3])
				hexc+=binascii.hexlify(by[2:])+" "
				vb=from_bytes(by,"little")
				indx+=4
				opers="v"+str(va)+", v"+str(vb)
			elif type == 18:
				#18 VA 8 bits, VB 8 bits, VC 8 bits
				va=oper
				vb=cod.insns[indx]
				hexc+=format(cod.insns[indx],'02x')
				vc=cod.insns[indx+1]
				hexc+=format(cod.insns[indx+1],'02x')
				indx+=2
				opers="v"+str(va)+", v"+str(vb)+", v"+str(vc)
			elif type == 19:
				#19 VA 4 bits, VB 4 bits, signed branch 16 bits
				va=(oper & 0xF0) >> 4
				vb=oper &  0x0F
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				hexc+=binascii.hexlify(by)
				value=from_bytes(by,"little")
				if value > 0x7FFF:
					value -= 0x10000
				indx+=2
				opers="v"+str(va)+", v"+str(vb)+" 0x"+format(value,'08x')
			elif type == 20:
				#20 VA 8 bits, signed branch 16 bits
				va=oper
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				hexc+=binascii.hexlify(by)
				value=from_bytes(by,"little")
				if value > 0x7FFF:
					value -= 0x10000
				indx+=2
				opers="v"+str(va)+" 0x"+format(value,'08x')
			elif type == 21:
				#21 VA 8 bits, VB 8 bits, VC 8 bits
				va=oper
				vb=cod.insns[indx]
				vc=cod.insns[indx+1]
				hexc+=format(cod.insns[indx],'02x')+" "+format(cod.insns[indx+1],'02x')
				indx+=2
				opers="v"+str(va)+", "+"v"+str(vb)+", "+"v"+str(vc)
			elif type == 22:
				#22 VA 4 bits, VB 4 bits, field index 16 bits
				va=(oper & 0xF0) >> 4
				vb=oper &  0x0F
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				hexc+=binascii.hexlify(by)
				field=self.from_bytes(by,"little")
				string=self.__String[self.__TypeIDS[self.__FieldIDS[field].class_idx]].string_data_data
				string+="->"+self.__String[self.__FieldIDS[field].name_idx].string_data_data
				indx+=2
				opers="v"+str(va)+", "+"v"+str(vb)+", "+string
			elif type == 23:
				#23 VA 8 bits, field index 16 bits
				va=oper
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				hexc+=binascii.hexlify(by)
				field=self.from_bytes(by,"little")
				indx+=2
				string=self.__String[self.__TypeIDS[self.__FieldIDS[field].class_idx]].string_data_data
				string+="->"+self.__String[self.__FieldIDS[field].name_idx].string_data_data
				string+=":"+self.__String[self.__TypeIDS[self.__FieldIDS[field].type_idx]].string_data_data
				opers="v"+str(va)+", "+string
			elif type == 24:
				#24 VA 4 bits MSB operator word counts, VB 16 bits method index, VC VD VE VF 4 bits each -> INVOKE
				va=(oper & 0xF0) >> 4
				#print bcolors.RED+"numero:"+str(va)+bcolors.ENDC
				i=0
				v=[]
				#if va > 0:
				#	v.append(oper & 0x0F)
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				hexc+=binascii.hexlify(by)+" "
				vb=self.from_bytes(by,"little")
				#print "VB:"+str(vb)
				string=self.__String[self.__TypeIDS[self.__MethodIDS[vb].class_idx]].string_data_data
				string+="->"+self.__String[self.__MethodIDS[vb].name_idx].string_data_data
				indx+=2
				par=bytearray()
				par.append(cod.insns[indx])
				par.append(cod.insns[indx+1])
				hexc+=binascii.hexlify(par)
				indx+=2
				inc=0
				while i < va and i != 4:
					if i%2==0:
						by=par[inc]
						inc+=1
						#print bcolors.RED+str(i)+":"+str(by & 0x0F)+bcolors.ENDC
						v.append((by & 0x0F))
						i+=1
					else:
						#print bcolors.RED+str(i)+":"+str((by & 0xF0) >> 4)+bcolors.ENDC
						v.append((by & 0xF0) >> 4)
						i+=1
				if va == 5:
					v.append(oper & 0x0F)
				opers="{"
				for item in v:
					if item == v[-1]:
						opers+="v"+str(item)
					else:
						opers+="v"+str(item)+", "
				opers+="} "+string
			elif type == 25:
				#VA 8 bits, VB 16 bits method index, VC 16 bits -> INVOKE RANGE
				va=oper
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				vb=self.from_bytes(by,"little")
				string=self.__String[self.__TypeIDS[self.__MethodIDS[vb].class_idx]].string_data_data
				string+="->"+self.__String[self.__MethodIDS[vb].name_idx].string_data_data
				hexc+=binascii.hexlify(by)+" "
				indx+=2
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				hexc+=binascii.hexlify(by)
				vc=self.from_bytes(by,"little")
				indx+=2
				opers="{ v"+str(vc)
				i=1
				while i < va:
					vc+=1
					opers+=", v"+str(vc)
					i+=1
				opers+="} " + string
			elif type == 26:
				#18 VA 8 bits, VB 8 bits, signed integer 8 bits
				va=oper
				vb=cod.insns[indx]
				hexc+=format(cod.insns[indx],'02x')
				vc=cod.insns[indx+1]
				if vc > 0x7F:
					vc -= 0x100
				hexc+=format(cod.insns[indx+1],'02x')
				indx+=2
				opers="v"+str(va)+", v"+str(vb)+", "+str(vc)
			elif type == 27:
				#27 VA 8 bits, branch 32 bits, sparse-switch & fill array data
				va=oper
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				hexc+=binascii.hexlify(by)+" "
				by.append(cod.insns[indx+2])
				by.append(cod.insns[indx+3])
				hexc+=binascii.hexlify(by[2:])+" "
				vb=from_bytes(by,"little")
				indx+=4
				opers="v"+str(va)+", "+str(vb)
			elif type == 28:
				#VA 8 bits, VB 16 bits method index, VC 16 bits -> filled-new-array/range
				va=oper
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				vb=self.from_bytes(by,"little")
				string=self.__String[self.__TypeIDS[vb]].string_data_data
				hexc+=binascii.hexlify(by)
				indx+=2
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				hexc+=binascii.hexlify(by)
				vc=self.from_bytes(by,"little")
				indx+=2
				opers="{ v"+str(vc)
				i=1
				while i < va:
					vc+=1
					opers+=", v"+str(vc)
					i+=1
				opers+="}" + string
			returned.append(hexc)
			returned.append(dy.dict[opc]+" "+opers)
			#print returned
		return returned

	def ParseByteCode(self,cod,opcode):
		returned=[]
		indx=0
		dy=ByteCodeDictionary()
		while indx<(cod.insns_size*2):
			opc=cod.insns[indx]
			oper=cod.insns[indx+1]
			indx+=2
			opers=""
			type=dy.oper[opc]
			if type == 0:
				#ident	ushort = 0x0200	identifying pseudo-opcode
				if oper == 0x02:
					#returned.append("Switch table:")
					#Size	ushort	number of entries in the table
					by=bytearray()
					by.append(cod.insns[indx])
					by.append(cod.insns[indx+1])
					indx+=2
					size=from_bytes(by,"little")
					#Keys	int[]	list of size key values, sorted low-to-high
					#indice=0
					#key=[]
					indx=indx+(4*size)
					#while indice<size:
						#by=bytearray()
						#by.append(cod.insns[indx])
						#by.append(cod.insns[indx+1])
						#by.append(cod.insns[indx+2])
						#by.append(cod.insns[indx+3])
						#indx+=4
						#by.reverse()
						#key.append(by)
						#hexc="0x"+binascii.hexlify(by)
						#returned.append(hexc)
						#returned.append("Key:"+str(key))
						#indice+=1
					#targets	int[]	list of size relative branch targets, each corresponding to
					#the key value at the same index. The targets are relative to the address of
					#the switch opcode, not of this table.
					#indice=0
					indx=indx+(4*size)
					#while indice<size:
						#by=bytearray()
						#by.append(cod.insns[indx])
						#by.append(cod.insns[indx+1])
						#by.append(cod.insns[indx+2])
						#by.append(cod.insns[indx+3])
						#indx+=4
						#item=from_bytes(by,"little")
						#returned.append("0x"+binascii.hexlify(key[indice])+" -> "+str(item))
						#indice+=1
					continue

				#ident	ushort = 0x0100	identifying pseudo-opcode
				elif oper == 0x01:
					#returned.append(hexc)
					#returned.append("Packed Swtich Table:")
					#Size	ushort	number of entries in the table
					by=bytearray()
					by.append(cod.insns[indx])
					by.append(cod.insns[indx+1])
					indx+=2
					size=from_bytes(by,"little")
					#hexc="0x"+binascii.hexlify(by)
					#returned.append(hexc)
					#returned.append("Size:"+str(size))
					#First_key	int	first (and lowest) switch case value
					#key=0
					#by=bytearray()
					#by.append(cod.insns[indx])
					#by.append(cod.insns[indx+1])
					#by.append(cod.insns[indx+2])
					#by.append(cod.insns[indx+3])
					indx+=4
					#hexc="0x"+binascii.hexlify(by)
					#by.reverse()
					#key=by
					#returned.append(hexc)
					#returned.append("Key:0x"+binascii.hexlify(key))
					#targets	int[]	list of size relative branch targets. The targets are relative to
					#the address of the switch opcode, not of this table.
					#indice=0
					indx=indx+(size*4)
					#while indice<size:
						#by=bytearray()
						#by.append(cod.insns[indx])
						#by.append(cod.insns[indx+1])
						#by.append(cod.insns[indx+2])
						#by.append(cod.insns[indx+3])
						#indx+=4
						#item=from_bytes(by,"little")
						#hexc="0x"+binascii.hexlify(by)
						#returned.append(hexc)
						#returned.append(str(item))
						#indice+=1
					continue

				elif oper == 0x03:
					#Element_width	ushort	number of bytes in each element
					by=bytearray()
					by.append(cod.insns[indx])
					by.append(cod.insns[indx+1])
					indx+=2
					width=from_bytes(by,"little")
					hexc="0x"+str(binascii.hexlify(by))
					#size	uint	number of elements in the table
					by=bytearray()
					by.append(cod.insns[indx])
					by.append(cod.insns[indx+1])
					by.append(cod.insns[indx+2])
					by.append(cod.insns[indx+3])
					indx+=4
					size=from_bytes(by,"little")
					#data	ubyte[]	data values
					#indice=0
					#Qua si puo modificare ancora -> Ogni elemento e' grande width e sono size
					#back=indx
					#while indice<size:
					#	by=bytearray()
					#	dt=0
					#	while dt < width:
					#		by.append(cod.insns[back])
					#		dt+=1
					#		back+=1
					#	indice+=1
					indx+=int((size * width + 1)/2)*2
					continue
				opers=""
			elif type == 1:
				#VA 4 bits, VB 4 bits
				va=(oper & 0xF0) >> 4
				vb=oper &  0x0F
				opers="v"+str(va)+", v"+str(vb)
			elif type == 2:
				#VA 8 bits, VB 16 bits
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				vb=self.from_bytes(by,"little")
				va=oper
				opers="v"+str(va)+", v"+str(vb)
				indx+=2
			elif type == 3:
				#VA 16 bits, VB 16 bits -> NOT ALLIGNED!
				by=bytearray()
				by.append(oper)
				by.append(cod.insns[indx+1])
				indx+=2
				va=self.from_bytes(by,"little")
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				indx+=2
				vb=self.from_bytes(by,"little")
				opers="v"+str(va)+", v"+str(vb)
			elif type == 4:
				#VA 8 bits
				opers="v"+str(oper)
			elif type == 5:
				#VA 4 bits, signed int 4 bits
				value=(oper & 0xF0) >> 4
				va=oper &  0x0F
				opers="v"+str(va)+"= "+str(value)
			elif type == 6:
				#VA 8 bits, signed int 16 bits
				by=bytearray()
				by.append(0x00)
				by.append(0x00)
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				value=self.from_bytes(by,"little")
				indx+=2
				va=oper
			elif type == 7:
				#VA 8 bits, signed int 32 bits
				va=oper
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				by.append(cod.insns[indx+2])
				by.append(cod.insns[indx+3])
				indx+=4
				value=self.from_bytes(by,"little")
				opers="v"+str(va)+"= "+str(value)
			elif type == 8:
				#VA 8 bits, signed int 64 bits
				va=oper
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				by.append(cod.insns[indx+2])
				by.append(cod.insns[indx+3])
				indx+=4
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				by.append(cod.insns[indx+2])
				by.append(cod.insns[indx+3])
				indx+=4
				value=self.from_bytes(by,"little")
				opers="v"+str(va)+"= "+str(value)
			elif type == 9:
				#VA 8 bits, string index 16 bits
				va=oper
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				indx+=2
				value=self.from_bytes(by,"little")
				#string=self.__String[value].string_data_data
				opers="v"+str(va)+"= "+str(value)
			elif type == 10:
				#VA 8 bits, string index 32 bits
				va=oper
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				by.append(cod.insns[indx+2])
				by.append(cod.insns[indx+3])
				indx+=4
				value=self.from_bytes(by,"little")
				#string=self.__String[value].string_data_data
				opers="v"+str(va)+"= "+str(value)
			elif type == 11:
				#VA 8 bits, type index 16 bits
				va=oper
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				indx+=2
				value=self.from_bytes(by,"little")
				#string=self.__String[self.__TypeIDS[value]].string_data_data
				opers="v"+str(va)+", "+str(value)
			elif type == 12:
				#VA 4 bits, VB 4 bits, type index 16 bits
				va=(oper & 0xF0) >> 4
				vb=oper &  0x0F
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				indx+=2
				value=self.from_bytes(by,"little")
				#string=self.__String[self.__TypeIDS[value]].string_data_data
				opers="v"+str(va)+", v"+str(vb)+", "+str(value)
			elif type == 13:
				#FILLED NEW ARRAY -> TO IMPLEMENTS
				opers="TO IMPLEMENTS -> MAYBE THERE ARE ERRORS"
			elif type == 14:
				#signed brach 8 bits
				opers=str(oper)
			elif type == 15:
				#signed brach 16 bits -> NOT ALLIGNED -> Aligned by indx+=1
				by=bytearray()
				by.append(oper)
				by.append(cod.insns[indx])
				indx+=2
				opers=str(self.from_bytes(by,"little"))
			elif type == 16:
				#signed brach 32 bits
				by=bytearray()
				by.append(oper)
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				by.append(cod.insns[indx+2])
				indx+=3
				opers=self.from_bytes(by,"little")
			elif type == 17:
				#17 VA 8 bits, VB 32 bits
				va=oper
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				by.append(cod.insns[indx+2])
				by.append(cod.insns[indx+3])
				vb=from_bytes(by,"little")
				indx+=4
				opers="v"+str(va)+", v"+str(vb)
			elif type == 18:
				#18 VA 8 bits, VB 8 bits, VC 8 bits
				va=oper
				vb=cod.insns[indx]
				vc=cod.insns[indx+1]
				indx+=2
				opers="v"+str(va)+", v"+str(vb)+", v"+str(vc)
			elif type == 19:
				#19 VA 4 bits, VB 4 bits, signed branch 16 bits
				va=(oper & 0xF0) >> 4
				vb=oper &  0x0F
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				indx+=2
				opers="v"+str(va)+", v"+str(vb)+" ,"+str(self.from_bytes(by,"little"))
			elif type == 20:
				#20 VA 8 bits, signed branch 16 bits
				va=oper
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				indx+=2
				opers="v"+str(va)+", "+str(self.from_bytes(by,"little"))
			elif type == 21:
				#21 VA 8 bits, VB 8 bits, VC 8 bits
				va=oper
				vb=cod.insns[indx]
				vc=cod.insns[indx+1]
				indx+=2
				opers="v"+str(va)+", "+"v"+str(vb)+", "+"v"+str(vc)
			elif type == 22:
				#22 VA 4 bits, VB 4 bits, field index 16 bits
				va=(oper & 0xF0) >> 4
				vb=oper &  0x0F
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				field=self.from_bytes(by,"little")
				#string=self.__String[self.__FieldIDS[field].class_idx].string_data_data
				#string+="->"+self.__String[self.__FieldIDS[field].name_idx].string_data_data
				indx+=2
				opers="v"+str(va)+", "+"v"+str(vb)+", "+str(field)
			elif type == 23:
				#23 VA 8 bits, field index 16 bits
				va=oper
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				field=self.from_bytes(by,"little")
				indx+=2
				#string=self.__String[self.__TypeIDS[self.__FieldIDS[field].class_idx]].string_data_data
				#string+="->"+self.__String[self.__FieldIDS[field].name_idx].string_data_data
				#string+=":"+self.__String[self.__TypeIDS[self.__FieldIDS[field].type_idx]].string_data_data
				opers="v"+str(va)+", "+str(field)
			elif type == 24:
				#24 VA 4 bits MSB operator word counts, VB 16 bits method index, VC VD VE VF 4 bits each -> INVOKE
				va=(oper & 0xF0) >> 4
				#print bcolors.RED+"numero:"+str(va)+bcolors.ENDC
				i=0
				v=[]
				#if va > 0:
				#	v.append(oper & 0x0F)
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				vb=self.from_bytes(by,"little")
				#print "VB:"+str(vb)
				indx+=2
				par=bytearray()
				par.append(cod.insns[indx])
				par.append(cod.insns[indx+1])
				indx+=2
				inc=0
				while i < va and i != 4:
					if i%2==0:
						by=par[inc]
						inc+=1
						#print bcolors.RED+str(i)+":"+str(by & 0x0F)+bcolors.ENDC
						v.append((by & 0x0F))
						i+=1
					else:
						#print bcolors.RED+str(i)+":"+str((by & 0xF0) >> 4)+bcolors.ENDC
						v.append((by & 0xF0) >> 4)
						i+=1
				if va == 5:
					v.append(oper & 0x0F)
				opers="{"
				for item in v:
					if item == v[-1]:
						opers+="v"+str(item)
					else:
						opers+="v"+str(item)+","
				opers+="} "+str(vb)
			elif type == 25:
				#VA 8 bits, VB 16 bits method index, VC 16 bits -> INVOKE
				va=oper
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				vb=self.from_bytes(by,"little")
				#string=self.__String[self.__TypeIDS[self.__MethodIDS[vb].class_idx]].string_data_data
				#string+="->"+self.__String[self.__MethodIDS[vb].name_idx].string_data_data
				indx+=2
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				vc=self.from_bytes(by,"little")
				indx+=2
				opers="{ v"+str(vc)
				i=1
				while i < va:
					vc+=1
					opers+=", v"+str(vc)
					i+=1
				opers+="} " + str(vb)
			elif type == 26:
				#18 VA 8 bits, VB 8 bits, signed integer 8 bits
				va=oper
				vb=cod.insns[indx]
				vc=cod.insns[indx+1]
				indx+=2
				opers="v"+str(va)+", v"+str(vb)+", "+str(vc)
			elif type == 27:
				#27 VA 8 bits, branch 32 bits, sparse-switch
				va=oper
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				by.append(cod.insns[indx+2])
				by.append(cod.insns[indx+3])
				vb=from_bytes(by,"little")
				indx+=4
				opers="v"+str(va)+", "+str(vb)
			#print dy.dict[opc]+" "+opers
			if opc in opcode:
				returned.append(dy.dict[opc]+" "+opers)
		return returned

	#For parsing static value
	def decodeType(self,type,f):
		#value arg 1110 0000 ->E0
		value_arg=(type & 0xE0) >> 5
		value_type=type & 0x1F
		size=value_arg
		item=0x00
		if value_type == 0x1E:
			#VALUE NULL
			item=0x00
			return item
		by=bytearray()
		i=0
		print ("VALUE ARG F:"+str(value_arg))
		print ("VALUE type F:"+str(value_type))
		if value_type == 0x1D:
			#VALUE ANNOTATION -> Probabily we should use a function
			enc=CClassDEF.encoded_annotation()
			enc.type_idx=self.decodeULEB(f)
			enc.size=self.decodeULEB(f)
			i=0
			while i < size:
				name=self.decodeULEB(f)
				#from bytes?
				value=self.decodeType(int(binascii.hexlify(f.read(1)),16),f)
				enc.elements[name]=value
				i+=1
			item=enc
		elif value_type == 0x1F:
			#VALUE BOOLEAN
			value_arg=value_arg
			if value_arg!=0:
				item=True
			else:
				item=False
		else:
			i=0
			print ("Size:"+str(size))
			if size != 0:
				by=bytearray(f.read(size+1))
			else:
				by.append(0x00)
			print ("BIN:"+binascii.hexlify(by))
			if value_type == 0x00:
				#VALUE BYTE SIGNED
				item=int(binascii.hexlify(f.read(1)),16)
				#return item
			elif value_type == 0x02:
				#VALUE SHORT SIGNED
				item=from_bytes(by,"little")
			elif value_type == 0x03:
				#VALUE CHAR UNSIGNED
				item=from_bytes(by,"little")
				print (item)
				item="'"+chr(item)+"'"
			elif value_type == 0x04:
				#VALUE INT SIGNED
				item=from_bytes(by,"little")

			elif value_type == 0x06:
				#VALUE LONG SIGNED
				item=from_bytes(by,"little")
			elif value_type == 0x10:
				#VALUE FLOAT IEEE754 32-bit floating point value
				item=from_bytes(by,"little")
			elif value_type == 0x11:
				#VALUE DOUBLE IEEE754 64-bit floating point value
				item=from_bytes(by,"little")
			elif value_type == 0x17:
				#VALUE STRING UNSIGNED -> INDEX STRING_IDS
				item=from_bytes(by,"little")
				item="\""+self.__String[item].string_data_data+"\""
			elif value_type == 0x18:
				#VALUE TYPE UNSIGNED -> INDEX TYPE_IDS
				item=from_bytes(by,"little")
				item="\""+self.__String[self.__TypeIDS[item]].string_data_data+"\""
			elif value_type == 0x19:
				#VALUE FIELD UNSIGNED -> INDEX FIELD_IDS
				item=from_bytes(by,"little")
				print (item)
				stri=self.__String[self.__FieldIDS[item].name_idx].string_data_data
				stri+=":"+self.__String[self.__TypeIDS[self.__FieldIDS[item].type_idx]].string_data_data
				item=stri
			elif value_type == 0x1A:
				#VALUE METHOD UNSIGNED -> INDEX METHOD_IDS
				item=from_bytes(by,"little")
				#str=self.__String[self.__FieldIDS[item].name_idx].string_data_data
				#str+=":"+self.__String[self.__TypeIDS[self.__FieldIDS[item].type_idx]].string_data_data
			elif value_type == 0x1B:
				#VALUE ENUM UNSIGNED -> INDEX FIELD_IDS
				item=from_bytes(by,"little")
			elif value_type == 0x1C:
				#VALUE ARRAY -> COMPLICATO
				item=from_bytes(by,"little")
		return item

	def readClass(self,indx):
		#Check Index
		if type(indx) is not int:
			print (bcolors.RED+"Error. Index is not integer"+bcolors.ENDC)
			return -1
		if indx not in self.__ClassDEF:
			print (bcolors.RED+"Error. Maybe the class is native?"+bcolors.ENDC)
			return -1
		classname=self.__String[self.__TypeIDS[indx]].string_data_data
		i=self.__ClassDEF[indx]
		if (i.read==True):
			return indx
		#print (bcolors.BOLD+"\nReading class:"+classname)
		#Read static field -> CHECK
		'''
		if i.static_values_off != 0:
			self.dexFl.seek(i.static_values_off)
			st=i.encoded_array()
			st.size=self.decodeULEB(self.dexFl)
			indx=0
			while indx < st.size:
				print bcolors.BOLD+"READING STATIC VALUE"
				field=i.encoded_value()
				#From bytes?
				field.value_arg=int(binascii.hexlify(self.dexFl.read(1)),16)
				#print "FIELD VALUE:"+str(field.value_arg)
				field.value=self.decodeType(field.value_arg,self.dexFl)
				print "VALORE:"+str(field.value)
				i.cdi.static_values.append(field)
				indx+=1
			#i.static_values=st
		'''
		#class_data_off
		#CHECK 0 VALUE IF NOT DATA SET
		if i.class_data_off != 0:
			self.dexFl.seek(i.class_data_off)
			#print "\nReading offsets..."
			i.cdi.static_fields_size=self.decodeULEB(self.dexFl)
			i.cdi.instance_fields_size=self.decodeULEB(self.dexFl)
			i.cdi.direct_methods_size=self.decodeULEB(self.dexFl)
			i.cdi.virtual_methods_size=self.decodeULEB(self.dexFl)

			#print "\nReading static fields..."
			ind=0
			while ind < i.cdi.static_fields_size:
				enc=i.encoded_field()
				enc.field_idx_diff=self.decodeULEB(self.dexFl)
				#print "statico FIELD_IDX_DIFF:"+str(enc.field_idx_diff)
				enc.access_flags=self.decodeULEB(self.dexFl)
				#print "statico flag:"+str(enc.access_flags)
				i.cdi.static_fields.append(enc)
				ind+=1

			#print "\nReading instance fields..."
			ind=0
			while ind < i.cdi.instance_fields_size:
				enc=i.encoded_field()
				enc.field_idx_diff=self.decodeULEB(self.dexFl)
				#print "FIELD_IDX_DIFF:"+str(enc.field_idx_diff)
				enc.access_flags=self.decodeULEB(self.dexFl)
				i.cdi.instance_fields.append(enc)
				ind+=1

			#print "\nReading the direct methods..."
			ind=0
			while ind < i.cdi.direct_methods_size:
				enc=i.encoded_method()
				enc.method_idx_diff=self.decodeULEB(self.dexFl)
				enc.access_flags=self.decodeULEB(self.dexFl)
				enc.code_off=self.decodeULEB(self.dexFl)
				i.cdi.direct_methods.append(enc)
				ind+=1

			#print "\nReading the virtual methods..."
			ind=0
			while ind < i.cdi.virtual_methods_size:
				enc=i.encoded_method()
				enc.method_idx_diff=self.decodeULEB(self.dexFl)
				enc.access_flags=self.decodeULEB(self.dexFl)
				enc.code_off=self.decodeULEB(self.dexFl)
				i.cdi.virtual_methods.append(enc)
				ind+=1
			#print"\n"
		i.read=True
		return indx

	def from_bytes(self,data,endianess):
		if endianess=="little":
			data.reverse()
		return int(binascii.hexlify(data),16)

	def decodeULEB(self,f):
		#print "Where?:"+str(f.tell())
		by=bytearray()
		while True:
			t=f.read(1)
			by.append(int.from_bytes(t, byteorder='little'))
			#print binascii.hexlify(by)
			if by[-1] & 0x80==0:
				break
			else:
				by[-1]=by[-1] & 0x7F
		by.reverse()
		#print binascii.hexlify(by)
		tot=0
		shift=1
		for i in by:
			tot=tot << 7*shift
			#print "totale_shift:"+str(tot)
			tot=tot | i
			#shift+=1
			#print "totale:"+str(tot)
		return tot

	def getListfromIndex(self,indx):
		self.dexFl.seek(indx)
		size=self.from_bytes(bytearray(self.dexFl.read(4)),"little")
		i=0
		returned=[]
		while i < size:
			item=self.from_bytes(bytearray(self.dexFl.read(2)),"little")
			returned.append(item)
			i+=1
		return returned

	def printMethod(self,clax,indx=None):
		#Direct Method
		dim=[clax.cdi.direct_methods_size,clax.cdi.virtual_methods_size]
		type=[clax.cdi.direct_methods,clax.cdi.virtual_methods]
		mod=0
		while mod != 2:
			index=0
			pr=0
			while index < dim[mod]:
				k=type[mod][index]
				meth=self.__MethodIDS[k.method_idx_diff+pr]
				if indx == None or indx == k.method_idx_diff+pr:
					inc=1
					flg=k.access_flags
					acc=""
					while flg!=0:
						if flg % 2 == 1:
							acc=acc+" "+clax.access_flagd[inc]
						inc+=1
						flg=flg >> 1
					metd=bcolors.RED
					metd+=acc[1:]+" "
					prot=self.__ProtoIDS[meth.proto_idx]
					metd+=self.__String[meth.name_idx].string_data_data+" "
					ret=self.__TypeIDS[prot.return_type_idx]
					metd+="("
					if prot.parameters_off != 0:
						pp=self.getListfromIndex(prot.parameters_off)
						for item in pp:
							metd+=self.__String[self.__TypeIDS[item]].string_data_data
							if item != pp[-1]:
								metd+=","
					else:
						metd+="void"
					metd+=")->"
					metd+=self.__String[ret].string_data_data
					print (metd+"\n")
					#Insert Code!
					if k.code_off!=0:
						#OPTIMIZATION POSSIBLE
						cod=(self.getCode(k.code_off))
						self.PrintCodeClass(cod)
					print("\n\n")
				pr=k.method_idx_diff+pr
				index+=1
			mod+=1

	def xrefto(self,obj,indx):
		if isinstance(obj,CMethodIDS):
			#ReadClass and check not native
			#clax=self.__String[self.__TypeIDS[]].string_data_data
			i=self.readClass(obj.class_idx)
			if i < 0:
				return
			i=self.__ClassDEF[i]
			#Return bytecode
			opcode=[0x6E,0x6F,0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78]
			dim=[i.cdi.direct_methods_size,i.cdi.virtual_methods_size]
			ty=[i.cdi.direct_methods,i.cdi.virtual_methods]
			mod=0
			while mod != 2:
				index=0
				pr=0
				while index < dim[mod]:
					k=ty[mod][index]
					meth=self.__MethodIDS[k.method_idx_diff+pr]
					if indx == k.method_idx_diff+pr:
						#Insert Code!
						if k.code_off!=0:
							#OPTIMIZATION POSSIBLE
							cod=(self.getCode(k.code_off))
							ret=self.ParseByteCode(cod,opcode)
							for line in ret:
								vb=int(line.split()[-1])
								string=self.__String[self.__TypeIDS[self.__MethodIDS[vb].class_idx]].string_data_data
								string+="->"+self.__String[self.__MethodIDS[vb].name_idx].string_data_data
								print (bcolors.GREEN+"%-89s %-30s") % (string,"["+str(vb)+"]"+bcolors.ENDC)
					pr=k.method_idx_diff+pr
					index+=1
				mod+=1
		print ("")

	def xreffrom(self,obj,indx):
		if obj == "Method":
			opcode=[0x6E,0x6F,0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78]
		elif obj == "String":
			opcode=[0x1A,0x1B]
		elif obj == "Type":
			opcode=[0x1C,0x1F,0x22,0x20,0x23]
		elif obj == "Field":
			opcode=[0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5A,0x5B,0x5C,0x5D,0x5E,0x5F,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6A,0x6B,0x6C,0x6D]

		#ReadClass and check not native
		#clxList=self.getClassesList()
		ina=0

		for item in self.__ClassDEF:
			ina+=1
			if self.readClass(item) < 0:
				print (bcolors.RED+"Something really go wrong here..."+bcolors.ENDC)
				return -1
			i=self.__ClassDEF[item]
			#Return bytecode
			#print "class:"+item
			dim=[i.cdi.direct_methods_size,i.cdi.virtual_methods_size]
			ty=[i.cdi.direct_methods,i.cdi.virtual_methods]
			mod=0
			while mod != 2:
				index=0
				pr=0
				while index < dim[mod]:
					k=ty[mod][index]
					meth=self.__MethodIDS[k.method_idx_diff+pr]
					#Insert Code!
					if k.code_off!=0:
						#OPTIMIZATION POSSIBLE

						cod=(self.getCode(k.code_off))
						ret=self.ParseByteCode(cod,opcode)
						for line in ret:
							vb=int(line.split()[-1])
							if vb == indx:
								if obj == "Method":
									string=self.__String[self.__TypeIDS[meth.class_idx]].string_data_data
									string+="->"+self.__String[meth.name_idx].string_data_data
									print (bcolors.Yellow+"%-50s %-30s") % (string,"["+str(k.method_idx_diff+pr)+"]"+bcolors.ENDC)
								elif obj == "String":
									string=self.__String[self.__TypeIDS[meth.class_idx]].string_data_data
									string+="->"+self.__String[meth.name_idx].string_data_data
									print (bcolors.Yellow+string+"["+str(k.method_idx_diff+pr)+"]"+bcolors.ENDC)
									string = self.__String[vb].string_data_data
									codix=""
									for i in line.split():
										if i != line.split()[-1]:
											codix+=i+" "
									print (bcolors.Yellow+"\t"+codix+" "+string+"["+str(vb)+"]"+bcolors.ENDC)
								elif obj == "Type":
									string=self.__String[self.__TypeIDS[meth.class_idx]].string_data_data
									string+="->"+self.__String[meth.name_idx].string_data_data
									print (bcolors.Yellow+"%-89s %-30s") % (string,"["+str(k.method_idx_diff+pr)+"]"+bcolors.ENDC)
									string = self.__String[self.__TypeIDS[vb]].string_data_data
									codix=""
									for i in line.split():
										if i != line.split()[-1]:
											codix+=i+" "
									print (bcolors.Yellow+"\t%-20s %-60s %-30s") % (codix,string,"["+str(vb)+"]"+bcolors.ENDC)
								elif obj == "Field":
									string=self.__String[self.__TypeIDS[meth.class_idx]].string_data_data
									string+="->"+self.__String[meth.name_idx].string_data_data
									print (bcolors.Yellow+"%-89s %-30s") % (string,"["+str(k.method_idx_diff+pr)+"]"+bcolors.ENDC)
									string = self.__String[self.__FieldIDS[vb].name_idx].string_data_data
									codix=""
									for i in line.split():
										if i != line.split()[-1]:
											codix+=i+" "
									print (bcolors.Yellow+"\t%-20s %-60s %-30s") % (codix,string,"["+str(vb)+"]"+bcolors.ENDC)
					pr=k.method_idx_diff+pr
					index+=1
				mod+=1
	#Get Single Object

	#Info function
	def xClass(self,indx):
		pass
	def xMethod(self,indx):
		pass
	def xString(self,indx):
		#GREEN = '\033[92m'
		#BLUE = '\033[94m'
		#CYAN = '\033[96m'
		#Yellow = '\033[93m'
		#1.Method name
		print (bcolors.GREEN+"---- Method ----"+"\n")
		for m in self.__MethodIDS:
			if m.name_idx == indx:
				print (self.__String[self.__TypeIDS[m.class_idx]].string_data_data+"->"+self.__String[indx].string_data_data)
		print("\n")
		print (bcolors.BLUE+"---- Field ----"+"\n")
		for m in self.__FieldIDS:
			if m.name_idx == indx:
				print (self.__String[self.__TypeIDS[m.class_idx]].string_data_data+":"+self.__String[indx].string_data_data)
		print ("\n")
		print (bcolors.CYAN+"---- Type ----"+"\n")
		for m in self.__TypeIDS:
			if m == indx:
				print (self.__String[m].string_data_data)
		print ("\n")
		print (bcolors.Yellow+"---- Inside Code ----"+"\n")
		#More complex
		self.xreffrom("String",indx)
		print ("\n")
	def xType(self,indx):
		pass
	def xField(self,indx):
		pass

	#Search function
	def getClass(self,indx=None):
		indici=[]
		if indx==None:
			for i in self.__ClassDEF:
				strin=self.__String[self.__TypeIDS[i]].string_data_data
				print(bcolors.HEADER+"Class Index:\t"+bcolors.ENDC+str(i)+"\tClass Name:"+strin)
		if type(indx) is list:
			for i in indx:
				if type(i) is int:
					strin=self.__String[self.__TypeIDS[i]].string_data_data
					print(bcolors.HEADER+"Class Index:\t"+bcolors.ENDC+str(i)+"\tClass Name:"+strin)
				if type(i) is str:
					for ixx in self.__ClassDEF:
						strin=self.__String[self.__TypeIDS[ixx]].string_data_data
						if i.lower() in strin.lower():
							print(bcolors.HEADER+"Class Index:\t"+bcolors.ENDC+str(ixx)+"\tClass Name:"+strin)
		if type(indx) is int:
			strin=self.__String[self.__TypeIDS[indx]].string_data_data
			print(bcolors.HEADER+"Class Index:\t"+bcolors.ENDC+str(indx)+"\tClass Name:"+strin)
		if type(indx) is str:
			for i in self.__ClassDEF:
				strin=self.__String[self.__TypeIDS[i]].string_data_data
				if indx.lower() in strin.lower():
					print(bcolors.HEADER+"Class Index:\t"+bcolors.ENDC+str(indx)+"\tClass Name:"+strin)

	def getMethod(self,st=None):
		#The same method can collide in more than one class -> Iterate the process ->
		#Moreover, the st can be list -> iterate over all this stuff
		methodlist=[]
		if st==None:
			indx=0
			#returned={}
			while indx<len(self.__MethodIDS):
				meth=self.__MethodIDS[indx]
				clax=self.__String[self.__TypeIDS[meth.class_idx]].string_data_data
				name=self.__String[meth.name_idx].string_data_data
				#returned[name]=indx
				print (bcolors.HEADER+"Class\t\t"+bcolors.ENDC+bcolors.BOLD+clax)
				print (bcolors.HEADER+"Method\t\t"+bcolors.ENDC+bcolors.BOLD+name)
				print (bcolors.HEADER+"Method Index\t"+bcolors.ENDC+bcolors.BOLD+str(indx)+"\n")
				indx+=1
			#return returned
		if type(st) is list:
			for ss in st:
				if type(ss) is int:
					methodlist.append(ss)
				elif type(ss) is str:
					indx=0
					while indx<len(self.__MethodIDS):
						meth=self.__MethodIDS[indx]
						name=self.__String[meth.name_idx].string_data_data
						if st.lower() in name.lower():
							methodlist.append(indx)
						indx+=1
		elif type(st) is int:
			methodlist.append(st)
		elif type(st) is str:
			indx=0
			while indx<len(self.__MethodIDS):
				meth=self.__MethodIDS[indx]
				name=self.__String[meth.name_idx].string_data_data
				if st.lower() in name.lower():
					methodlist.append(indx)
				indx+=1

		#Starting iterate here
		returned={}
		for item in methodlist:
			meth=self.__MethodIDS[item]
			clax=self.__String[self.__TypeIDS[meth.class_idx]].string_data_data
			name=self.__String[meth.name_idx].string_data_data
			#returned[name]=item
			print (bcolors.HEADER+"Class\t\t"+bcolors.ENDC+bcolors.BOLD+clax)
			print (bcolors.HEADER+"Method\t\t"+bcolors.ENDC+bcolors.BOLD+name)
			print (bcolors.HEADER+"Method Index\t"+bcolors.ENDC+bcolors.BOLD+str(item)+"\n")
		#return returned

	def getString(self,string=None):
		#Find the string where is used and defined ->
		#Search in all code where this index is used
		indici=[]
		if string==None:
			indx=0
			while indx < len(self.__String):
				print(bcolors.HEADER+"String Index:\t"+bcolors.ENDC+str(indx)+"\tString:"+self.__String[indx].string_data_data)
				indx+=1
		if type(string) is list:
			for ss in string:
				if type(ss) is str:
					indx=0
					while indx<len(self.__String):
						if ss.lower() in self.__String[indx].string_data_data.lower():
							print(bcolors.HEADER+"String Index:\t"+bcolors.ENDC+str(indx)+"\tString:"+self.__String[indx].string_data_data)
						indx+=1
				elif type(ss) is int:
					print(bcolors.HEADER+"String Index:\t"+bcolors.ENDC+str(ss)+"\tString:"+self.__String[ss].string_data_data)
		if type(string) is str:
			indx=0
			while indx<len(self.__String):
				if string.lower() in self.__String[indx].string_data_data.lower():
					print(bcolors.HEADER+"String Index:\t"+bcolors.ENDC+str(indx)+"\tString:"+self.__String[indx].string_data_data)
				indx+=1
		elif type(string) is int:
			print ("["+self.__String[string].string_data_data+" , "+str(string)+"]")
			print(bcolors.HEADER+"String Index:\t"+bcolors.ENDC+str(string)+"\tString:"+self.__String[string].string_data_data)

	def getType(self,typex=None):
		#Find where a "type" is used and defined -> Check if it is a class, primitive or other
		indici=[]
		if typex==None:
			for i in self.__TypeIDS:
				print (bcolors.HEADER+"Type Index:\t"+bcolors.ENDC+bcolors.BOLD+str(i)+"\tType Name:\t"+self.__String[i].string_data_data)
		if type(typex) is list:
			for ss in typex:
				if type(ss) is str:
					indx=0
					while indx<len(self.__TypeIDS):
						strin=self.__String[self.__TypeIDS[indx]].string_data_data
						if ss.lower() in strin.lower():
							print (bcolors.HEADER+"Type Index:\t"+bcolors.ENDC+bcolors.BOLD+str(indx)+"\tType Name:\t"+strin)
						indx+=1
				elif type(ss) is int:
					print (bcolors.HEADER+"Type Index:\t"+bcolors.ENDC+bcolors.BOLD+str(ss)+"\tType Name:\t"+self.__String[self.__TypeIDS[ss]].string_data_data)
		if type(typex) is str:
			indx=0
			while indx<len(self.__TypeIDS):
				strin=self.__String[self.__TypeIDS[indx]].string_data_data
				if typex.lower() in strin.lower():
					print (bcolors.HEADER+"Type Index:\t"+bcolors.ENDC+bcolors.BOLD+str(indx)+"\tType Name:\t"+strin)
				indx+=1
		elif type(typex) is int:
			print (bcolors.HEADER+"Type Index:\t"+bcolors.ENDC+bcolors.BOLD+str(typex)+"\tType Name:\t"+self.__String[self.__TypeIDS[typex]].string_data_data)

	def getField(self,field=None):
		#find where a "field" is used and defined
		#Find where a "type" is used and defined -> Check if it is a class, primitive or other
		indici=[]
		if field==None:
			ix=0
			while ix < len(self.__FieldIDS):
				i=self.__FieldIDS[ix]
				print (bcolors.HEADER+"Class\t\t"+bcolors.ENDC+bcolors.BOLD+self.__String[self.__TypeIDS[i.class_idx]].string_data_data)
				print (bcolors.HEADER+"Field Type\t"+bcolors.ENDC+bcolors.BOLD+self.__String[self.__TypeIDS[i.type_idx]].string_data_data)
				print (bcolors.HEADER+"Field Name\t"+bcolors.ENDC+bcolors.BOLD+self.__String[i.name_idx].string_data_data)
				print (bcolors.HEADER+"Field Index\t"+bcolors.ENDC+bcolors.BOLD+str(ix)+"\n")
				ix+=1
		if type(field) is list:
			for ss in field:
				if type(ss) is str:
					indx=0
					while indx<len(self.__FieldIDS):
						if ss.lower() in self.__String[self.__FieldIDS[indx].name_idx].string_data_data.lower():
							indici.append(indx)
						indx+=1
				elif type(ss) is int:
					indici.append(ss)
		if type(field) is str:
			indx=0
			while indx<len(self.__FieldIDS):
				if field.lower() in self.__String[self.__FieldIDS[indx].name_idx].string_data_data.lower():
					indici.append(indx)
				indx+=1
		elif type(field) is int:
			indici.append(field)
		returned={}
		for i in indici:
			tp=self.__FieldIDS[i]
			print (bcolors.HEADER+"Class\t\t"+bcolors.ENDC+bcolors.BOLD+self.__String[self.__TypeIDS[tp.class_idx]].string_data_data)
			print (bcolors.HEADER+"Field Type\t"+bcolors.ENDC+bcolors.BOLD+self.__String[self.__TypeIDS[tp.type_idx]].string_data_data)
			print (bcolors.HEADER+"Field Name\t"+bcolors.ENDC+bcolors.BOLD+self.__String[tp.name_idx].string_data_data)
			print (bcolors.HEADER+"Field Index\t"+bcolors.ENDC+bcolors.BOLD+str(i)+"\n")

	def printHeader(self):
		print (self.__Head)

	#ReadFile
	def ReadDex(self,f=None):
		#The APK has only one classes.dex
		if hasattr(self,'dexFl') == True and f!=None:
			self.dexFl=f
		elif hasattr(self,'dexFl') == True and f==None:
			f=self.dexFl
		elif f==None and hasattr(self,'dexFl') == False:
			print ("Must select a classes.dex first")
			return
		else:
			self.dexFl=f

		print (bcolors.HEADER+"\nReading header...")
		self.__Head.MagicNumber=bytearray(f.read(8))
		self.__Head.checksum=bytearray(f.read(4))
		self.__Head.signature=bytearray(f.read(20))
		self.__Head.file_size=bytearray(f.read(4))
		self.__Head.header_size=bytearray(f.read(4))
		self.__Head.endian_tag=bytearray(f.read(4))
		if self.__Head.endian_tag[0] == 0x78:
			order="little"
		else:
			order="big"
		self.__Head.file_size=self.from_bytes(self.__Head.file_size, order)
		self.__Head.header_size=self.from_bytes(self.__Head.header_size, order)
		self.__Head.link_size=self.from_bytes(bytearray(f.read(4)),order)
		self.__Head.link_off=self.from_bytes(bytearray(f.read(4)),order)
		self.__Head.map_off=self.from_bytes(bytearray(f.read(4)),order)
		self.__Head.string_ids_size=self.from_bytes(bytearray(f.read(4)),order)
		self.__Head.string_ids_off=self.from_bytes(bytearray(f.read(4)),order)
		self.__Head.type_ids_size=self.from_bytes(bytearray(f.read(4)),order)
		self.__Head.type_ids_off=self.from_bytes(bytearray(f.read(4)),order)
		self.__Head.proto_ids_size=self.from_bytes(bytearray(f.read(4)),order)
		self.__Head.proto_ids_off=self.from_bytes(bytearray(f.read(4)),order)
		self.__Head.field_ids_size=self.from_bytes(bytearray(f.read(4)),order)
		self.__Head.field_ids_off=self.from_bytes(bytearray(f.read(4)),order)
		self.__Head.method_ids_size=self.from_bytes(bytearray(f.read(4)),order)
		self.__Head.method_ids_off=self.from_bytes(bytearray(f.read(4)),order)
		self.__Head.class_defs_size=self.from_bytes(bytearray(f.read(4)),order)
		self.__Head.class_defs_off=self.from_bytes(bytearray(f.read(4)),order)
		self.__Head.data_size=self.from_bytes(bytearray(f.read(4)),order)
		self.__Head.data_off=self.from_bytes(bytearray(f.read(4)),order)
		#Strings
		print (bcolors.HEADER+"\nReading strings...")
		f.seek(self.__Head.string_ids_off)
		i=0
		while i < self.__Head.string_ids_size:
			s=StringIDS()
			s.string_data_off=self.from_bytes(bytearray(f.read(4)),order)
			i+=1
			self.__String.append(s)
		for strx in self.__String:
			offset=strx.string_data_off
			f.seek(offset)
			strx.string_data_len=self.decodeULEB(f)
			s=f.read(strx.string_data_len)
			#Reading string_data_data
			strx.string_data_data=str(s)

		#Type
		print ("\nReading types...")
		f.seek(self.__Head.type_ids_off)
		i=0
		while i < self.__Head.type_ids_size:
			index=self.from_bytes(bytearray(f.read(4)),order)
			i+=1
			self.__TypeIDS.append(index)

		#Protype
		print ("\nReading prototypes...")
		f.seek(self.__Head.proto_ids_off)
		i=0
		while i < self.__Head.proto_ids_size:
			s=CProtoIDS()
			s.shorty_idx=from_bytes(bytearray(f.read(4)),order)
			s.return_type_idx=from_bytes(bytearray(f.read(4)),order)
			s.parameters_off=from_bytes(bytearray(f.read(4)),order)
			i+=1
			self.__ProtoIDS.append(s)
		for p in self.__ProtoIDS:
			if p.parameters_off != 0:
				f.seek(p.parameters_off)
				len=from_bytes(bytearray(f.read(4)),order)
				indx=0
				while indx < len:
					x=from_bytes(bytearray(f.read(2)),order)
					p.parameters.append(x)
					indx+=1

		#Fields
		print ("\nReading fields...")
		f.seek(self.__Head.field_ids_off)
		i=0
		#print self.__Head.field_ids_off
		while i < self.__Head.field_ids_size:
			s=CFieldIDS()
			s.class_idx=self.from_bytes(bytearray(f.read(2)),"little")
			s.type_idx=self.from_bytes(bytearray(f.read(2)),"little")
			s.name_idx=self.from_bytes(bytearray(f.read(4)),"little")
			#print str(i)+":\tClass:"+str(s.class_idx)+"\tField:"+str(s.name_idx)
			i+=1
			self.__FieldIDS.append(s)

		#Methods
		print ("\nReading methods...")
		f.seek(self.__Head.method_ids_off)
		i=0
		while i < self.__Head.method_ids_size:
			s=CMethodIDS()
			s.class_idx=self.from_bytes(bytearray(f.read(2)),order)
			s.proto_idx=self.from_bytes(bytearray(f.read(2)),order)
			s.name_idx=self.from_bytes(bytearray(f.read(4)),order)
			i+=1
			self.__MethodIDS.append(s)


		#CLASSES
		print ("\nReading classes...")
		f.seek(self.__Head.class_defs_off)
		i=0
		while i < self.__Head.class_defs_size:
			s=CClassDEF()
			s.class_idx=self.from_bytes(bytearray(f.read(4)),order)
			s.access_flags=self.from_bytes(bytearray(f.read(4)),order)
			s.superclass_idx=self.from_bytes(bytearray(f.read(4)),order)
			s.interfaces_off=self.from_bytes(bytearray(f.read(4)),order)
			s.source_file_idx=self.from_bytes(bytearray(f.read(4)),order)
			s.annotations_off=self.from_bytes(bytearray(f.read(4)),order)
			s.class_data_off=self.from_bytes(bytearray(f.read(4)),order)
			s.static_values_off=self.from_bytes(bytearray(f.read(4)),order)
			i+=1
			self.__ClassDEF[s.class_idx]=s
