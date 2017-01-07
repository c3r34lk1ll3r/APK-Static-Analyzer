#READ CLASS.DEX

import binascii
import math
from btcodedict import *
from type import *

#Modify Read Byte in utility class

class bcolors:
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'
	RED = '\033[91m'
	GREEN = '\033[92m'
	BLUE = '\033[94m'
	CYAN = '\033[96m'
	White = '\033[97m'
	Yellow = '\033[93m'
	Magenta = '\033[95m'
	Grey = '\033[90m'
	Black = '\033[90m'
	Default = '\033[99m'

def from_bytes(data,endianess):
	if endianess=="little":
		data.reverse()
	return int(binascii.hexlify(data),16)
	
class DexFile:

	def __init__(self,f=None):
		if f!=None:
			self.dexFl=f
		self.Head=Header()
		self.String=[]
		self.TypeIDS=[]
		self.ProtoIDS=[]
		self.FieldIDS=[]
		self.MethodIDS=[]
		self.ClassDEF={}
		if f!=None:
			self.ReadDex()
	
	
	#Utility -> NOT WORKING
	def printClassGui(self,indx):
		self.readClass(indx)
		cl=self.ClassDEF[indx]
		returned=[]
		#Header
		returned.append("Class name:\t"+self.String[self.TypeIDS[indx]].string_data_data+"\n")
		#Access flag	
		index=1
		flg=cl.access_flags
		while flg!=0:
			if flg % 2 == 1:
				returned.append("Access flag:\t"+cl.access_flagd[index]+"\n")
			index+=1
			flg=flg >> 1
		
		#Check NO_INDEX BEFORE
		returned.append("Superclass:\t"+self.String[self.TypeIDS[cl.superclass_idx]].string_data_data+"\n")
		returned.append("Interface:\t"+"\n")
		#CHECK NO_INDEX before
		returned.append("Source file:\t"+self.String[cl.source_file_idx].string_data_data+"\n")
		returned.append("Annotation:\t"+"\n")
		
		#Fields
		returned.append("\n\n\t--------------\tStatic Field\t--------------\n\n")
		index=0
		pr=0
		print "static field:"+str(cl.cdi.static_fields_size)
		while index<cl.cdi.static_fields_size:
			k=cl.cdi.static_fields[index]
			inc=1
			flg=k.access_flags
			acc=""
			while flg!=0:
				if flg % 2 == 1:
					acc=acc+" "+cl.access_flagd[inc]
				inc+=1
				flg=flg >> 1
			field=self.FieldIDS[k.field_idx_diff+pr]
			tipo=self.String[self.TypeIDS[field.type_idx]].string_data_data
			name=self.String[field.name_idx].string_data_data
			returned.append("\t"+acc+"\t"+tipo+"\t"+name+"\n")
			index+=1
			pr=k.field_idx_diff+pr
			
		returned.append("\n\n\t--------------\tInstance Field\t--------------\n\n")	
		index=0
		pr=0
		print "Instance field:"+str(cl.cdi.instance_fields_size)
		while index<cl.cdi.instance_fields_size:
			k=cl.cdi.instance_fields[index]
			inc=1
			flg=k.access_flags
			acc=""
			#print flg
			while flg!=0:
				if flg % 2 == 1:
					acc=acc+" "+cl.access_flagd[inc]
				inc+=1
				flg=flg >> 1
			#print k.field_idx_diff
			#print k.field_idx_diff+pr
			field=self.FieldIDS[k.field_idx_diff+pr]
			#print "FIELD IDS:"+str(field.name_idx)
			tipo=self.String[self.TypeIDS[field.type_idx]].string_data_data
			name=self.String[field.name_idx].string_data_data
			returned.append(str(index)+":\t"+acc+"\t"+tipo+"\t"+name+"\n")
			#print (str(index)+":\t"+acc+"\t"+tipo+"\t"+name+"\n")
			index+=1
			pr=k.field_idx_diff+pr
		
		returned.append("\n\n\t--------------\tDirect methods\t--------------\n\n")	
		#Methods
		print "Direct method:"+str(cl.cdi.direct_methods_size)
		index=0
		pr=0
		while index < cl.cdi.direct_methods_size:
			k=cl.cdi.direct_methods[index]
			inc=1
			flg=k.access_flags
			acc=""
			while flg!=0:
				if flg % 2 == 1:
					acc=acc+" "+cl.access_flagd[inc]
				inc+=1
				flg=flg >> 1
			returned.append(acc+" ")
			meth=self.MethodIDS[k.method_idx_diff+pr]
			prot=self.ProtoIDS[meth.proto_idx]
			returned.append(self.String[meth.name_idx].string_data_data+" ")
			ret=self.TypeIDS[prot.return_type_idx]
			returned.append("(")
			if prot.parameters_off != 0:
				pp=self.getListfromIndex(prot.parameters_off)
				for item in pp:
					returned.append(self.String[self.TypeIDS[item]].string_data_data)
					if item != pp[-1]:
						returned.append(",")
			else:
				returned.append("void")
			returned.append(")->")
			returned.append(self.String[ret].string_data_data)
			returned.append("\n")
			#Insert Code!
			if k.code_off!=0:
				cod=(self.getCode(k.code_off))
				returned.append(self.PrintCodeClass(cod))
			returned.append("\n\n\n")
			pr=k.method_idx_diff+pr
			index+=1
			
		#Methods
		print "Virtual method:"+str(cl.cdi.virtual_methods_size)
		index=0
		pr=0
		while index < cl.cdi.virtual_methods_size:
			k=cl.cdi.virtual_methods[index]
			inc=1
			flg=k.access_flags
			acc=""
			while flg!=0:
				if flg % 2 == 1:
					acc=acc+" "+cl.access_flagd[inc]
				inc+=1
				flg=flg >> 1
			returned.append(acc+" ")
			meth=self.MethodIDS[k.method_idx_diff+pr]
			prot=self.ProtoIDS[meth.proto_idx]
			returned.append(self.String[meth.name_idx].string_data_data+" ")
			ret=self.TypeIDS[prot.return_type_idx]
			returned.append("(")
			if prot.parameters_off != 0:
				pp=self.getListfromIndex(prot.parameters_off)
				for item in pp:
					returned.append(self.String[self.TypeIDS[item]].string_data_data)
					if item != pp[-1]:
						returned.append(",")
			else:
				returned.append("void")
			returned.append(")->")
			returned.append(self.String[ret].string_data_data)
			returned.append("\n")
			#Insert Code!
			if k.code_off!=0:
				cod=(self.getCode(k.code_off))
				returned.append(self.PrintCodeClass(cod))
			returned.append("\n\n\n")
			pr=k.method_idx_diff+pr
			index+=1
		return returned
	
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
			print line
	
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
					print bcolors.RED+hexc+bcolors.ENDC
					#Element_width	ushort	number of bytes in each element
					by=bytearray()
					by.append(cod.insns[indx])
					by.append(cod.insns[indx+1])
					indx+=2
					width=from_bytes(by,"little")
					hexc="0x"+binascii.hexlify(by)
					print bcolors.RED+hexc+bcolors.ENDC
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
					print bcolors.RED+hexc+bcolors.ENDC
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
						print bcolors.RED+hexc+bcolors.ENDC
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
				string=self.String[value].string_data_data
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
				string=self.String[value].string_data_data
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
				string=self.String[self.TypeIDS[value]].string_data_data
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
				string=self.String[self.TypeIDS[value]].string_data_data
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
				string=self.String[self.TypeIDS[vb]].string_data_data
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
				string=self.String[self.TypeIDS[self.FieldIDS[field].class_idx]].string_data_data
				string+="->"+self.String[self.FieldIDS[field].name_idx].string_data_data
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
				string=self.String[self.TypeIDS[self.FieldIDS[field].class_idx]].string_data_data
				string+="->"+self.String[self.FieldIDS[field].name_idx].string_data_data
				string+=":"+self.String[self.TypeIDS[self.FieldIDS[field].type_idx]].string_data_data
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
				string=self.String[self.TypeIDS[self.MethodIDS[vb].class_idx]].string_data_data
				string+="->"+self.String[self.MethodIDS[vb].name_idx].string_data_data
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
				string=self.String[self.TypeIDS[self.MethodIDS[vb].class_idx]].string_data_data
				string+="->"+self.String[self.MethodIDS[vb].name_idx].string_data_data
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
				string=self.String[self.TypeIDS[vb]].string_data_data
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
					hexc="0x"+binascii.hexlify(by)
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
				#string=self.String[value].string_data_data
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
				#string=self.String[value].string_data_data
				opers="v"+str(va)+"= "+str(value)
			elif type == 11:
				#VA 8 bits, type index 16 bits
				va=oper
				by=bytearray()
				by.append(cod.insns[indx])
				by.append(cod.insns[indx+1])
				indx+=2
				value=self.from_bytes(by,"little")
				#string=self.String[self.TypeIDS[value]].string_data_data
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
				#string=self.String[self.TypeIDS[value]].string_data_data
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
				#string=self.String[self.FieldIDS[field].class_idx].string_data_data
				#string+="->"+self.String[self.FieldIDS[field].name_idx].string_data_data
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
				#string=self.String[self.TypeIDS[self.FieldIDS[field].class_idx]].string_data_data
				#string+="->"+self.String[self.FieldIDS[field].name_idx].string_data_data
				#string+=":"+self.String[self.TypeIDS[self.FieldIDS[field].type_idx]].string_data_data
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
				#string=self.String[self.TypeIDS[self.MethodIDS[vb].class_idx]].string_data_data
				#string+="->"+self.String[self.MethodIDS[vb].name_idx].string_data_data
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
		print "VALUE ARG F:"+str(value_arg)
		print "VALUE type F:"+str(value_type)
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
			print "Size:"+str(size)
			if size != 0:
				by=bytearray(f.read(size+1))
			else:
				by.append(0x00)
			print "BIN:"+binascii.hexlify(by)
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
				print item
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
				item="\""+self.String[item].string_data_data+"\""
			elif value_type == 0x18:
				#VALUE TYPE UNSIGNED -> INDEX TYPE_IDS
				item=from_bytes(by,"little")
				item="\""+self.String[self.TypeIDS[item]].string_data_data+"\""
			elif value_type == 0x19:
				#VALUE FIELD UNSIGNED -> INDEX FIELD_IDS
				item=from_bytes(by,"little")
				print item
				stri=self.String[self.FieldIDS[item].name_idx].string_data_data
				stri+=":"+self.String[self.TypeIDS[self.FieldIDS[item].type_idx]].string_data_data
				item=stri
			elif value_type == 0x1A:
				#VALUE METHOD UNSIGNED -> INDEX METHOD_IDS
				item=from_bytes(by,"little")
				#str=self.String[self.FieldIDS[item].name_idx].string_data_data
				#str+=":"+self.String[self.TypeIDS[self.FieldIDS[item].type_idx]].string_data_data
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
			print bcolors.RED+"Error. Index is not integer"+bcolors.ENDC
			return -1
		if indx not in self.ClassDEF:
			print bcolors.RED+"Error. Maybe the class is native?"+bcolors.ENDC
			return -1
		classname=self.String[self.TypeIDS[indx]].string_data_data
		i=self.ClassDEF[indx]
		if (i.read==True):
			return indx
		print bcolors.BOLD+"\nReading class:"+classname
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
			by.append(f.read(1))
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
				meth=self.MethodIDS[k.method_idx_diff+pr]
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
					prot=self.ProtoIDS[meth.proto_idx]
					metd+=self.String[meth.name_idx].string_data_data+" "
					ret=self.TypeIDS[prot.return_type_idx]
					metd+="("
					if prot.parameters_off != 0:
						pp=self.getListfromIndex(prot.parameters_off)
						for item in pp:
							metd+=self.String[self.TypeIDS[item]].string_data_data
							if item != pp[-1]:
								metd+=","
					else:
						metd+="void"
					metd+=")->"
					metd+=self.String[ret].string_data_data
					print metd+"\n"
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
			#clax=self.String[self.TypeIDS[]].string_data_data
			i=self.readClass(obj.class_idx)
			if i < 0:
				return
			i=self.ClassDEF[i]
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
					meth=self.MethodIDS[k.method_idx_diff+pr]
					if indx == k.method_idx_diff+pr:
						#Insert Code!
						if k.code_off!=0:
							#OPTIMIZATION POSSIBLE
							cod=(self.getCode(k.code_off))
							ret=self.ParseByteCode(cod,opcode)
							for line in ret:
								vb=int(line.split()[-1])
								string=self.String[self.TypeIDS[self.MethodIDS[vb].class_idx]].string_data_data
								string+="->"+self.String[self.MethodIDS[vb].name_idx].string_data_data
								print (bcolors.GREEN+"%-89s %-30s") % (string,"["+str(vb)+"]"+bcolors.ENDC)
					pr=k.method_idx_diff+pr
					index+=1
				mod+=1
		print ""
	
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
		clxList=self.getClassesList()
		ina=0
			
		for item in clxList:
			ina+=1
			if self.readClass(clxList[item]) < 0:
				print bcolors.RED+"Something really wrong go here..."+bcolors.ENDC
				return -1
			i=self.ClassDEF[clxList[item]]
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
					meth=self.MethodIDS[k.method_idx_diff+pr]
					#Insert Code!
					if k.code_off!=0:
						#OPTIMIZATION POSSIBLE
						
						cod=(self.getCode(k.code_off))
						ret=self.ParseByteCode(cod,opcode)
						for line in ret:
							vb=int(line.split()[-1])
							if vb == indx:
								if obj == "Method":
									string=self.String[self.TypeIDS[meth.class_idx]].string_data_data
									string+="->"+self.String[meth.name_idx].string_data_data
									print (bcolors.Yellow+"%-50s %-30s") % (string,"["+str(k.method_idx_diff+pr)+"]"+bcolors.ENDC)
								elif obj == "String":
									string=self.String[self.TypeIDS[meth.class_idx]].string_data_data
									string+="->"+self.String[meth.name_idx].string_data_data
									print (bcolors.Yellow+"%-89s %-30s") % (string,"["+str(k.method_idx_diff+pr)+"]"+bcolors.ENDC)
									string = self.String[vb].string_data_data
									codix=""
									for i in line.split():
										if i != line.split()[-1]:
											codix+=i+" "
									print (bcolors.Yellow+"\t%-20s %-60s %-30s") % (codix,string,"["+str(vb)+"]"+bcolors.ENDC)
								elif obj == "Type":
									string=self.String[self.TypeIDS[meth.class_idx]].string_data_data
									string+="->"+self.String[meth.name_idx].string_data_data
									print (bcolors.Yellow+"%-89s %-30s") % (string,"["+str(k.method_idx_diff+pr)+"]"+bcolors.ENDC)
									string = self.String[self.TypeIDS[vb]].string_data_data
									codix=""
									for i in line.split():
										if i != line.split()[-1]:
											codix+=i+" "
									print (bcolors.Yellow+"\t%-20s %-60s %-30s") % (codix,string,"["+str(vb)+"]"+bcolors.ENDC)
								elif obj == "Field":
									string=self.String[self.TypeIDS[meth.class_idx]].string_data_data
									string+="->"+self.String[meth.name_idx].string_data_data
									print (bcolors.Yellow+"%-89s %-30s") % (string,"["+str(k.method_idx_diff+pr)+"]"+bcolors.ENDC)
									string = self.String[self.FieldIDS[vb].name_idx].string_data_data
									codix=""
									for i in line.split():
										if i != line.split()[-1]:
											codix+=i+" "
									print (bcolors.Yellow+"\t%-20s %-60s %-30s") % (codix,string,"["+str(vb)+"]"+bcolors.ENDC)
					pr=k.method_idx_diff+pr
					index+=1
				mod+=1
	#Get Single Object
	
	def getClass(self,indx):
		indici=[]
		if type(indx) is str:
			for i in self.ClassDEF:
				strin=self.String[self.TypeIDS[i]].string_data_data
				if indx in strin:
					indici.append(i)
		if len(indici) == 0:
			print "Error. This class can not be found..."
			return -1
		for i in indici:
			self.readClass(i)
			cl=self.ClassDEF[i]
			returned=[]
			#Header
			print(bcolors.HEADER+"Class name:\t"+bcolors.ENDC+self.String[self.TypeIDS[i]].string_data_data+"\n")
			#Access flag	
			index=1
			flg=cl.access_flags
			while flg!=0:
				if flg % 2 == 1:
					print(bcolors.HEADER+"Access flag:\t"+bcolors.ENDC+cl.access_flagd[index]+"\n")
				index+=1
				flg=flg >> 1
		
			#Check NO_INDEX BEFORE
			if cl.source_file_idx!=4294967295:
				print(bcolors.HEADER+"Superclass:\t"+bcolors.ENDC+self.String[self.TypeIDS[cl.superclass_idx]].string_data_data+"\n")
			print(bcolors.HEADER+"Interface: NOT IMPLEMENTED\t"+bcolors.ENDC+"\n")
			if cl.source_file_idx!=4294967295:
				print(bcolors.HEADER+"Source file:\t"+bcolors.ENDC+self.String[cl.source_file_idx].string_data_data+"\n")
			print(bcolors.HEADER+"Annotation: NOT IMPLEMENTED\t"+bcolors.ENDC+"\n")
		
			#Fields
			print(bcolors.OKGREEN+"\n\n\t--------------\tStatic Field\t--------------\n\n"+bcolors.ENDC)
			index=0
			pr=0
			print bcolors.HEADER+"Static fields:"+bcolors.ENDC+str(cl.cdi.static_fields_size)
			while index<cl.cdi.static_fields_size:
				k=cl.cdi.static_fields[index]
				inc=1
				flg=k.access_flags
				acc=""
				while flg!=0:
					if flg % 2 == 1:
						acc=acc+" "+cl.access_flagd[inc]
					inc+=1
					flg=flg >> 1
				field=self.FieldIDS[k.field_idx_diff+pr]
				tipo=self.String[self.TypeIDS[field.type_idx]].string_data_data
				name=self.String[field.name_idx].string_data_data
				if index < len(cl.cdi.static_values):
					value=cl.cdi.static_values[index]
					print("\t"+acc+"\t"+tipo+"\t"+name+"\t= "+str(value)+"\n")
				else:
					print("\t"+acc+"\t"+tipo+"\t"+name+"\n")
				index+=1
				pr=k.field_idx_diff+pr
				
			print(bcolors.OKGREEN+"\n\n\t--------------\tInstance Field\t--------------\n\n"+bcolors.ENDC)	
			index=0
			pr=0
			print bcolors.HEADER+"Instance fields:"+bcolors.ENDC+str(cl.cdi.instance_fields_size)
			while index<cl.cdi.instance_fields_size:
				k=cl.cdi.instance_fields[index]
				inc=1
				flg=k.access_flags
				acc=""
				#print flg
				while flg!=0:
					if flg % 2 == 1:
						acc=acc+" "+cl.access_flagd[inc]
					inc+=1
					flg=flg >> 1
				#print k.field_idx_diff
				#print k.field_idx_diff+pr
				field=self.FieldIDS[k.field_idx_diff+pr]
				#print "FIELD IDS:"+str(field.name_idx)
				tipo=self.String[self.TypeIDS[field.type_idx]].string_data_data
				name=self.String[field.name_idx].string_data_data
				print(str(index)+":\t"+acc+"\t"+tipo+"\t"+name+"\n")
				#print (str(index)+":\t"+acc+"\t"+tipo+"\t"+name+"\n")
				index+=1
				pr=k.field_idx_diff+pr
			
			print(bcolors.OKGREEN+"\n\n\t--------------\tMethods\t--------------\n\n"+bcolors.ENDC)	
			self.printMethod(cl)
		
	def getMethod(self,st):
		#The same method can collide in more than one class -> Iterate the process -> 
		#Moreover, the st can be list -> iterate over all this stuff
		methodlist=[]
		if type(st) is list:
			for ss in st:
				if type(ss) is int:
					methodlist.append(ss)
				elif type(ss) is str:
					indx=0
					while indx<len(self.MethodIDS):
						meth=self.MethodIDS[indx]
						name=self.String[meth.name_idx].string_data_data
						if st == name:
							methodlist.append(indx)
						indx+=1
		elif type(st) is int:
			methodlist.append(st)
		elif type(st) is str:
			indx=0
			while indx<len(self.MethodIDS):
				meth=self.MethodIDS[indx]
				name=self.String[meth.name_idx].string_data_data
				if st.lower() in name.lower():
					methodlist.append(indx)
				indx+=1

		#Starting iterate here
		returned={}
		for item in methodlist:
			meth=self.MethodIDS[item]
			flg=self.readClass(meth.class_idx)
			clax=self.String[self.TypeIDS[meth.class_idx]].string_data_data
			name=self.String[meth.name_idx].string_data_data
			returned[name]=item
			print (bcolors.HEADER+"%-30s"+bcolors.ENDC+bcolors.BOLD+"%-30s") %("Class",clax)
			print (bcolors.HEADER+"%-30s"+bcolors.ENDC+bcolors.BOLD+"%-30s") %("Method",name)
			print (bcolors.HEADER+"%-30s"+bcolors.ENDC+bcolors.BOLD+"%-30s") %("Method Index",str(item))+"\n"
			#ReadClass
			if flg == -1:
				continue
			i=self.ClassDEF[meth.class_idx]
			#Method
			self.printMethod(i,item)
			#DEFINE XREF
			#To find xref FROM -> Search in ALL classess the define of this method
			#To find xref TO -> Search in this method the invoke
			print(bcolors.RED+"\n\n \t\t#---XREF TO---\n\n"+bcolors.ENDC)
			self.xrefto(meth,item)
			print(bcolors.RED+"\n\n \t\t#---XREF FROM---\n\n"+bcolors.ENDC)
			self.xreffrom("Method",item)
		return returned
	
	def getString(self,string):
		#Find the string where is used and defined -> 
		#Search in all code where this index is used
		indici=[]
		if type(string) is list:
			for ss in string:
				if type(ss) is str:
					indx=0
					while indx<len(self.String):
						if ss.lower() in self.String[indx].string_data_data.lower():
							indici.append(indx)
						indx+=1
				elif type(ss) is int:
					indici.append(ss)
		if type(string) is str:
			indx=0
			while indx<len(self.String):
				
				if string.lower() in self.String[indx].string_data_data.lower():
					indici.append(indx)
				indx+=1
		elif type(string) is int:
			indici.append(string)
		returned={}
		for i in indici:
			returned[self.String[i].string_data_data]=i
			'''
			Now i have all the index -> Can start the search.
			I should search the string in:
			1. Method Name
			2. Field Name
			3. Type Name
			4. Inside the code
			'''
			#1.Method name
			#GREEN = '\033[92m'
			#BLUE = '\033[94m'
			#CYAN = '\033[96m'
			#Yellow = '\033[93m'
			print bcolors.GREEN+"---- Method ----"
			print ""
			for m in self.MethodIDS:
				if m.name_idx == i:
					print self.String[self.TypeIDS[m.class_idx]].string_data_data+"->"+self.String[i].string_data_data
			print ""
			print bcolors.BLUE+"---- Field ----"
			print ""
			for m in self.FieldIDS:
				if m.name_idx == i:
					print self.String[self.TypeIDS[m.class_idx]].string_data_data+":"+self.String[i].string_data_data
			print ""	
			print bcolors.CYAN+"---- Type ----"
			print ""
			for m in self.TypeIDS:
				if m == i:
					print self.String[m].string_data_data
			print ""		
			print bcolors.Yellow+"---- Inside Code ----"
			print ""
			#More complex
			self.xreffrom("String",i)
			print ""
		return returned
	
	def getType(self,typex):
		#Find where a "type" is used and defined -> Check if it is a class, primitive or other
		indici=[]
		if type(typex) is list:
			for ss in typex:
				if type(ss) is str:
					indx=0
					while indx<len(self.TypeIDS):
						if ss.lower() in self.String[self.TypeIDS[indx]].string_data_data.lower():
							indici.append(indx)
						indx+=1
				elif type(ss) is int:
					indici.append(ss)
		if type(typex) is str:
			indx=0
			while indx<len(self.TypeIDS):
				if typex.lower() in self.String[self.TypeIDS[indx]].string_data_data.lower():
					indici.append(indx)
				indx+=1
		elif type(string) is int:
			indici.append(typex)
		returned={}
		for i in indici:
			tp=self.String[self.TypeIDS[i]].string_data_data
			returned[tp]=i
			'''
			Now i have all the index -> Can start the search.
			I should search the string in:
			1. Method Parameters
			2. Field Name 
			4. Inside the code
			'''
			#1.Method name
			#GREEN = '\033[92m'
			#BLUE = '\033[94m'
			#Yellow = '\033[93m'
			print bcolors.GREEN+"---- Method parameters ----"
			print ""
			for m in self.MethodIDS:
				proto=self.ProtoIDS[m.proto_idx]
				if proto.return_type_idx == i or i in proto.parameters:
					line="("
					if len(proto.parameters) == 0:
						line+="void"
					else:
						for j in proto.parameters:
							line+=self.String[self.TypeIDS[j]].string_data_data+", "
					line+=")"+self.String[self.TypeIDS[proto.return_type_idx]].string_data_data
					print self.String[self.TypeIDS[m.class_idx]].string_data_data+"->"+self.String[m.name_idx].string_data_data+line
			print ""
			print bcolors.BLUE+"---- Field ----"
			print ""
			for m in self.FieldIDS:
				if m.type_idx == i:
					print self.String[self.TypeIDS[m.class_idx]].string_data_data+":"+self.String[m.name_idx].string_data_data
			print ""	
			print bcolors.Yellow+"---- Inside Code ----"
			print ""
			#More complex
			self.xreffrom("Type",i)
			print ""
		return returned
	
	def getField(self,field):
		#find where a "field" is used and defined
		#Find where a "type" is used and defined -> Check if it is a class, primitive or other
		indici=[]
		if type(field) is list:
			for ss in field:
				if type(ss) is str:
					indx=0
					while indx<len(self.FieldIDS):
						if ss.lower() in self.String[self.FieldIDS[indx].name_idx].string_data_data.lower():
							indici.append(indx)
						indx+=1
				elif type(ss) is int:
					indici.append(ss)
		if type(field) is str:
			indx=0
			while indx<len(self.FieldIDS):
				if field.lower() in self.String[self.FieldIDS[indx].name_idx].string_data_data.lower():
					indici.append(indx)
				indx+=1
		elif type(field) is int:
			indici.append(field)
		returned={}
		for i in indici:
			tp=self.String[self.FieldIDS[i].name_idx].string_data_data
			returned[tp]=i
			'''
			Now i have all the index -> Can start the search.
			I should search the string in:
			1. Field Name 
			2. Inside the code
			'''
			#1.Method name
			#BLUE = '\033[94m'
			#Yellow = '\033[93m'
			print bcolors.BLUE+"---- Field ----"
			print ""
			fie=self.FieldIDS[i]
			print self.String[self.TypeIDS[fie.class_idx]].string_data_data+":"+self.String[fie.name_idx].string_data_data+" "+self.String[self.TypeIDS[fie.type_idx]].string_data_data
			print ""	
			print bcolors.Yellow+"---- Inside Code ----"
			print ""
			#More complex
			self.xreffrom("Field",i)
			print ""
		return returned
		pass
	#GET LIST of Objects -> field list miss
	
	def getMethodList(self,st=None):
		returned={}
		indx=0
		if st==None:
			while indx<len(self.MethodIDS):
				meth=self.MethodIDS[indx]
				returned[self.String[meth.name_idx].string_data_data]=indx
				indx+=1
		else:
			if type(st) is list:
				for ss in st:
					if type(ss) is int:
						meth=self.MethodIDS[ss]
						returned[self.String[meth.name_idx].string_data_data]=ss
					elif type(ss) is str:
						indx=0
						while indx<len(self.MethodIDS):
							meth=self.MethodIDS[indx]
							name=self.String[meth.name_idx].string_data_data
							if ss.lower() in name.lower():
								returned[name]=indx
							indx+=1
			elif type(st) is int:
				meth=self.MethodIDS[ss]
				returned[self.String[meth.name_idx].string_data_data]=ss
			elif type(st) is str:
				indx=0
				while indx<len(self.MethodIDS):
					meth=self.MethodIDS[indx]
					name=self.String[meth.name_idx].string_data_data
					if st.lower() in name.lower():
						returned[name]=indx
					indx+=1
		return returned
		
	def getClassesList(self,st=None):
		#CHECK INDEX
		returned={}
		if st==None:
			for i in self.ClassDEF:
				returned[self.String[self.TypeIDS[i]].string_data_data]=i
		else:
			if type(st) is list:
				for ss in st:
					indx=0
					if type(ss) is str:
						for i in self.ClassDEF:
							strin=self.String[self.TypeIDS[i]].string_data_data
							if ss in strin:
								returned[strin]=i
					elif type(ss) is int:
						returned[self.String[self.TypeIDS[ss]].string_data_data]=ss
			else:
				if type(st) is str:
					for i in self.ClassDEF:
						strin=self.String[self.TypeIDS[i]].string_data_data
						if st in strin:
							returned[strin]=i
				elif type(st) is int:
					returned[self.String[self.TypeIDS[st]].string_data_data]=st
		return returned
	
	def getStringList(self,st=None):
		#CHECK INDEX RANGE
		returned={}
		indx=0
		if st==None:
			while indx < len(self.String):
				returned[self.String[indx].string_data_data]=indx
				indx+=1
		else:
			if type(st) is list:
				for ss in st:
					indx=0
					if type(ss) is int:
						returned[self.String[ss].string_data_data]=ss
					elif type(ss) is str:
						while indx < len(self.TypeIDS):
							strin=self.String[indx].string_data_data
							if ss in strin:
								returned[self.String[indx].string_data_data]=indx
			else:
				if type(st) is int:
					returned[self.String[st].string_data_data]=st
				elif type(st) is str:
					while indx < len(self.TypeIDS):
						strin=self.String[indx].string_data_data
						if st in strin:
							returned[self.String[indx].string_data_data]=indx
						indx+=1
		return returned
		
	def getTypeList(self,st=None):
		#CHECK THE INDEX RANGE
		returned=[]
		indx=0
		if st==None:
			while indx < len(self.TypeIDS):
				strin=self.String[self.TypeIDS[indx]].string_data_data
				returned.append(str(indx)+": "+strin)
				indx+=1
		else:
			if type(st) is list:
				for ss in st:
					indx=0
					if type(ss) is int:
						returned.append(str(ss)+": "+self.String[self.TypeIDS[ss]].string_data_data)
					elif type(ss) is str:
						while indx < len(self.TypeIDS):
							strin=self.String[self.TypeIDS[indx]].string_data_data
							if st in strin:
								returned.append(str(indx)+": "+strin)
			else:
				if type(st) is int:
					returned.append(str(st)+": "+(self.String[self.TypeIDS[st]].string_data_data))
				elif type(st) is str:
					while indx < len(self.TypeIDS):
						strin=self.String[self.TypeIDS[indx]].string_data_data
						if st in strin:
							returned.append(str(indx)+": "+strin)
						indx+=1
		return returned
	
	def printHeader(self):
		print "Magic Number:\t\t"+bcolors.ENDC+"0x"+binascii.hexlify(self.Head.MagicNumber[0:4])+"\t["+self.Head.MagicNumber[0:3]+"]"
		print bcolors.BOLD+"DEX Version:\t\t"+bcolors.ENDC+"0x"+binascii.hexlify(self.Head.MagicNumber[4:8])+"\t["+self.Head.MagicNumber[4:7]+"]"
		print bcolors.BOLD+"Checksum:\t\t"+bcolors.ENDC+"0x"+binascii.hexlify(self.Head.checksum)
		print bcolors.BOLD+"Signature:\t\t"+bcolors.ENDC+"0x"+binascii.hexlify(self.Head.signature)
		print bcolors.BOLD+"File size:\t\t"+bcolors.ENDC+str(self.Head.file_size)
		print bcolors.BOLD+"Header size:\t\t"+bcolors.ENDC+str(self.Head.header_size)
		print bcolors.BOLD+"Ordering byte:\t\t"+bcolors.ENDC+"0x"+binascii.hexlify(self.Head.endian_tag)
		print bcolors.BOLD+"Link size:\t\t"+bcolors.ENDC+str(self.Head.link_size)
		print bcolors.BOLD+"Link offset:\t\t"+bcolors.ENDC+str(self.Head.link_off)
		print bcolors.BOLD+"Map offset:\t\t"+bcolors.ENDC+str(self.Head.map_off)
		print bcolors.BOLD+"String IDS size:\t"+bcolors.ENDC+str(self.Head.string_ids_size)
		print bcolors.BOLD+"String IDS offset:\t"+bcolors.ENDC+str(self.Head.string_ids_off)
		print bcolors.BOLD+"Type IDS size:\t\t"+bcolors.ENDC+str(self.Head.type_ids_size)
		print bcolors.BOLD+"Type IDS offset:\t"+bcolors.ENDC+str(self.Head.type_ids_off)
		print bcolors.BOLD+"Proto IDS size:\t\t"+bcolors.ENDC+str(self.Head.proto_ids_size)
		print bcolors.BOLD+"Proto IDS offset:\t"+bcolors.ENDC+str(self.Head.proto_ids_off)
		print bcolors.BOLD+"Field IDS size:\t\t"+bcolors.ENDC+str(self.Head.field_ids_size)
		print bcolors.BOLD+"Field IDS offset:\t"+bcolors.ENDC+str(self.Head.field_ids_off)
		print bcolors.BOLD+"Method IDS size:\t"+bcolors.ENDC+str(self.Head.method_ids_size)
		print bcolors.BOLD+"Method IDS offset:\t"+bcolors.ENDC+str(self.Head.method_ids_off)
		print bcolors.BOLD+"Class DEFS size:\t"+bcolors.ENDC+str(self.Head.class_defs_size)
		print bcolors.BOLD+"Class DEFS offset:\t"+bcolors.ENDC+str(self.Head.class_defs_off)
		print bcolors.BOLD+"Data size:\t\t"+bcolors.ENDC+str(self.Head.data_size)
		print bcolors.BOLD+"Data offset:\t\t"+bcolors.ENDC+str(self.Head.data_off)
	
	def ReadDex(self,f=None):
		#The APK has only one classes.dex
		if hasattr(self,'dexFl') == True and f!=None:
			self.dexFl=f
		elif hasattr(self,'dexFl') == True and f==None:
			f=self.dexFl
		elif f==None and hasattr(self,'dexFl') == False:
			print "Must select a classes.dex first"
			return
		else:
			self.dexFl=f
		
		print bcolors.HEADER+"\nReading header..."
		self.Head.MagicNumber=bytearray(f.read(8))
		self.Head.checksum=bytearray(f.read(4))
		self.Head.signature=bytearray(f.read(20))
		self.Head.file_size=bytearray(f.read(4))
		self.Head.header_size=bytearray(f.read(4))
		self.Head.endian_tag=bytearray(f.read(4))
		if self.Head.endian_tag[0] == 0x78:
			order="little"
		else:
			order="big"
		self.Head.file_size=self.from_bytes(self.Head.file_size, order)
		self.Head.header_size=self.from_bytes(self.Head.header_size, order)
		self.Head.link_size=self.from_bytes(bytearray(f.read(4)),order)
		self.Head.link_off=self.from_bytes(bytearray(f.read(4)),order)
		self.Head.map_off=self.from_bytes(bytearray(f.read(4)),order)
		self.Head.string_ids_size=self.from_bytes(bytearray(f.read(4)),order)
		self.Head.string_ids_off=self.from_bytes(bytearray(f.read(4)),order)
		self.Head.type_ids_size=self.from_bytes(bytearray(f.read(4)),order)
		self.Head.type_ids_off=self.from_bytes(bytearray(f.read(4)),order)
		self.Head.proto_ids_size=self.from_bytes(bytearray(f.read(4)),order)
		self.Head.proto_ids_off=self.from_bytes(bytearray(f.read(4)),order)
		self.Head.field_ids_size=self.from_bytes(bytearray(f.read(4)),order)
		self.Head.field_ids_off=self.from_bytes(bytearray(f.read(4)),order)
		self.Head.method_ids_size=self.from_bytes(bytearray(f.read(4)),order)
		self.Head.method_ids_off=self.from_bytes(bytearray(f.read(4)),order)
		self.Head.class_defs_size=self.from_bytes(bytearray(f.read(4)),order)
		self.Head.class_defs_off=self.from_bytes(bytearray(f.read(4)),order)
		self.Head.data_size=self.from_bytes(bytearray(f.read(4)),order)
		self.Head.data_off=self.from_bytes(bytearray(f.read(4)),order)
		print "Magic Number:\t\t"+bcolors.ENDC+bcolors.BOLD+"0x"+binascii.hexlify(self.Head.MagicNumber[0:4])+"\t["+self.Head.MagicNumber[0:3]+"]"
		print bcolors.HEADER+"DEX Version:\t\t"+bcolors.ENDC+bcolors.BOLD+"0x"+binascii.hexlify(self.Head.MagicNumber[4:8])+"\t["+self.Head.MagicNumber[4:7]+"]"
		print bcolors.HEADER+"Checksum:\t\t"+bcolors.ENDC+bcolors.BOLD+"0x"+binascii.hexlify(self.Head.checksum)
		print bcolors.HEADER+"Signature:\t\t"+bcolors.ENDC+bcolors.BOLD+"0x"+binascii.hexlify(self.Head.signature)
		print bcolors.HEADER+"File size:\t\t"+bcolors.ENDC+bcolors.BOLD+str(self.Head.file_size)
		print bcolors.HEADER+"Header size:\t\t"+bcolors.ENDC+bcolors.BOLD+str(self.Head.header_size)
		print bcolors.HEADER+"Ordering byte:\t\t"+bcolors.ENDC+bcolors.BOLD+"0x"+binascii.hexlify(self.Head.endian_tag)
		print bcolors.HEADER+"Link size:\t\t"+bcolors.ENDC+bcolors.BOLD+str(self.Head.link_size)
		print bcolors.HEADER+"Link offset:\t\t"+bcolors.ENDC+bcolors.BOLD+str(self.Head.link_off)
		print bcolors.HEADER+"Map offset:\t\t"+bcolors.ENDC+bcolors.BOLD+str(self.Head.map_off)
		print bcolors.HEADER+"String IDS size:\t"+bcolors.ENDC+bcolors.BOLD+str(self.Head.string_ids_size)
		print bcolors.HEADER+"String IDS offset:\t"+bcolors.ENDC+bcolors.BOLD+str(self.Head.string_ids_off)
		print bcolors.HEADER+"Type IDS size:\t\t"+bcolors.ENDC+bcolors.BOLD+str(self.Head.type_ids_size)
		print bcolors.HEADER+"Type IDS offset:\t"+bcolors.ENDC+bcolors.BOLD+str(self.Head.type_ids_off)
		print bcolors.HEADER+"Proto IDS size:\t\t"+bcolors.ENDC+bcolors.BOLD+str(self.Head.proto_ids_size)
		print bcolors.HEADER+"Proto IDS offset:\t"+bcolors.ENDC+bcolors.BOLD+str(self.Head.proto_ids_off)
		print bcolors.HEADER+"Field IDS size:\t\t"+bcolors.ENDC+bcolors.BOLD+str(self.Head.field_ids_size)
		print bcolors.HEADER+"Field IDS offset:\t"+bcolors.ENDC+bcolors.BOLD+str(self.Head.field_ids_off)
		print bcolors.HEADER+"Method IDS size:\t"+bcolors.ENDC+bcolors.BOLD+str(self.Head.method_ids_size)
		print bcolors.HEADER+"Method IDS offset:\t"+bcolors.ENDC+bcolors.BOLD+str(self.Head.method_ids_off)
		print bcolors.HEADER+"Class DEFS size:\t"+bcolors.ENDC+bcolors.BOLD+str(self.Head.class_defs_size)
		print bcolors.HEADER+"Class DEFS offset:\t"+bcolors.ENDC+bcolors.BOLD+str(self.Head.class_defs_off)
		print bcolors.HEADER+"Data size:\t\t"+bcolors.ENDC+bcolors.BOLD+str(self.Head.data_size)
		print bcolors.HEADER+"Data offset:\t\t"+bcolors.ENDC+bcolors.BOLD+str(self.Head.data_off)

		#Strings
		print bcolors.HEADER+"\nReading strings..."
		f.seek(self.Head.string_ids_off)
		i=0
		while i < self.Head.string_ids_size:
			s=StringIDS()
			s.string_data_off=self.from_bytes(bytearray(f.read(4)),order)
			i+=1
			self.String.append(s)
		for strx in self.String:
			offset=strx.string_data_off
			f.seek(offset)
			strx.string_data_len=self.decodeULEB(f)
			s=f.read(strx.string_data_len)
			#Reading string_data_data
			strx.string_data_data=s
			
		#Type
		print "\nReading types..."
		f.seek(self.Head.type_ids_off)
		i=0
		while i < self.Head.type_ids_size:
			index=self.from_bytes(bytearray(f.read(4)),order)
			i+=1
			self.TypeIDS.append(index)
		
		#Protype
		print "\nReading prototypes..."
		f.seek(self.Head.proto_ids_off)
		i=0
		while i < self.Head.proto_ids_size:
			s=CProtoIDS()
			s.shorty_idx=from_bytes(bytearray(f.read(4)),order)
			s.return_type_idx=from_bytes(bytearray(f.read(4)),order)
			s.parameters_off=from_bytes(bytearray(f.read(4)),order)
			i+=1
			self.ProtoIDS.append(s)
		for p in self.ProtoIDS:
			if p.parameters_off != 0:
				f.seek(p.parameters_off)
				len=from_bytes(bytearray(f.read(4)),order)
				indx=0
				while indx < len:
					x=from_bytes(bytearray(f.read(2)),order)
					p.parameters.append(x)
					indx+=1
			
		#Fields
		print "\nReading fields..."
		f.seek(self.Head.field_ids_off)
		i=0
		#print self.Head.field_ids_off
		while i < self.Head.field_ids_size:
			s=CFieldIDS()
			s.class_idx=self.from_bytes(bytearray(f.read(2)),"little")
			s.type_idx=self.from_bytes(bytearray(f.read(2)),"little")
			s.name_idx=self.from_bytes(bytearray(f.read(4)),"little")
			#print str(i)+":\tClass:"+str(s.class_idx)+"\tField:"+str(s.name_idx)
			i+=1
			self.FieldIDS.append(s)
			
		#Methods
		print "\nReading methods..."
		f.seek(self.Head.method_ids_off)
		i=0
		while i < self.Head.method_ids_size:
			s=CMethodIDS()
			s.class_idx=self.from_bytes(bytearray(f.read(2)),order)
			s.proto_idx=self.from_bytes(bytearray(f.read(2)),order)
			s.name_idx=self.from_bytes(bytearray(f.read(4)),order)
			i+=1
			self.MethodIDS.append(s)
			
			
		#CLASSES
		print "\nReading classes..."
		f.seek(self.Head.class_defs_off)
		i=0
		while i < self.Head.class_defs_size:
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
			self.ClassDEF[s.class_idx]=s