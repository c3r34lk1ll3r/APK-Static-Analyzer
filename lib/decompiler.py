#READ CLASS.DEX

import binascii
from btcodedict import ByteCodeDictionary

class DexFile:
	class Header:
		def __init__(self):
			self.MagicNumber=0x0 	#ubyte[8]
			self.checksum=0x0 		#uint
			self.signature=0x0 		#ubyte[20]
			self.file_size=0 		#uint
			self.header_size=0 		#uint
			self.endian_tag=0x0		#uint
			self.link_size=0 		#uint
			self.link_off=0 		#uint
			self.map_off=0			#uint
			self.string_ids_size=0 	#uint
			self.string_ids_off=0	#uint
			self.type_ids_size=0	#uint
			self.type_ids_off=0 	#uint
			self.proto_ids_size=0 	#uint
			self.proto_ids_off=0 	#uint
			self.field_ids_size=0 	#uint
			self.field_ids_off=0 	#uint
			self.method_ids_size=0 	#uint
			self.method_ids_off=0 	#uint
			self.class_defs_size=0 	#uint
			self.class_defs_off=0 	#uint
			self.data_size=0 		#uint
			self.data_off=0 		#uint
	
	class StringIDS:
		def __init__(self):
			self.string_data_off=0
			self.string_data_len=0
			self.string_data_data=""
	
	class CProtoIDS:
		def __init__(self):
			self.shorty_idx=0				#uint	index into the string_ids list for the short-form descriptor
											#string of this prototype. The string must conform to the syntax for
											#ShortyDescriptor, defined above, and must correspond to the return type
											#and parameters of this item.
			self.return_type_idx=0			#uint	index into the type_ids list for the return type of this prototype
			self.parameters_off=0			#uint	offset from the start of the file to the list of parameter types for
											#this prototype, or 0 if this prototype has no parameters. This offset,
											#if non-zero, should be in the data section, and the data there should be
											#in the format specified by "type_list" below. Additionally, there should be no
											#reference to the type void in the list.
	
	class CFieldIDS:
		def __init__(self):
			self.class_idx=0				#ushort	index into the type_ids list for the definer of this field.
											#This must be a class type, and not an array or primitive type.
			self.type_idx=0					#ushort	index into the type_ids list for the type of this field
			self.name_idx=0					#uint	index into the string_ids list for the name of this field.
											#The string must conform to the syntax for MemberName, defined above.
			
	class CMethodIDS:
		def __init__(self):
			class_idx=0 					#ushort	index into the type_ids list for the definer of this method.
											#This must be a class or array type, and not a primitive type.
			proto_idx=0						#ushort	index into the proto_ids list for the prototype of this method
			name_idx=0						#uint	index into the string_ids list for the name of this method.
											#The string must conform to the syntax for MemberName, defined above.

	class CClassDEF:
		class class_data_item:
			def __init__(self):
				self.static_fields_size=0	#uleb128	the number of static fields defined in this item
				self.instance_fields_size=0	#uleb128	the number of instance fields defined in this item
				self.direct_methods_size=0	#uleb128	the number of direct methods defined in this item
				self.virtual_methods_size=0	#uleb128	the number of virtual methods defined in this item
				
				self.static_fields=[]		#encoded_field[static_fields_size]	the defined static fields, represented as a sequence of encoded elements.
											#The fields must be sorted by field_idx in increasing order.
				self.instance_fields=[]		#encoded_field[instance_fields_size]	the defined instance fields, represented as a sequence
											#of encoded elements. The fields must be sorted by field_idx in increasing order.
				self.direct_methods=[]		#encoded_method[direct_methods_size]	the defined direct (any of static, private, or constructor) methods, represented as a sequence of encoded elements. The methods must be sorted by method_idx in increasing order.
				self.virtual_methods=[]		#encoded_method[virtual_methods_size]

				self.static_values=0
				
		class encoded_field:
			def __init__(self):
				self.field_idx_diff=0		#uleb128	index into the field_ids list for the identity of this field
											#			(includes the name and descriptor), represented as a
											#			difference from the index of previous element in the list.
											#			The index of the first element in a list is represented directly.
				self.access_flags=0			#uleb128	access flags for the field (public, final, etc.). See "access_flags Definitions" for details.
		class encoded_method:
			def __init__(self):
				self.method_idx_diff=0		#uleb128	index into the method_ids list for the identity of this method
											#			(includes the name and descriptor), represented as a difference 
											#			from the index of previous element in the list.
											#			The index of the first element in a list is represented directly.
				self.access_flags=0			#uleb128	access flags for the method (public, final, etc.). See "access_flags Definitions" for details.
				self.code_off=0				#uleb128	offset from the start of the file to the code structure for this method,
											#or 0 if this method is either abstract or native.
											#The offset should be to a location in the data section. The format of the data is specified by
											#"code_item" below.
		class encoded_array:
			def __init__(self):
				self.size=0					#uleb128	number of elements in the array
				self.values=0				#Offset from the start of file where find the field
		
		class encoded_value:
			def __init__(self):
				self.value_arg=0			#ubyte	byte indicating the type of the immediately subsequent value along with an optional
											#clarifying argument in the high-order three bits. See below for the various value definitions.
											#In most cases, value_arg encodes the length of the immediately-subsequent value in bytes, as
											#(size - 1), e.g., 0 means that the value requires one byte, and 7 means it requires eight bytes;
											#however, there are exceptions as noted below.
				self.value=0				#ubyte[] bytes representing the value, variable in length and interpreted differently
											#for different value_type bytes, though always little-endian.
		
		class code_item:
			def __init__(self):
				self.registers_size=0		#ushort	the number of registers used by this code
				self.ins_size=0				#ushort	the number of words of incoming arguments to 
											#the method that this code is for
				self.outs_size=0			#ushort	the number of words of outgoing argument space required by this code for method invocation
				self.tries_size=0			#ushort	the number of try_items for this instance. If non-zero, then these appear as the tries
											#array just after the insns in this instance.
				self.debug_info_off=0		#uint	offset from the start of the file to the debug info (line numbers + local variable info)
											#sequence for this code, or 0 if there simply is no information. The offset,
											#if non-zero, should be to a location in the data section. The format of the data
											#is specified by "debug_info_item" below.
				self.insns_size=0			#uint	size of the instructions list, in 16-bit code units
				self.insns=[]				#ushort[insns_size]	actual array of bytecode. The format of code in an insns array is
											#specified by the companion document Dalvik bytecode. Note that though this is
											#defined as an array of ushort, there are some internal structures that prefer
											#four-byte alignment. Also, if this happens to be in an endian-swapped file, then the
											#swapping is only done on individual ushorts and not on the larger internal structures.
				self.padding=0				#ushort (optional) = 0	two bytes of padding to make tries four-byte aligned.
											#This element is only present if tries_size is non-zero and insns_size is odd.
				self.tries=0				#try_item[tries_size] (optional)	array indicating where in the code exceptions are caught and 
											#how to handle them. Elements of the array must be non-overlapping in range and in order from
											#low to high address. This element is only present if tries_size is non-zero.
				self.handlers=0				#encoded_catch_handler_list (optional)	bytes representing a list of lists of catch types and
											#associated handler addresses. Each try_item has a byte-wise offset into this structure.
											#This element is only present if tries_size is non-zero.
			
			def from_bytes(self,data,endianess):
				if endianess=="little":
					data.reverse()
				return int(binascii.hexlify(data),16)
			
			def ByteCodeToString(self):
				returned=[]
				indx=0
				dy=ByteCodeDictionary()
				print "SIZE:"+str(self.insns_size)
				while indx<(self.insns_size*2):
					opc=self.insns[indx]
					oper=self.insns[indx+1]
					#numopc=int(binascii.hexlify(opc),16)
					indx+=2
					opers=""
					type=dy.oper[opc]
					print "OPCODE:"+str(hex(opc))
					print "TIPO:"+str(type)
					hexc="0x"+format(opc,'02x')+format(oper,'02x')+" "
					if type == 0:
						opers=""
					elif type == 1:
						#VA 4 bits, VB 4 bits
						va=(oper & 0xF0) >> 4
						vb=oper &  0x0F
						opers="v"+str(va)+", v"+str(vb)
					elif type == 2:
						#VA 8 bits, VB 16 bits
						by=bytearray()
						by.append(self.insns[indx])
						by.append(self.insns[indx+1])
						vb=self.from_bytes(by,"little")
						va=oper
						opers="v"+str(va)+", v"+str(vb)
						indx+=2
						hexc+=binascii.hexlify(by)
					elif type == 3:
						#VA 16 bits, VB 16 bits -> NOT ALLIGNED!
						by=bytearray()
						by.append(oper)
						by.append(self.insns[indx+1])
						hexc+=binascii.hexlify(by)+" "
						indx+=2
						va=self.from_bytes(by,"little")
						by=bytearray()
						by.append(self.insns[indx])
						by.append(self.insns[indx+1])
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
						va=oper &  0x0F
						opers="v"+str(va)+" = "+str(value)
					elif type == 6:
						#VA 8 bits, signed int 16 bits
						by=bytearray()
						by.append(self.insns[indx])
						by.append(self.insns[indx+1])
						value=self.from_bytes(by,"little")
						indx+=2
						va=oper
						opers="v"+str(va)+" = "+str(value)
						hexc+=binascii.hexlify(by)
					elif type == 7:
						#VA 8 bits, signed int 32 bits
						va=oper
						by=bytearray()
						by.append(self.insns[indx])
						by.append(self.insns[indx+1])
						by.append(self.insns[indx+2])
						by.append(self.insns[indx+3])
						indx+=4
						value=self.from_bytes(by,"little")
						opers="v"+str(va)+" = "+str(value)
						hexc+=binascii.hexlify(by)
					elif type == 8:
						#VA 8 bits, signed int 64 bits
						va=oper
						by=bytearray()
						by.append(self.insns[indx])
						by.append(self.insns[indx+1])
						hexc+=binascii.hexlify(by)+" "
						by.append(self.insns[indx+2])
						by.append(self.insns[indx+3])
						hexc+=binascii.hexlify(by)+" "
						indx+=4
						by.append(self.insns[indx])
						by.append(self.insns[indx+1])
						hexc+=binascii.hexlify(by)+" "
						by.append(self.insns[indx+2])
						by.append(self.insns[indx+3])
						hexc+=binascii.hexlify(by)
						indx+=4
						value=self.from_bytes(by,"little")
						opers="v"+str(va)+" = "+str(value)
					elif type == 9:
						#VA 8 bits, string index 16 bits
						va=oper
						by=bytearray()
						by.append(self.insns[indx])
						by.append(self.insns[indx+1])
						hexc+=binascii.hexlify(by)
						indx+=2
						value=self.from_bytes(by,"little")
						opers="v"+str(va)+" = "+str(value)
					elif type == 10:
						#VA 8 bits, string index 32 bits
						va=oper
						by=bytearray()
						by.append(self.insns[indx])
						by.append(self.insns[indx+1])
						hexc+=binascii.hexlify(by)+" "
						by.append(self.insns[indx+2])
						by.append(self.insns[indx+3])
						hexc+=binascii.hexlify(by)
						indx+=4
						value=self.from_bytes(by,"little")
						opers="v"+str(va)+" = "+str(value)
					elif type == 11:
						#VA 8 bits, type index 16 bits
						va=oper
						by=bytearray()
						by.append(self.insns[indx])
						by.append(self.insns[indx+1])
						hexc+=binascii.hexlify(by)
						indx+=2
						value=self.from_bytes(by,"little")
						opers="v"+str(va)+" , "+str(value)
					elif type == 12:
						#VA 4 bits, VB 4 bits, type index 16 bits						
						va=(oper & 0xF0) >> 4
						vb=oper &  0x0F
						by=bytearray()
						by.append(self.insns[indx])
						by.append(self.insns[indx+1])
						hexc+=binascii.hexlify(by)
						indx+=2
						value=self.from_bytes(by,"little")
						opers="v"+str(va)+", v"+str(vb)+" , "+str(value)
					elif type == 13:
						#FILLED NEW ARRAY -> TO IMPLEMENTS
						opers="TO IMPLEMENTS -> MAYBE THERE ARE ERRORS"
					elif type == 14:
						#signed brach 8 bits
						opers=str(oper)
					elif type == 15:
						#signed brach 16 bits -> NOT ALLIGNED
						by=bytearray()
						by.append(oper)
						by.append(self.insns[indx])
						hexc+=binascii.hexlify(by)+" "
						indx+=1
						opers=self.from_bytes(by,"little")
					elif type == 16:
						#signed brach 32 bits
						by=bytearray()
						by.append(oper)
						by.append(self.insns[indx])
						hexc+=binascii.hexlify(by)+" "
						by.append(self.insns[indx+1])
						by.append(self.insns[indx+2])
						hexc+=binascii.hexlify(by)
						indx+=3
						opers=self.from_bytes(by,"little")
					elif type == 17:
						#17 VA 8 bits, VB 32 bits
						va=oper
						by=bytearray()
						by.append(self.insns[indx])
						by.append(self.insns[indx+1])
						hexc+=binascii.hexlify(by)+" "
						by.append(self.insns[indx+2])
						by.append(self.insns[indx+3])
						hexc+=binascii.hexlify(by)+" "
						vb=self.from_bytes(by,"little")
						indx+=4
						opers="v"+str(va)+", v"+str(vb)
					elif type == 18:
						#18 VA 8 bits, VB 8 bits, VC 8 bits
						va=oper
						vb=self.insns[indx]
						hexc+=format(self.insns[indx],'02x')
						vc=self.insns[indx+1]
						hexc+=format(self.insns[indx+1],'02x')
						indx+=2
						opers="v"+str(va)+", v"+str(vb)+", v"+str(vc)
					elif type == 19:
						#19 VA 4 bits, VB 4 bits, signed branch 16 bits
						va=(oper & 0xF0) >> 4
						vb=oper &  0x0F
						by=bytearray()
						by.append(self.insns[indx])
						by.append(self.insns[indx+1])
						hexc+=binascii.hexlify(by)
						indx+=2
						opers="v"+str(va)+", v"+str(vb)+" ,"+str(self.from_bytes(by,"little"))
					elif type == 20:
						#20 VA 8 bits, signed branch 16 bits
						va=oper
						by=bytearray()
						by.append(self.insns[indx])
						by.append(self.insns[indx+1])
						hexc+=binascii.hexlify(by)
						indx+=2
						opers="v"+str(va)+", "+str(self.from_bytes(by,"little"))
					elif type == 21:
						#21 VA 8 bits, VB 8 bits, VC 8 bits
						va=oper
						vb=self.insns[indx]
						vc=self.insns[indx+1]
						hexc+=format(self.insns[indx],'02x')+" "+format(self.insns[indx+1],'02x')
						indx+=2
						opers="v"+str(va)+", "+"v"+str(vb)+", "+"v"+str(vc)
					elif type == 22:
						#22 VA 4 bits, VB 4 bits, field index 16 bits
						va=(oper & 0xF0) >> 4
						vb=oper &  0x0F
						by=bytearray()
						by.append(self.insns[indx])
						by.append(self.insns[indx+1])
						hexc+=binascii.hexlify(by)
						field=self.from_bytes(by,"little")
						indx+=2
						opers="v"+str(va)+", "+"v"+str(vb)+", "+str(field)
					elif type == 23:
						#23 VA 8 bits, field index 16 bits
						va=oper
						by=bytearray()
						by.append(self.insns[indx])
						by.append(self.insns[indx+1])
						hexc+=binascii.hexlify(by)
						field=self.from_bytes(by,"little")
						indx+=2
						field=self.from_bytes(by,"little")
						opers="v"+str(va)+", "+str(field)
					elif type == 24:
						#24 VA 4 bits, VB 16 bits, VC VD VE 4 bits each -> INVOKE
						va=(oper & 0xF0) >> 4
						i=2
						v=[]
						if va > 0:
							v.append(oper & 0x0F)
						by=bytearray()
						by.append(self.insns[indx])
						by.append(self.insns[indx+1])
						hexc+=binascii.hexlify(by)+" "
						vb=self.from_bytes(by,"little")
						indx+=2
						waste=4-(va-1)
						while i <= va:
							if i%2==0:
								by=self.insns[indx]
								hexc+=format(by,'02x')
								indx+=1
								print "INCREMENTATO:"+str(indx)
								v.append(((by & 0xF0) >> 4))
								i+=1
							else:
								v.append((by & 0x0F))
								i+=1
						if waste > 1:
							by=self.insns[indx]
							hexc+=format(by,'02x')
							if waste % 2 == 0:
								by=self.insns[indx+1]
								hexc+=format(by,'02x')
								indx+=1
							indx+=1
						opers="{"
						for item in v:
							if item == v[-1]:
								opers+="v"+str(item)
							else:
								opers+="v"+str(item)+","
						opers+="} "+str(vb)
					returned.append(hexc)
					returned.append(dy.dict[opc]+" "+opers)
					print "INDEX:"+str(indx)
					print returned
					
				return returned
			def __str__(self):
				returned="{\n"
				returned+="\tRegister:\t\t"+str(self.registers_size)+"\n"
				returned+="\tWords incoming:\t"+str(self.ins_size)+"\n"
				returned+="\tWords outgoing:\t"+str(self.outs_size)+"\n"
				returned+="\tTry items:\t"+str(self.tries_size)+"\n"
				if self.debug_info_off == 0:
					returned+="\tDebug information:\t None"+"\n"
				else:
					#Debug info
					returned+="\tDebug information:\t INSERTED"+"\n"
					pass
				returned+="\tLoC:\t\t"+str(self.insns_size)+"\n"
				#Convert Bytecode into Human Readable Format
				returned+="\n\n \t\t#---CODE BEGIN---\n\n"
				codex=self.ByteCodeToString()
				indx=0
				while indx<len(codex):
					returned+="\t"+codex[indx]+":\t"+codex[indx+1]+"\n"
					indx+=2
				returned+="}"
				return returned
		def __init__(self):
			self.class_idx=0				#index into the type_ids list for this class. This must be a class type, and not 
											#an array or primitive type.
			self.access_flags=0				#access flags for the class (public, final, etc.). See "access_flags Definitions" for details.
			self.superclass_idx=0			#index into the type_ids list for the superclass, or the constant value NO_INDEX if this class
											#has no superclass (i.e., it is a root class such as Object). If present,
											#this must be a class type, and not an array or primitive type.
			self.interfaces_off=0			#offset from the start of the file to the list of interfaces, or 0 if there are none.
											#This offset should be in the data section, and the data there should be in the format
											#specified by "type_list" below. Each of the elements of the list must be a class type
											#(not an array or primitive type), and there must not be any duplicates.
			self.source_file_idx=0			#index into the string_ids list for the name of the file containing the
											#original source for (at least most of) this class, or the special value NO_INDEX to
											#represent a lack of this information. The debug_info_item of any given method may override this
											#source file, but the expectation is that most classes will only come from one source file.
			self.annotations_off=0			#offset from the start of the file to the annotations structure for this class, or 0 if there are no annotations on
											#this class. This offset, if non-zero, should be in the data section, and the data there should be in the format
											#specified by "annotations_directory_item" below, with all items referring to this class as the definer.
			self.class_data_off=0			#offset from the start of the file to the associated class data for this item, or 0 if there is no class data
											#for this class. (This may be the case, for example, if this class is a marker interface.) The offset,
											#if non-zero, should be in the data section, and the data there should be in the format specified
											#by "class_data_item" below, with all items referring to this class as the definer.
			self.static_values_off=0		#offset from the start of the file to the list of initial values for static fields,
											#or 0 if there are none (and all static fields are to be initialized with 0 or null).
											#This offset should be in the data section, and the data there should be in the format specified by
											#"encoded_array_item" below. The size of the array must be no larger than the number of static
											#fields declared by this class, and the elements correspond to the static fields in the same
											#order as declared in the corresponding field_list. The type of each array element
											#must match the declared type of its corresponding field. If there are fewer elements in
											#the array than there are static fields, then the leftover fields are initialized with a
											#type-appropriate 0 or null.
			self.cdi=self.class_data_item()
			self.access_flagd={}
			self.access_flagd[1]="public"
			self.access_flagd[2]="private"
			self.access_flagd[3]="protected"
			self.access_flagd[4]="static"
			self.access_flagd[5]="final"
			self.access_flagd[6]="synchronized"
			self.access_flagd[7]="volatile"
			self.access_flagd[8]="transient"
			self.access_flagd[9]="native"
			self.access_flagd[10]="interface"
			self.access_flagd[11]="abstract"
			self.access_flagd[12]="strictfp"
			self.access_flagd[13]="synthetic"
			self.access_flagd[14]="annotation"
			self.access_flagd[15]="enumerator"
			self.access_flagd[16]="unused"
			self.access_flagd[17]="constructor"
			self.access_flagd[18]="synchronized"

	def printClass(self,indx):
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
				returned.append(str(cod))
			returned.append("\n\n\n")
			pr=k.method_idx_diff+pr
			index+=1
		return returned
	
	def getCode(self,indx):
		self.dexFl.seek(indx)
		code=self.CClassDEF.code_item()
		code.registers_size=self.from_bytes(bytearray(self.dexFl.read(2)),"little")
		code.ins_size=self.from_bytes(bytearray(self.dexFl.read(2)),"little")
		code.outs_size=self.from_bytes(bytearray(self.dexFl.read(2)),"little")
		code.tries_size=self.from_bytes(bytearray(self.dexFl.read(2)),"little")
		code.debug_info_off=self.from_bytes(bytearray(self.dexFl.read(4)),"little")
		code.insns_size=self.from_bytes(bytearray(self.dexFl.read(4)),"little")
		
		#reading bytecode
		indx=0
		print "\n\nINDICE FILE:"+str(self.dexFl.tell())
		while indx < (code.insns_size*2):
			cx=int(binascii.hexlify(self.dexFl.read(1)),16)
			code.insns.append(cx)
			indx+=1
		print "LENGTH:"+str(len(code.insns))
		return code
		
	def decodeType(self,cl):
		pass
		
	def readClass(self,indx):
		i=self.ClassDEF[indx]
		#Read static field
		self.dexFl.seek(i.static_values_off)
		st=i.encoded_array()
		st.size=self.from_bytes(bytearray(self.dexFl.read(1)),"little")
		st.values=int(i.static_values_off+1)
		i.static_values=st
		#class_data_off
		#CHECK 0 VALUE IF NOT DATA SET
		self.dexFl.seek(i.class_data_off)
		print i.class_data_off
		print "\n\nReading the offset..."
		i.cdi.static_fields_size=self.decodeULEB(self.dexFl)
		i.cdi.instance_fields_size=self.decodeULEB(self.dexFl)
		i.cdi.direct_methods_size=self.decodeULEB(self.dexFl)
		i.cdi.virtual_methods_size=self.decodeULEB(self.dexFl)
		
		print "\n\nReading static field..."
		ind=0
		while ind < i.cdi.static_fields_size:
			enc=i.encoded_field()
			enc.field_idx_diff=self.decodeULEB(self.dexFl)
			#print "statico FIELD_IDX_DIFF:"+str(enc.field_idx_diff)
			enc.access_flags=self.decodeULEB(self.dexFl)
			#print "statico flag:"+str(enc.access_flags)
			i.cdi.static_fields.append(enc)
			ind+=1
		
		print "\n\nReading instance fields..."
		ind=0
		while ind < i.cdi.instance_fields_size:
			enc=i.encoded_field()
			enc.field_idx_diff=self.decodeULEB(self.dexFl)
			#print "FIELD_IDX_DIFF:"+str(enc.field_idx_diff)
			enc.access_flags=self.decodeULEB(self.dexFl)
			i.cdi.instance_fields.append(enc)
			ind+=1
		
		print "\n\nReading the direct method..."
		ind=0
		while ind < i.cdi.direct_methods_size:
			enc=i.encoded_method()
			enc.method_idx_diff=self.decodeULEB(self.dexFl)
			enc.access_flags=self.decodeULEB(self.dexFl)			
			enc.code_off=self.decodeULEB(self.dexFl)
			i.cdi.direct_methods.append(enc)
			ind+=1
			
		print "\n\nReading the virtual method..."
		ind=0
		while ind < i.cdi.virtual_methods_size:
			enc=i.encoded_method()
			enc.method_idx_diff=self.decodeULEB(self.dexFl)
			enc.access_flags=self.decodeULEB(self.dexFl)
			enc.code_off=self.decodeULEB(self.dexFl)
			i.cdi.virtual_methods.append(enc)
			ind+=1
		
		#Init static field
		#print "\n\nReading the initial value of static field..."
		#self.dexFl.seek(i.static_values_off)
		#ind=0
		#while ind<i.cdi.static_fields_size:
			
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
		
	def __init__(self):
		self.Head=self.Header()
		self.String=[]
		self.TypeIDS=[]
		self.ProtoIDS=[]
		self.FieldIDS=[]
		self.MethodIDS=[]
		self.ClassDEF={}
	
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
	
	def getClassesName(self):
		returned={}
		for i in self.ClassDEF:
			#print i.class_idx
			returned[self.String[self.TypeIDS[i]].string_data_data]=i
		return returned
	
	def getStringList(self):
		returned=[]
		for i in self.String:
			returned.append(i.string_data_data)
		return returned
		
	def getTypeList(self):
		returned=[]
		for i in self.TypeIDS:
			returned.append(self.String[i].string_data_data)
		return returned
		
	def ReadDex(self,f):
		self.dexFl=f
		print "Reading header..."
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
		print "Magic Number:\t\t0x"+binascii.hexlify(self.Head.MagicNumber[0:4])+"\t["+self.Head.MagicNumber[0:3]+"]"
		print "DEX Version:\t\t0x"+binascii.hexlify(self.Head.MagicNumber[4:8])+"\t["+self.Head.MagicNumber[4:7]+"]"
		print "Checksum:\t\t0x"+binascii.hexlify(self.Head.checksum)
		print "Signature:\t\t0x"+binascii.hexlify(self.Head.signature)
		print "File size:\t\t"+str(self.Head.file_size)
		print "Header size:\t\t"+str(self.Head.header_size)
		print "Ordering byte:\t\t0x"+binascii.hexlify(self.Head.endian_tag)
		print "Link size:\t\t"+str(self.Head.link_size)
		print "Link offset:\t\t"+str(self.Head.link_off)
		print "Map offset:\t\t"+str(self.Head.map_off)
		print "String IDS size:\t"+str(self.Head.string_ids_size)
		print "String IDS offset:\t"+str(self.Head.string_ids_off)
		#print "String IDS offset:\t0x"+binascii.hexlify(self.string_ids_off)
		print "Type IDS size:\t\t"+str(self.Head.type_ids_size)
		print "Type IDS offset:\t"+str(self.Head.type_ids_off)
		print "Proto IDS size:\t\t"+str(self.Head.proto_ids_size)
		print "Proto IDS offset:\t"+str(self.Head.proto_ids_off)
		print "Field IDS size:\t\t"+str(self.Head.field_ids_size)
		print "Field IDS offset:\t"+str(self.Head.field_ids_off)
		print "Method IDS size:\t"+str(self.Head.method_ids_size)
		print "Method IDS offset:\t"+str(self.Head.method_ids_off)
		print "Class DEFS size:\t"+str(self.Head.class_defs_size)
		print "Class DEFS offset:\t"+str(self.Head.class_defs_off)
		print "Data size:\t\t"+str(self.Head.data_size)
		print "Data offset:\t\t"+str(self.Head.data_off)

		#Strings
		print "\n\nReading strings..."
		f.seek(self.Head.string_ids_off)
		i=0
		while i < self.Head.string_ids_size:
			s=self.StringIDS()
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
#		i=0
#		while i<self.Head.string_ids_size:
#			print "Index:"+str(i)+"\tOffset:"+str(self.String[i].string_data_off)+"\tLegth:"+str(self.String[i].string_data_len)+"\tData:"+self.String[i].string_data_data
#			i+=1
		#Type
		print "\n\nReading types..."
		f.seek(self.Head.type_ids_off)
		i=0
		while i < self.Head.type_ids_size:
			index=self.from_bytes(bytearray(f.read(4)),order)
			i+=1
			self.TypeIDS.append(index)
		#for i in self.TypeIDS:
		#	print str(i) + "\tStr:"+self.String[i].string_data_data
		
		
		#Protype
		print "\n\nReading prototypes..."
		f.seek(self.Head.proto_ids_off)
		i=0
		while i < self.Head.proto_ids_size:
			s=self.CProtoIDS()
			s.shorty_idx=self.from_bytes(bytearray(f.read(4)),order)
			s.return_type_idx=self.from_bytes(bytearray(f.read(4)),order)
			s.parameters_off=self.from_bytes(bytearray(f.read(4)),order)
			i+=1
			self.ProtoIDS.append(s)
			
		#Fields
		print "\n\nReading fields..."
		f.seek(self.Head.field_ids_off)
		i=0
		#print self.Head.field_ids_off
		while i < self.Head.field_ids_size:
			s=self.CFieldIDS()
			s.class_idx=self.from_bytes(bytearray(f.read(2)),"little")
			s.type_idx=self.from_bytes(bytearray(f.read(2)),"little")
			s.name_idx=self.from_bytes(bytearray(f.read(4)),"little")
			#print str(i)+":\tClass:"+str(s.class_idx)+"\tField:"+str(s.name_idx)
			i+=1
			self.FieldIDS.append(s)
			
		#Methods
		print "\n\nReading methods..."
		f.seek(self.Head.method_ids_off)
		i=0
		while i < self.Head.method_ids_size:
			s=self.CMethodIDS()
			s.class_idx=self.from_bytes(bytearray(f.read(2)),order)
			s.proto_idx=self.from_bytes(bytearray(f.read(2)),order)
			s.name_idx=self.from_bytes(bytearray(f.read(4)),order)
			i+=1
			self.MethodIDS.append(s)
			
			
		#CLASSES
		print "\n\nReading classes..."
		f.seek(self.Head.class_defs_off)
		i=0
		while i < self.Head.class_defs_size:
			s=self.CClassDEF()
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
		
	#2052
#		self.readClass(int('2053'))
		#print self.printClass(int('2053'))
		#self.printClass(int('2053'))

#dx=DexFile()
#f=open('classes.dex','rb')
#dx.ReadDex(f)