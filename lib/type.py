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
		self.parameters=[]
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

			self.static_values=[]
			
				
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
			self.values=[]				#Offset from the start of file where find the field
	
	class encoded_value:
		def __init__(self):
			self.value_arg=0			#ubyte	byte indicating the type of the immediately subsequent value along with an optional
										#clarifying argument in the high-order three bits. See below for the various value definitions.
										#In most cases, value_arg encodes the length of the immediately-subsequent value in bytes, as
										#(size - 1), e.g., 0 means that the value requires one byte, and 7 means it requires eight bytes;
										#however, there are exceptions as noted below.
			self.value=0				#ubyte[] bytes representing the value, variable in length and interpreted differently
										#for different value_type bytes, though always little-endian.
		def __str__(self):
			return str(self.value)
	
	class encoded_annotation:
		def __init__(self):
			self.type_idx=0				#uleb128	type of the annotation. This must be a class not array or primitive) type.
			self.size=0					#uleb128	number of name-value mappings in this annotation
			self.elements={}			#annotation_element[size]	elements of the annotation, represented
										#directly in-line (not as offsets). Elements must be sorted in
										#increasing order by string_id index.
											#name_idx (Key)	uleb128	element name, represented as an index into
											#the string_ids section. The string must conform to the syntax for
											#MemberName, defined above.
											#value	encoded_value	element value
		
		def __str__(self):
			return "ANNOTATION FOR NOW"
			
	
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
		self.read=False		
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