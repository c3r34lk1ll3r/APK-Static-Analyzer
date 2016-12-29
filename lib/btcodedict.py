class ByteCodeDictionary:
	def __init__(self):
		self.dict={}
		self.dict[0x00]="NOP"
		self.dict[0x01]="move"
		self.dict[0x02]="move/from16"
		self.dict[0x03]="move/16"
		self.dict[0x04]="move-wide"
		self.dict[0x05]="move-wide/from16"
		self.dict[0x06]="move-wiide/16"
		self.dict[0x07]="move-object"
		self.dict[0x08]="move-object/from16"
		self.dict[0x09]="move-object/16"
		self.dict[0x0A]="move-result"
		self.dict[0x0B]="move-result-wide"
		self.dict[0x0C]="move-result-object"
		self.dict[0x0D]="move-exception"
		self.dict[0x0E]="return-void"
		self.dict[0x0F]="return"
		
		self.dict[0x10]="return-wide"
		self.dict[0x11]="return-object"
		self.dict[0x12]="const/4"
		self.dict[0x13]="const/16"
		self.dict[0x14]="const"
		self.dict[0x15]="const/high16"
		self.dict[0x16]="const-wide/16"
		self.dict[0x17]="const-wide/32"
		self.dict[0x18]="const-wide"
		self.dict[0x19]="const-wide/high16"
		self.dict[0x1A]="const-string"
		self.dict[0x1B]="const-string-jumbo"
		self.dict[0x1C]="const-class"
		self.dict[0x1D]="monitor-enter"
		self.dict[0x1E]="monitor-exit"
		self.dict[0x1F]="check-cast"

		self.dict[0x20]="instance-of"
		self.dict[0x21]="array-length"
		self.dict[0x22]="new-instance"
		self.dict[0x23]="new-array"
		self.dict[0x24]="filled-new-array"
		self.dict[0x25]="filled-new-array-range"
		self.dict[0x26]="fill-array-data"
		self.dict[0x27]="throw"
		self.dict[0x28]="goto"
		self.dict[0x29]="goto/16"
		self.dict[0x2A]="goto/32"
		self.dict[0x2B]="packed-switch"
		self.dict[0x2C]="sparse-switch"
		self.dict[0x2D]="cmpl-float"
		self.dict[0x2E]="cmpg-float"
		self.dict[0x2F]="cmpg-double"

		self.dict[0x30]="cmpg-double"
		self.dict[0x31]="cmp-long"
		self.dict[0x32]="if-eq"
		self.dict[0x33]="if-ne"
		self.dict[0x34]="if-lt"
		self.dict[0x35]="if-ge"
		self.dict[0x36]="if-gt"
		self.dict[0x37]="if-le"
		self.dict[0x38]="if-eqz"
		self.dict[0x39]="if-nez"
		self.dict[0x3A]="if-ltz"
		self.dict[0x3B]="if-gez"
		self.dict[0x3C]="if-gtz"
		self.dict[0x3D]="if-lez"
		self.dict[0x3E]="unused"
		self.dict[0x3F]="unused"
		
		self.dict[0x40]="unused"
		self.dict[0x41]="unused"
		self.dict[0x42]="unused"
		self.dict[0x43]="unused"
		self.dict[0x44]="aget"
		self.dict[0x45]="aget-wide"
		self.dict[0x46]="aget-object"
		self.dict[0x47]="aget-boolean"
		self.dict[0x48]="aget-byte"
		self.dict[0x49]="aget-char"
		self.dict[0x4A]="aget-short"
		self.dict[0x4B]="aput"
		self.dict[0x4C]="aput-wide"
		self.dict[0x4D]="aput-object"
		self.dict[0x4E]="aput-boolean"
		self.dict[0x4F]="aput-byte"

		self.dict[0x50]="aput-char"
		self.dict[0x51]="aput-short"
		self.dict[0x52]="iget"
		self.dict[0x53]="iget-wide"
		self.dict[0x54]="iget-object"
		self.dict[0x55]="iget-boolean"
		self.dict[0x56]="iget-byte"
		self.dict[0x57]="iget-char"
		self.dict[0x58]="iget-short"
		self.dict[0x59]="iput"
		self.dict[0x5A]="iput-wide"
		self.dict[0x5B]="iput-object"
		self.dict[0x5C]="iput-boolean"
		self.dict[0x5D]="iput-byte"
		self.dict[0x5E]="iput-char"
		self.dict[0x5F]="iput-short"

		self.dict[0x60]="sget"
		self.dict[0x61]="sget-wide"
		self.dict[0x62]="sget-object"
		self.dict[0x63]="sget-boolean"
		self.dict[0x64]="sget-byte"
		self.dict[0x65]="sget-char"
		self.dict[0x66]="sget-short"
		self.dict[0x67]="sput"
		self.dict[0x68]="sput-wide"
		self.dict[0x69]="sput-object"
		self.dict[0x6A]="sput-boolean"
		self.dict[0x6B]="sput-byte"
		self.dict[0x6C]="sput-char"
		self.dict[0x6D]="sput-short"
		self.dict[0x6E]="invoke-virtual"
		self.dict[0x6F]="invoke-super"
		
		self.dict[0x70]="invoke-direct"
		self.dict[0x71]="invoke-static"
		self.dict[0x72]="invoke-interface"
		self.dict[0x73]="unused"
		self.dict[0x74]="invoke-virtual/range"
		self.dict[0x75]="invoke-super/range"
		self.dict[0x76]="invoke-direct/range"
		self.dict[0x77]="invoke-static/range"
		self.dict[0x78]="invoke-interface-range"
		self.dict[0x79]="unused"
		self.dict[0x7A]="unused"
		self.dict[0x7B]="neg-int"
		self.dict[0x7C]="not-int"
		self.dict[0x7D]="neg-long"
		self.dict[0x7E]="not-long"
		self.dict[0x7F]="neg-float"

		self.dict[0x80]="neg-double"
		self.dict[0x81]="int-to-long"
		self.dict[0x82]="int-to-float"
		self.dict[0x83]="int-to-double"
		self.dict[0x84]="long-to-int"
		self.dict[0x85]="long-to-float"
		self.dict[0x86]="long-to-double"
		self.dict[0x87]="float-to-int"
		self.dict[0x88]="float-to-long"
		self.dict[0x89]="float-to-double"
		self.dict[0x8A]="double-to-int"
		self.dict[0x8B]="double-to-long"
		self.dict[0x8C]="double-to-float"
		self.dict[0x8D]="int-to-byte"
		self.dict[0x8E]="int-to-char"
		self.dict[0x8F]="int-to-short"

		self.dict[0x90]="add-int"
		self.dict[0x91]="sub-int"
		self.dict[0x92]="mul-int"
		self.dict[0x93]="div-int"
		self.dict[0x94]="rem-int"
		self.dict[0x95]="add-int"
		self.dict[0x96]="or-int"
		self.dict[0x97]="xor-int"
		self.dict[0x98]="shl-int"
		self.dict[0x99]="shr-int"
		self.dict[0x9A]="ushr-int"
		self.dict[0x9B]="add-long"
		self.dict[0x9C]="sub-long"
		self.dict[0x9D]="mul-long"
		self.dict[0x9E]="div-long"
		self.dict[0x9F]="rem-long"
		
		self.dict[0xA0]="and-long"
		self.dict[0xA1]="or-long"
		self.dict[0xA2]="xor-long"
		self.dict[0xA3]="shl-long"
		self.dict[0xA4]="shr-long"
		self.dict[0xA5]="ushr-long"
		self.dict[0xA6]="add-float"
		self.dict[0xA7]="sub-float"
		self.dict[0xA8]="mul-float"
		self.dict[0xA9]="div-float"
		self.dict[0xAA]="rem-float"
		self.dict[0xAB]="add-double"
		self.dict[0xAC]="sub-double"
		self.dict[0xAD]="mul-double"
		self.dict[0xAE]="div-double"
		self.dict[0xAF]="rem-double"

		self.dict[0xB0]="add-int/2addr"
		self.dict[0xB1]="sub-int/2addr"
		self.dict[0xB2]="mul-int/2addr"
		self.dict[0xB3]="div-int/2addr"
		self.dict[0xB4]="rem-int/2addr"
		self.dict[0xB5]="add-int/2addr"
		self.dict[0xB6]="or-int/2addr"
		self.dict[0xB7]="xor-int/2addr"
		self.dict[0xB8]="shl-int/2addr"
		self.dict[0xB9]="shr-int/2addr"
		self.dict[0xBA]="ushr-int/2addr"
		self.dict[0xBB]="add-long/2addr"
		self.dict[0xBC]="sub-long/2addr"
		self.dict[0xBD]="mul-long/2addr"
		self.dict[0xBE]="div-long/2addr"
		self.dict[0xBF]="rem-long/2addr"

		self.dict[0xC0]="and-long/2addr"
		self.dict[0xC1]="or-long/2addr"
		self.dict[0xC2]="xor-long/2addr"
		self.dict[0xC3]="shl-long/2addr"
		self.dict[0xC4]="shr-long/2addr"
		self.dict[0xC5]="ushr-long/2addr"
		self.dict[0xC6]="add-float/2addr"
		self.dict[0xC7]="sub-float/2addr"
		self.dict[0xC8]="mul-float/2addr"
		self.dict[0xC9]="div-float/2addr"
		self.dict[0xCA]="rem-float/2addr"
		self.dict[0xCB]="add-double/2addr"
		self.dict[0xCC]="sub-double/2addr"
		self.dict[0xCD]="mul-double/2addr"
		self.dict[0xCE]="div-double/2addr"
		self.dict[0xCF]="rem-double/2addr"
 
		self.dict[0xD0]="add-int/lit16"
		self.dict[0xD1]="sub-int/lit16"
		self.dict[0xD2]="mul-int/lit16"
		self.dict[0xD3]="div-int/lit16"
		self.dict[0xD4]="rem-int/lit16"
		self.dict[0xD5]="and-int/lit16"
		self.dict[0xD6]="or-int/lit16"
		self.dict[0xD7]="xor-int/lit16"
		self.dict[0xD8]="add-int/lit8"
		self.dict[0xD9]="sub-int/lit8"
		self.dict[0xDA]="mul-int/lit8"
		self.dict[0xDB]="div-int/lit8"
		self.dict[0xDC]="rem-int/lit8"
		self.dict[0xDD]="and-int/lit8"
		self.dict[0xDE]="or-int/lit8"
		self.dict[0xDF]="xor-int/lit8"

		self.dict[0xE0]="shl-int/lit8"
		self.dict[0xE1]="shr-int/lit8"
		self.dict[0xE2]="ushr-int/lit8"
		self.dict[0xE3]="unused"
		self.dict[0xE4]="unused"
		self.dict[0xE5]="unused"
		self.dict[0xE6]="unused"
		self.dict[0xE7]="unused"
		self.dict[0xE8]="unused"
		self.dict[0xE9]="unused"
		self.dict[0xEA]="unused"
		self.dict[0xEB]="unused"
		self.dict[0xEC]="unused"
		self.dict[0xED]="unused"
		self.dict[0xEE]="execute-inline"
		self.dict[0xEF]="unused"

		self.dict[0xF0]="invoke-direct-empty"
		self.dict[0xF1]="unused"
		self.dict[0xF2]="iget-quick"
		self.dict[0xF3]="iget-wide-quick"
		self.dict[0xF4]="iget-object-quick"
		self.dict[0xF5]="iput-quick"
		self.dict[0xF6]="iput-wide-quick"
		self.dict[0xF7]="iput-object-quick "
		self.dict[0xF8]="invoke-virtual-quick"
		self.dict[0xF9]="invoke-virtual-quick/range"
		self.dict[0xFA]="invoke-super-quick"
		self.dict[0xFB]="invoke-super-quick/range"
		self.dict[0xFC]="unused"
		self.dict[0xFD]="unused"
		self.dict[0xFE]="unused"
		self.dict[0xFF]="unused"
		
		#0  NO operator
		#1  VA 4 bits, VB 4 bits
		#2  VA 8 bits, VB 16 bits
		#3  VA 16 bits, VB 16 bits
		#4  VA 8 bits
		#5  VA 4 bits, signed int 4 bits
		#6  VA 8 bits, signed int 16 bits
		#7  VA 8 bits, signed int 32 bits
		#8  VA 8 bits, signed int 64 bits
		#9  VA 8 bits, index string 16 bits
		#10 VA 8 bits, index string 32 bits
		#11 VA 8 bits, type string 32 bits
		#12 VA 4 bits, VB 4 bits, type index 16 bits
		
		self.oper={}
		self.oper[0x00]=0
		self.oper[0x01]=1
		self.oper[0x02]=2
		self.oper[0x03]=3
		self.oper[0x04]=1
		self.oper[0x05]=2
		self.oper[0x06]=3
		self.oper[0x07]=1
		self.oper[0x08]=2
		self.oper[0x09]=3
		self.oper[0x0A]=4
		self.oper[0x0B]=4
		self.oper[0x0C]=4
		self.oper[0x0D]=4
		self.oper[0x0E]=0
		self.oper[0x0F]=4
		
		self.oper[0x10]=4
		self.oper[0x11]=4
		self.oper[0x12]=5
		self.oper[0x13]=6
		self.oper[0x14]=7
		self.oper[0x15]=6
		self.oper[0x16]=6
		self.oper[0x17]=7
		self.oper[0x18]=8
		self.oper[0x19]=6
		self.oper[0x1A]=9
		self.oper[0x1B]=10
		self.oper[0x1C]=11
		self.oper[0x1D]=4
		self.oper[0x1E]=4
		self.oper[0x1F]=11

		#0  NO operator
		#1  VA 4 bits, VB 4 bits
		#2  VA 8 bits, VB 16 bits
		#3  VA 16 bits, VB 16 bits
		#4  VA 8 bits
		#5  VA 4 bits, signed int 4 bits
		#6  VA 8 bits, signed int 16 bits
		#7  VA 8 bits, signed int 32 bits
		#8  VA 8 bits, signed int 64 bits
		#9  VA 8 bits, string index 16 bits
		#10 VA 8 bits, string index 32 bits
		#11 VA 8 bits, type index 16 bits
		#12 VA 4 bits, VB 4 bits, type index 16 bits
		#13 FILLED NEW ARRAY -> TO IMPLEMENTS
		#14 signed brach 8 bits
		#15 signed brach 16 bits
		#16 signed brach 32 bits
		#17 VA 8 bits, VB 32 bits
		#18 VA 8 bits, VB 8 bits, VC 8 bits
		#19 VA 4 bits, VB 4 bits, signed branch 16 bits
		#20 VA 8 bits, signed branch 16 bits
		
		self.oper[0x20]=12
		self.oper[0x21]=1
		self.oper[0x22]=11
		self.oper[0x23]=12
		self.oper[0x24]=13
		self.oper[0x25]=13
		self.oper[0x26]=26
		self.oper[0x27]=4
		self.oper[0x28]=14
		self.oper[0x29]=15
		self.oper[0x2A]=16
		self.oper[0x2B]=17
		self.oper[0x2C]=17
		self.oper[0x2D]=18
		self.oper[0x2E]=18
		self.oper[0x2F]=18

		self.oper[0x30]=18
		self.oper[0x31]=18
		self.oper[0x32]=19
		self.oper[0x33]=19
		self.oper[0x34]=19
		self.oper[0x35]=19
		self.oper[0x36]=19
		self.oper[0x37]=19
		self.oper[0x38]=20
		self.oper[0x39]=20
		self.oper[0x3A]=20
		self.oper[0x3B]=20
		self.oper[0x3C]=20
		self.oper[0x3D]=20
		self.oper[0x3E]=0
		self.oper[0x3F]=0
		
		#0  NO operator
		#1  VA 4 bits, VB 4 bits
		#2  VA 8 bits, VB 16 bits
		#3  VA 16 bits, VB 16 bits
		#4  VA 8 bits
		#5  VA 4 bits, signed int 4 bits
		#6  VA 8 bits, signed int 16 bits
		#7  VA 8 bits, signed int 32 bits
		#8  VA 8 bits, signed int 64 bits
		#9  VA 8 bits, string index 16 bits
		#10 VA 8 bits, string index 32 bits
		#11 VA 8 bits, type index 16 bits
		#12 VA 4 bits, VB 4 bits, type index 16 bits
		#13 FILLED NEW ARRAY -> TO IMPLEMENTS
		#14 signed brach 8 bits
		#15 signed brach 16 bits
		#16 signed brach 32 bits
		#17 VA 8 bits, VB 32 bits
		#18 VA 8 bits, VB 8 bits, VC 8 bits
		#19 VA 4 bits, VB 4 bits, signed branch 16 bits
		#20 VA 8 bits, signed branch 16 bits
		#21 VA 8 bits, VB 8 bits, VC 8 bits
		#22 VA 4 bits, VB 4 bits, field index 16 bits
		#23 VA 8 bits, field index 16 bits
		
		self.oper[0x40]=0
		self.oper[0x41]=0
		self.oper[0x42]=0
		self.oper[0x43]=0
		self.oper[0x44]=21
		self.oper[0x45]=21
		self.oper[0x46]=21
		self.oper[0x47]=21
		self.oper[0x48]=21
		self.oper[0x49]=21
		self.oper[0x4A]=21
		self.oper[0x4B]=21
		self.oper[0x4C]=21
		self.oper[0x4D]=21
		self.oper[0x4E]=21
		self.oper[0x4F]=21

		self.oper[0x50]=21
		self.oper[0x51]=21
		self.oper[0x52]=22
		self.oper[0x53]=22
		self.oper[0x54]=22
		self.oper[0x55]=22
		self.oper[0x56]=22
		self.oper[0x57]=22
		self.oper[0x58]=22
		self.oper[0x59]=22
		self.oper[0x5A]=22
		self.oper[0x5B]=22
		self.oper[0x5C]=22
		self.oper[0x5D]=22
		self.oper[0x5E]=22
		self.oper[0x5F]=22

		self.oper[0x60]=23
		self.oper[0x61]=23
		self.oper[0x62]=23
		self.oper[0x63]=23
		self.oper[0x64]=23
		self.oper[0x65]=23
		self.oper[0x66]=23
		self.oper[0x67]=23
		self.oper[0x68]=23
		self.oper[0x69]=23
		self.oper[0x6A]=23
		self.oper[0x6B]=23
		self.oper[0x6C]=23
		self.oper[0x6D]=23
		self.oper[0x6E]=24
		self.oper[0x6F]=24
		
		#0  NO operator
		#1  VA 4 bits, VB 4 bits
		#2  VA 8 bits, VB 16 bits
		#3  VA 16 bits, VB 16 bits
		#4  VA 8 bits
		#5  VA 4 bits, signed int 4 bits
		#6  VA 8 bits, signed int 16 bits
		#7  VA 8 bits, signed int 32 bits
		#8  VA 8 bits, signed int 64 bits
		#9  VA 8 bits, string index 16 bits
		#10 VA 8 bits, string index 32 bits
		#11 VA 8 bits, type index 16 bits
		#12 VA 4 bits, VB 4 bits, type index 16 bits
		#13 FILLED NEW ARRAY -> TO IMPLEMENTS
		#14 signed brach 8 bits
		#15 signed brach 16 bits
		#16 signed brach 32 bits
		#17 VA 8 bits, VB 32 bits
		#18 VA 8 bits, VB 8 bits, VC 8 bits
		#19 VA 4 bits, VB 4 bits, signed branch 16 bits
		#20 VA 8 bits, signed branch 16 bits
		#21 VA 8 bits, VB 8 bits, VC 8 bits
		#22 VA 4 bits, VB 4 bits, field index 16 bits
		#23 VA 8 bits, field index 16 bits
		#24 VA 4 bits, VB 16 bits, VC VD VE 4 bits each -> INVOKE
		
		self.oper[0x70]=24
		self.oper[0x71]=24
		self.oper[0x72]=24
		self.oper[0x73]=24
		self.oper[0x74]="invoke-virtual/range"
		self.oper[0x75]="invoke-super/range"
		self.oper[0x76]="invoke-direct/range"
		self.oper[0x77]="invoke-static/range"
		self.oper[0x78]="invoke-interface-range"
		self.oper[0x79]=0
		self.oper[0x7A]=0
		self.oper[0x7B]="neg-int"
		self.oper[0x7C]="not-int"
		self.oper[0x7D]="neg-long"
		self.oper[0x7E]="not-long"
		self.oper[0x7F]="neg-float"

		self.oper[0x80]="neg-double"
		self.oper[0x81]="int-to-long"
		self.oper[0x82]="int-to-float"
		self.oper[0x83]="int-to-double"
		self.oper[0x84]="long-to-int"
		self.oper[0x85]="long-to-float"
		self.oper[0x86]="long-to-double"
		self.oper[0x87]="float-to-int"
		self.oper[0x88]="float-to-long"
		self.oper[0x89]="float-to-double"
		self.oper[0x8A]="double-to-int"
		self.oper[0x8B]="double-to-long"
		self.oper[0x8C]="double-to-float"
		self.oper[0x8D]="int-to-byte"
		self.oper[0x8E]="int-to-char"
		self.oper[0x8F]="int-to-short"

		self.oper[0x90]="add-int"
		self.oper[0x91]="sub-int"
		self.oper[0x92]="mul-int"
		self.oper[0x93]="div-int"
		self.oper[0x94]="rem-int"
		self.oper[0x95]="add-int"
		self.oper[0x96]="or-int"
		self.oper[0x97]="xor-int"
		self.oper[0x98]="shl-int"
		self.oper[0x99]="shr-int"
		self.oper[0x9A]="ushr-int"
		self.oper[0x9B]="add-long"
		self.oper[0x9C]="sub-long"
		self.oper[0x9D]="mul-long"
		self.oper[0x9E]="div-long"
		self.oper[0x9F]="rem-long"
		
		self.oper[0xA0]="and-long"
		self.oper[0xA1]="or-long"
		self.oper[0xA2]="xor-long"
		self.oper[0xA3]="shl-long"
		self.oper[0xA4]="shr-long"
		self.oper[0xA5]="ushr-long"
		self.oper[0xA6]="add-float"
		self.oper[0xA7]="sub-float"
		self.oper[0xA8]="mul-float"
		self.oper[0xA9]="div-float"
		self.oper[0xAA]="rem-float"
		self.oper[0xAB]="add-double"
		self.oper[0xAC]="sub-double"
		self.oper[0xAD]="mul-double"
		self.oper[0xAE]="div-double"
		self.oper[0xAF]="rem-double"

		self.oper[0xB0]="add-int/2addr"
		self.oper[0xB1]="sub-int/2addr"
		self.oper[0xB2]="mul-int/2addr"
		self.oper[0xB3]="div-int/2addr"
		self.oper[0xB4]="rem-int/2addr"
		self.oper[0xB5]="add-int/2addr"
		self.oper[0xB6]="or-int/2addr"
		self.oper[0xB7]="xor-int/2addr"
		self.oper[0xB8]="shl-int/2addr"
		self.oper[0xB9]="shr-int/2addr"
		self.oper[0xBA]="ushr-int/2addr"
		self.oper[0xBB]="add-long/2addr"
		self.oper[0xBC]="sub-long/2addr"
		self.oper[0xBD]="mul-long/2addr"
		self.oper[0xBE]="div-long/2addr"
		self.oper[0xBF]="rem-long/2addr"

		self.oper[0xC0]="and-long/2addr"
		self.oper[0xC1]="or-long/2addr"
		self.oper[0xC2]="xor-long/2addr"
		self.oper[0xC3]="shl-long/2addr"
		self.oper[0xC4]="shr-long/2addr"
		self.oper[0xC5]="ushr-long/2addr"
		self.oper[0xC6]="add-float/2addr"
		self.oper[0xC7]="sub-float/2addr"
		self.oper[0xC8]="mul-float/2addr"
		self.oper[0xC9]="div-float/2addr"
		self.oper[0xCA]="rem-float/2addr"
		self.oper[0xCB]="add-double/2addr"
		self.oper[0xCC]="sub-double/2addr"
		self.oper[0xCD]="mul-double/2addr"
		self.oper[0xCE]="div-double/2addr"
		self.oper[0xCF]="rem-double/2addr"
 
		self.oper[0xD0]="add-int/lit16"
		self.oper[0xD1]="sub-int/lit16"
		self.oper[0xD2]="mul-int/lit16"
		self.oper[0xD3]="div-int/lit16"
		self.oper[0xD4]="rem-int/lit16"
		self.oper[0xD5]="and-int/lit16"
		self.oper[0xD6]="or-int/lit16"
		self.oper[0xD7]="xor-int/lit16"
		self.oper[0xD8]="add-int/lit8"
		self.oper[0xD9]="sub-int/lit8"
		self.oper[0xDA]="mul-int/lit8"
		self.oper[0xDB]="div-int/lit8"
		self.oper[0xDC]="rem-int/lit8"
		self.oper[0xDD]="and-int/lit8"
		self.oper[0xDE]="or-int/lit8"
		self.oper[0xDF]="xor-int/lit8"

		self.oper[0xE0]="shl-int/lit8"
		self.oper[0xE1]="shr-int/lit8"
		self.oper[0xE2]="ushr-int/lit8"
		self.oper[0xE3]=0
		self.oper[0xE4]=0
		self.oper[0xE5]=0
		self.oper[0xE6]=0
		self.oper[0xE7]=0
		self.oper[0xE8]=0
		self.oper[0xE9]=0
		self.oper[0xEA]=0
		self.oper[0xEB]=0
		self.oper[0xEC]=0
		self.oper[0xED]=0
		self.oper[0xEE]="execute-inline"
		self.oper[0xEF]=0

		self.oper[0xF0]="invoke-direct-empty"
		self.oper[0xF1]=0
		self.oper[0xF2]="iget-quick"
		self.oper[0xF3]="iget-wide-quick"
		self.oper[0xF4]="iget-object-quick"
		self.oper[0xF5]="iput-quick"
		self.oper[0xF6]="iput-wide-quick"
		self.oper[0xF7]="iput-object-quick "
		self.oper[0xF8]="invoke-virtual-quick"
		self.oper[0xF9]="invoke-virtual-quick/range"
		self.oper[0xFA]="invoke-super-quick"
		self.oper[0xFB]="invoke-super-quick/range"
		self.oper[0xFC]=0
		self.oper[0xFD]=0
		self.oper[0xFE]=0
		self.oper[0xFF]=0