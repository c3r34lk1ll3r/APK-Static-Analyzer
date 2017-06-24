'''
#Utility -> NOT WORKING
def printClassGui(self,indx):
    self.readClass(indx)
    cl=self.ClassDEF[indx]
    returned=[]
    #Header
    returned.append("Class name:\t"+self.__String[self.TypeIDS[indx]].string_data_data+"\n")
    #Access flag
    index=1
    flg=cl.access_flags
    while flg!=0:
        if flg % 2 == 1:
            returned.append("Access flag:\t"+cl.access_flagd[index]+"\n")
        index+=1
        flg=flg >> 1

    #Check NO_INDEX BEFORE
    returned.append("Superclass:\t"+self.__String[self.TypeIDS[cl.superclass_idx]].string_data_data+"\n")
    returned.append("Interface:\t"+"\n")
    #CHECK NO_INDEX before
    returned.append("Source file:\t"+self.__String[cl.source_file_idx].string_data_data+"\n")
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
        tipo=self.__String[self.TypeIDS[field.type_idx]].string_data_data
        name=self.__String[field.name_idx].string_data_data
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
        tipo=self.__String[self.TypeIDS[field.type_idx]].string_data_data
        name=self.__String[field.name_idx].string_data_data
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
        returned.append(self.__String[meth.name_idx].string_data_data+" ")
        ret=self.TypeIDS[prot.return_type_idx]
        returned.append("(")
        if prot.parameters_off != 0:
            pp=self.getListfromIndex(prot.parameters_off)
            for item in pp:
                returned.append(self.__String[self.TypeIDS[item]].string_data_data)
                if item != pp[-1]:
                    returned.append(",")
        else:
            returned.append("void")
        returned.append(")->")
        returned.append(self.__String[ret].string_data_data)
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
        returned.append(self.__String[meth.name_idx].string_data_data+" ")
        ret=self.TypeIDS[prot.return_type_idx]
        returned.append("(")
        if prot.parameters_off != 0:
            pp=self.getListfromIndex(prot.parameters_off)
            for item in pp:
                returned.append(self.__String[self.TypeIDS[item]].string_data_data)
                if item != pp[-1]:
                    returned.append(",")
        else:
            returned.append("void")
        returned.append(")->")
        returned.append(self.__String[ret].string_data_data)
        returned.append("\n")
        #Insert Code!
        if k.code_off!=0:
            cod=(self.getCode(k.code_off))
            returned.append(self.PrintCodeClass(cod))
        returned.append("\n\n\n")
        pr=k.method_idx_diff+pr
        index+=1
    return returned



    def getMethodList(self,st=None):
		returned={}
		indx=0
		if st==None:
			while indx<len(self.MethodIDS):
				meth=self.MethodIDS[indx]
				returned[self.__String[meth.name_idx].string_data_data]=indx
				indx+=1
		else:
			if type(st) is list:
				for ss in st:
					if type(ss) is int:
						meth=self.MethodIDS[ss]
						returned[self.__String[meth.name_idx].string_data_data]=ss
					elif type(ss) is str:
						indx=0
						while indx<len(self.MethodIDS):
							meth=self.MethodIDS[indx]
							name=self.__String[meth.name_idx].string_data_data
							if ss.lower() in name.lower():
								returned[name]=indx
							indx+=1
			elif type(st) is int:
				meth=self.MethodIDS[ss]
				returned[self.__String[meth.name_idx].string_data_data]=ss
			elif type(st) is str:
				indx=0
				while indx<len(self.MethodIDS):
					meth=self.MethodIDS[indx]
					name=self.__String[meth.name_idx].string_data_data
					if st.lower() in name.lower():
						returned[name]=indx
					indx+=1
		return returned



        def getStringList(self,st=None):
    		#CHECK INDEX RANGE
    		returned={}
    		indx=0
    		if st==None:
    			while indx < len(self.__String):
    				returned[self.__String[indx].string_data_data]=indx
    				indx+=1
    		else:
    			if type(st) is list:
    				for ss in st:
    					indx=0
    					if type(ss) is int:
    						returned[self.__String[ss].string_data_data]=ss
    					elif type(ss) is str:
    						while indx < len(self.TypeIDS):
    							strin=self.__String[indx].string_data_data
    							if ss in strin:
    								returned[self.__String[indx].string_data_data]=indx
    			else:
    				if type(st) is int:
    					returned[self.__String[st].string_data_data]=st
    				elif type(st) is str:
    					while indx < len(self.TypeIDS):
    						strin=self.__String[indx].string_data_data
    						if st in strin:
    							returned[self.__String[indx].string_data_data]=indx
    						indx+=1
    		return returned

        	def getClassesList(self,st=None):
        		#CHECK INDEX
        		returned={}
        		if st==None:
        			for i in self.__ClassDEF:
        				returned[self.__String[self.TypeIDS[i]].string_data_data]=i
        		else:
        			if type(st) is list:
        				for ss in st:
        					indx=0
        					if type(ss) is str:
        						for i in self.__ClassDEF:
        							strin=self.__String[self.TypeIDS[i]].string_data_data
        							if ss in strin:
        								returned[strin]=i
        					elif type(ss) is int:
        						returned[self.__String[self.TypeIDS[ss]].string_data_data]=ss
        			else:
        				if type(st) is str:
        					for i in self.__ClassDEF:
            						strin=self.__String[self.TypeIDS[i]].string_data_data
        						if st in strin:
        							returned[strin]=i
        				elif type(st) is int:
        					returned[self.__String[self.TypeIDS[st]].string_data_data]=st
        		return returned



    			Now i have all the index -> Can start the search.
    			I should search the string in:
    			1. Method Name
    			2. Field Name
    			3. Type Name
    			4. Inside the code

    			#1.Method name
    			#GREEN = '\033[92m'
    			#BLUE = '\033[94m'
    			#CYAN = '\033[96m'
    			#Yellow = '\033[93m'
    			print (bcolors.GREEN+"---- Method ----")
    			print ("")
    			for m in self.__MethodIDS:
    				if m.name_idx == i:
    					print (self.__String[self.__TypeIDS[m.class_idx]].string_data_data+"->"+self.__String[i].string_data_data)
    			print ("")
    			print (bcolors.BLUE+"---- Field ----")
    			print ("")
    			for m in self.__FieldIDS:
    				if m.name_idx == i:
    					print (self.__String[self.__TypeIDS[m.class_idx]].string_data_data+":"+self.__String[i].string_data_data)
    			print ("")
    			print (bcolors.CYAN+"---- Type ----")
    			print ("")
    			for m in self.__TypeIDS:
    				if m == i:
    					print (self.__String[m].string_data_data)
    			print ("")
    			print (bcolors.Yellow+"---- Inside Code ----")
    			print ("")
    			#More complex
    			self.xreffrom("String",i)
    			print ("")
    			'''




                		'''
                		for i in indici:
                			tp=self.__String[self.__TypeIDS[i]].string_data_data
                			returned[tp]=i

                			Now i have all the index -> Can start the search.
                			I should search the string in:
                			1. Method Parameters
                			2. Field Name
                			4. Inside the code

                			#1.Method name
                			#GREEN = '\033[92m'
                			#BLUE = '\033[94m'
                			#Yellow = '\033[93m'
                			print (bcolors.GREEN+"---- Method parameters ----")
                			print ("")
                			for m in self.__MethodIDS:
                				proto=self.__ProtoIDS[m.proto_idx]
                				if proto.return_type_idx == i or i in proto.parameters:
                					line="("
                					if len(proto.parameters) == 0:
                						line+="void"
                					else:
                						for j in proto.parameters:
                							line+=self.__String[self.__TypeIDS[j]].string_data_data+", "
                					line+=")"+self.__String[self.__TypeIDS[proto.return_type_idx]].string_data_data
                					print (self.__String[self.__TypeIDS[m.class_idx]].string_data_data+"->"+self.__String[m.name_idx].string_data_data+line)
                			print ("")
                			print (bcolors.BLUE+"---- Field ----")
                			print ("")
                			for m in self.__FieldIDS:
                				if m.type_idx == i:
                					print (self.__String[self.__TypeIDS[m.class_idx]].string_data_data+":"+self.__String[m.name_idx].string_data_data)
                			print ("")
                			print (bcolors.Yellow+"---- Inside Code ----")
                			print ("")
                			#More complex
                			self.xreffrom("Type",i)
                			print ("")
                		return returned
                '''


                	'''
        			returned[tp]=i
        			Now i have all the index -> Can start the search.
        			I should search the string in:
        			1. Field Name
        			2. Inside the code

        			#1.Method name
        			#BLUE = '\033[94m'
        			#Yellow = '\033[93m'
        			print (bcolors.BLUE+"---- Field ----")
        			print ("")
        			fie=self.__FieldIDS[i]
        			print (self.__String[self.__TypeIDS[fie.class_idx]].string_data_data+":"+self.__String[fie.name_idx].string_data_data+" "+self.__String[self.__TypeIDS[fie.type_idx]].string_data_data)
        			print ("")
        			print (bcolors.Yellow+"---- Inside Code ----")
        			print ("")
        			#More complex
        			self.xreffrom("Field",i)
        			print ("")
        		return returned
        		pass

                	def getTypeList(self,st=None):
                		#CHECK THE INDEX RANGE
                		returned=[]
                		indx=0
                		if st==None:
                			while indx < len(self.__TypeIDS):
                				strin=self.__String[self.__TypeIDS[indx]].string_data_data
                				returned.append(str(indx)+": "+strin)
                				indx+=1
                		else:
                			if type(st) is list:
                				for ss in st:
                					indx=0
                					if type(ss) is int:
                						returned.append(str(ss)+": "+self.__String[self.__TypeIDS[ss]].string_data_data)
                					elif type(ss) is str:
                						while indx < len(self.__TypeIDS):
                							strin=self.__String[self.__TypeIDS[indx]].string_data_data
                							if st in strin:
                								returned.append(str(indx)+": "+strin)
                			else:
                				if type(st) is int:
                					returned.append(str(st)+": "+(self.__String[self.__TypeIDS[st]].string_data_data))
                				elif type(st) is str:
                					while indx < len(self.__TypeIDS):
                						strin=self.__String[self.__TypeIDS[indx]].string_data_data
                						if st in strin:
                							returned.append(str(indx)+": "+strin)
                						indx+=1
                		return returned

'''
