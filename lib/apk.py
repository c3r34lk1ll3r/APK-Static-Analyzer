import zipfile

class BytetoFile:
	def __init__(self,byte):
		self.b=byte
		self.start=0
	def read(self,qty):
		byte=self.b[self.start:self.start+qty]
		self.start+=qty
		return byte
	def seek(self,qty):
		self.start=qty
	def tell(self):
		return self.start
#READ APK
class APK:
	def __init__(self,name):
		self.name=name
		#CHECK if it is a APK
		self.zip=zipfile.ZipFile(self.name)
		
	def FileList(self):
		if hasattr(self,'zip') == False:
			self.zip=zipfile.ZipFile(self.name)
		return self.zip.namelist()
	def Dex(self):
		if hasattr(self,'zip') == False:
			self.zip=zipfile.ZipFile(self.name)
		a=self.zip.namelist()
		returned=[]
		for s in self.zip.namelist():
			if "classes" in s:
				z=self.zip.read(s)
				bt=BytetoFile(z)
				returned.append(bt)
		return returned
	def OpenFile(self,name):
		return self.zip.read(name)

		
		