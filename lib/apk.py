import zipfile
#READ APK
class APK:
	def __init__(self,name):
		self.name=name
	def ZipExtract(self):
		#Check if it is a APK
		self.zip=zipfile.ZipFile(self.name)
	def FileList(self):
		if hasattr(self,'zip') == False:
			self.zip=zipfile.ZipFile(self.name)
		return self.zip.namelist()
	def ClassDex(self):
		if hasattr(self,'zip') == False:
			self.zip=zipfile.ZipFile(self.name)
		a=self.zip.namelist()
		returned=[]
		for s in self.zip.namelist():
			if "classes" in s:
				returned.append(self.zip.open(s,'r'))
		return returned
	def OpenFile(self,name):
		return self.zip.read(name)