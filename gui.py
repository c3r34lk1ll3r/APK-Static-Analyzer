from lib.apk import APK
from lib.decompiler import DexFile
import sys
from PyQt4 import QtGui, QtCore # importiamo i moduli necessari

import window
import list

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

class ListWindow(QtGui.QMainWindow, list.Ui_MainWindow):

	def __init__(self,model):
		super(self.__class__, self).__init__()
		self.setupUi(self)
		self.connect(self.actionClose, QtCore.SIGNAL('triggered()'), QtCore.SLOT('close()'))
		
		self.listView.setModel(model)
		
class MainWindow(QtGui.QMainWindow, window.Ui_MainWindow):

	def __init__(self):
		super(self.__class__, self).__init__()
		self.setupUi(self)		
		self.statusbar.showMessage("Ready...")
		#FILE
		self.connect(self.actionOpen, QtCore.SIGNAL('triggered()'), self.selectFile)
		self.connect(self.actionQuit, QtCore.SIGNAL('triggered()'), QtCore.SLOT('close()'))
		#EDIT
		self.connect(self.actionShow_Strings, QtCore.SIGNAL('triggered()'), self.viewString)
		self.connect(self.actionShow_Type, QtCore.SIGNAL('triggered()'), self.viewType)
		self.connect(self.actionShow_Header, QtCore.SIGNAL('triggered()'), self.viewString)
		self.connect(self.actionShow_Prototype, QtCore.SIGNAL('triggered()'), self.viewString)
		self.connect(self.actionShow_Method, QtCore.SIGNAL('triggered()'), self.viewString)
		
		self.fileModel=QtGui.QStandardItemModel()
		self.fileView.setModel(self.fileModel)
		item= QtGui.QStandardItem("File")
		self.fileModel.setHorizontalHeaderItem(0,item)
		self.fileView.doubleClicked.connect(self.fileModel_clicked)
		
		self.classModel=QtGui.QStandardItemModel()
		self.classView.setModel(self.classModel)
		item= QtGui.QStandardItem("Classes")
		self.classModel.setHorizontalHeaderItem(0,item)
		self.classView.doubleClicked.connect(self.class_clicked)
		
		self.view=[]
		
		self.tabt=[]
		
		self.textBrowser=[]
		
	def addTextBrowserTab(self,name):
		self.tabt.append(QtGui.QWidget())
		self.tabt[-1].setObjectName("tab_"+name)
		self.textBrowser.append(QtGui.QTextEdit(self.tabt[-1]))
		self.textBrowser[-1].setGeometry(QtCore.QRect(0, 0, 671, 771))
		self.textBrowser[-1].setObjectName("text"+name)
		self.tabWidget.addTab(self.tabt[-1], name)
		
	def viewString(self):
		x=self.dx.getStringList()
		#Create model for String
		model=QtGui.QStandardItemModel()
		for i in x:
			item=QtGui.QStandardItem(i)
			model.appendRow(item)
		self.view.append(ListWindow(model))
		self.view[-1].show()
	
	def viewType(self):
		x=self.dx.getTypeList()
		#Create model for String
		model=QtGui.QStandardItemModel()
		for i in x:
			item=QtGui.QStandardItem(i)
			model.appendRow(item)
		self.view.append(ListWindow(model))
		self.view[-1].show()
		
	def class_clicked(self):
		item = self.classView.selectedIndexes()[0]
		item=self.classModel.itemFromIndex(item)
		class_name=str(item.text())
		item=item.parent()
		while item != None:
			class_name=str(item.text())+"/"+class_name
			item=item.parent()
		print class_name
		print self.clx[class_name]
		sx=self.dx.printClass(self.clx[class_name])
		self.addTextBrowserTab(class_name)
		br=self.textBrowser[-1]
		for l in sx:
			br.insertPlainText(l)
			#self.textBrowser[-1].setHtml(l)
		
		
	def fileModel_clicked(self):
		item = self.fileView.selectedIndexes()[0]
		x=self.fileModel.itemFromIndex(item)
		#Now open file x
		file=self.apk.OpenFile(str(x.text()))
		MagicNumber=file[:4]
		print MagicNumber[:3]
		print MagicNumber[3]
		if MagicNumber[:3]=="dex":
			bt=BytetoFile(file)
			self.OpenDex(bt)

	def OpenDex(self,file):
		self.dx=DexFile()
		self.dx.ReadDex(file)
		self.clx=self.dx.getClassesName()
		self.classModel.clear()
		self.addClass(self.classModel,self.clx)
		self.classView.setEnabled(True)
		self.actionShow_Strings.setEnabled(True)
		self.actionShow_Type.setEnabled(True)
		#self.actionShow_Header.setEnabled(True)
		#self.actionShow_Prototype.setEnabled(True)
		#self.actionShow_Method.setEnabled(True)
		
	def selectFile(self):
		self.apkpath=QtGui.QFileDialog.getOpenFileName()
		self.statusbar.showMessage("Apk selected:\t"+self.apkpath)
		self.apk=APK(str(self.apkpath))
		filelist=self.apk.FileList()
		self.fileModel.clear()
		self.addItem(self.fileModel,filelist,"File")
		self.fileView.setEnabled(True)
		
	def addClass(self,model,elements):
		mod=[]
		for key in elements:
			mod.append(key)
		self.addItem(model,mod,"Classes")

	def addItem(self,model,elements,string):
		item= QtGui.QStandardItem(string)
		model.setHorizontalHeaderItem(0,item)
		for el in elements:
			rt=el.split('/')
			#print el
			index=0
			row=model
			while index < len(rt):
				#check if it already exist
				i=model.findItems(rt[index],QtCore.Qt.MatchRecursive)
				if len(i) == 0:
					item=QtGui.QStandardItem(rt[index])
					row.appendRow(item)
					row=item
				elif len(i)>1:
					print "Something really strange appers here"
				else:
					row=i[0]
				index+=1
				
		
		
		
		
def main():
    app = QtGui.QApplication(sys.argv)  # A new instance of QApplication
    form = MainWindow()                 # We set the form to be our MainWindow (design)
    form.show()                         # Show the form
    app.exec_()  	                    # and execute the app


if __name__ == '__main__':              # if we're running file directly and not importing it
    main()                              # run the main functio		
