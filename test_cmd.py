import cmd

class HelloWorld(cmd.Cmd):
    def do_greet(self, line):
        print ("hello")

    def do_EOF(self, line):
        print ("Cacca")
    def do_ahead(self,line):
        Hello2().cmdloop()

class Hello2(cmd.Cmd):
    def do_second(self,line):
        print("Secondo")
    def do_th(self,line):
        print("Ciao ciao")
    def do_undo(self,line):
        return
if __name__ == '__main__':
    HelloWorld().cmdloop()
