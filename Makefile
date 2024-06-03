JFLAGS = -g
JC = javac
.SUFFIXES: .java .class
.java.class:
	$(JC) $(JFLAGS) $*.java

CLASSES = \
	CSProject/Server/Server.java \
	CSProject/Client/Client.java \

default: classes

classes: $(CLASSES:.java=.class)

clean:
	$(RM) CSProject/Server/*.class
	$(RM) CSProject/Client/*.class
	$(RM) balance.txt
	$(RM) private_key.key
	$(RM) public_key.pub
	$(RM) passwd.txt

