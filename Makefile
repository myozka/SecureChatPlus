##############################################################################
# 
# Makefile for programming project
#
##############################################################################

target: chat

JAVA            = java
JAVAC           = javac

JAVASRCS        = \
			Chat/ChatClient.java \
			Chat/ChatServer.java \
			Chat/ChatClientThread.java \
			Chat/ChatServerThread.java \
			Chat/ClientRecord.java \
			Chat/ChatLoginPanel.java \
			Chat/ChatRoomPanel.java \
			Chat/CertificateAuthority.java \
			Chat/CertificateAuthorityActivityPanel.java \
			Chat/CertificateAuthorityThread.java \
			Chat/CertRequest.java \
			Chat/MessageBlock.java \
			Chat/Tools.java \
			Chat/X509CertificateGenerator.java \

JAVAOBJS        = $(JAVASRCS:.java=.class)

.SUFFIXES:	.class .java

.java.class: $*.java
	    $(JAVAC) $(JAVACFLAGS) $*.java;

clean:
	    rm -f Chat/*\$*.class Chat/*.class

chat:    $(JAVAOBJS)
