#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <iterator>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <pthread.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef unsigned char BYTE;
typedef unsigned int DWORD;
typedef unsigned short WORD;

#define REGISTER    0X00000001
#define LOGIN       0X00000002
#define LOGOUT      0X00000004
#define SEND        0X00000008
#define SEND2       0X00000010
#define SENDA       0X00000020
#define SENDA2      0X00000040
#define SENDF       0X00000080
#define SENDF2      0X00000100
#define LIST        0X00000200
#define DELAY       0X00000400
#define INIT        0X00000800
#define ADDGROUP    0X00001000
#define RMGROUP     0X00002000
#define JOINGROUP   0X00004000
#define LEAVEGROUP  0X00008000
#define SENDGROUP   0X00010000

#define OK                          0X80000001
#define FAIL                        0X80000002
#define INVALID_ONLINE_ID           0X80000004
#define NOT_LOGGED_IN               0X80000008
#define ACCOUNT_INCORRECT           0X80000010
#define CANNOT_WRITE_FILE           0X80000020
#define FILE_TRANSMISSION_FAILED    0X80000040
#define FILE_NOT_FOUND              0X80000080
#define GROUP_NOT_FOUND             0X80000100
#define USER_NOT_IN_GROUP           0X80000200

#define MAX_SCRIPT_COMMANDS 10000
#define MAX_NUM_THREADS 8
#define MAX_NAME_SIZE 8
#define MAX_MSG_SIZE 256
#define FILE_BUFFER_SIZE 512
#define MAX_GROUPS 10

struct scriptCmd
{
    int op;
    std::string fd1;
    std::string fd2;
};
struct pkt
{
    int op;
    int onlineID;
    char targetName[MAX_NAME_SIZE];
    char msg[MAX_MSG_SIZE]; //for message and password
};

int cmdLineCnt;
const char * svrIP;
int svrPort;
scriptCmd * scriptCmds = new scriptCmd[MAX_SCRIPT_COMMANDS];
int onlineID;
int isLogIn; // 0-before login   1-after login   2-after logout

void Error(const char * format, ...) {
	char msg[4096];
	va_list argptr;
	va_start(argptr, format);
	vsprintf(msg, format, argptr);
	va_end(argptr);
	fprintf(stderr, "Error: %s\n", msg);
	exit(-1);
}

void Log(const char * format, ...) {
	char msg[2048];
	va_list argptr;
	va_start(argptr, format);
	vsprintf(msg, format, argptr);
	va_end(argptr);
	fprintf(stderr, "%s\n", msg);
}

void split(const std::string& s, std::vector<std::string>& tokens, const std::string& delimiters)
{
   std::string::size_type lastPos = s.find_first_not_of(delimiters, 0);
   std::string::size_type pos = s.find_first_of(delimiters, lastPos);
   while (std::string::npos != pos || std::string::npos != lastPos)
   {
      tokens.push_back(s.substr(lastPos, pos - lastPos));
      lastPos = s.find_first_not_of(delimiters, pos);
      pos = s.find_first_of(delimiters, lastPos);
   }
}

void readScript(const char * scriptRL) {
    std::ifstream scriptFile(scriptRL);
    if (!scriptFile.good())
    {
        Error("Invalid script file--%s", scriptRL);
    }

    std::string scriptLine;
    std::vector<std::string> scriptLineComps;
    
    while (std::getline(scriptFile, scriptLine))
    {
        if (cmdLineCnt > MAX_SCRIPT_COMMANDS)
        {
            Error("Script commands exceeds limit.");
        }
        
        split(scriptLine, scriptLineComps, " ");

        if (scriptLineComps.size() <= 0)
        {
            Error("Invalid script command.");
        }

        if (scriptLineComps[0] == "REGISTER")
        {
            if (scriptLineComps.size() != 3)
            {
                Error("Invalid REGISTER arguments on line %d of the script.", cmdLineCnt + 1);
            }
            scriptCmds[cmdLineCnt].op = REGISTER;
            scriptCmds[cmdLineCnt].fd1 = scriptLineComps[1];
            scriptCmds[cmdLineCnt].fd2 = scriptLineComps[2];
        }
        else if (scriptLineComps[0] == "LOGIN")
        {
            if (scriptLineComps.size() != 3)
            {
                Error("Invalid LOGIN arguments on line %d of the script.", cmdLineCnt + 1);
            }
            scriptCmds[cmdLineCnt].op = LOGIN;
            scriptCmds[cmdLineCnt].fd1 = scriptLineComps[1];
            scriptCmds[cmdLineCnt].fd2 = scriptLineComps[2];
        }
        else if (scriptLineComps[0] == "LOGOUT")
        {
            if (scriptLineComps.size() != 1)
            {
                Error("Invalid LOGOUT command on line %d of the script.", cmdLineCnt + 1);
            }
            scriptCmds[cmdLineCnt].op = LOGOUT;
            Log("LOGOUT Command detected, all following commands inscript will not be evaluated");
            break;
        }
        else if (scriptLineComps[0] == "SEND")
        {
            if (scriptLineComps.size() <= 1)
            {
                Error("Too few SEND arguments on line %d of the script.", cmdLineCnt + 1);
            }
            scriptCmds[cmdLineCnt].op = SEND;
            scriptCmds[cmdLineCnt].fd1 = scriptLine.substr(5);
        }
        else if (scriptLineComps[0] == "SEND2")
        {
            if (scriptLineComps.size() <= 2)
            {
                Error("Too few SEND2 arguments on line %d of the script.", cmdLineCnt + 1);
            }
            scriptCmds[cmdLineCnt].op = SEND2;
            scriptCmds[cmdLineCnt].fd1 = scriptLineComps[1];
            scriptCmds[cmdLineCnt].fd2 = scriptLine.substr(7 + scriptLineComps[1].length());
        }
        else if (scriptLineComps[0] == "SENDA")
        {
            if (scriptLineComps.size() <= 1)
            {
                Error("Too few SENDA arguments on line %d of the script.", cmdLineCnt + 1);
            }
            scriptCmds[cmdLineCnt].op = SENDA;
            scriptCmds[cmdLineCnt].fd1 = scriptLine.substr(6);
        }
        else if (scriptLineComps[0] == "SENDA2")
        {
            if (scriptLineComps.size() <= 2)
            {
                Error("Too few SENDA2 arguments on line %d of the script.", cmdLineCnt + 1);
            }
            scriptCmds[cmdLineCnt].op = SENDA2;
            scriptCmds[cmdLineCnt].fd1 = scriptLineComps[1];
            scriptCmds[cmdLineCnt].fd2 = scriptLine.substr(8 + scriptLineComps[1].length());
        }
        else if (scriptLineComps[0] == "SENDF")
        {
            if (scriptLineComps.size() <= 1)
            {
                Error("Too few SENDF arguments on line %d of the script.", cmdLineCnt + 1);
            }
            scriptCmds[cmdLineCnt].op = SENDF;
            scriptCmds[cmdLineCnt].fd1 = scriptLine.substr(6);
        }
        else if (scriptLineComps[0] == "SENDF2")
        {
            if (scriptLineComps.size() <= 2)
            {
                Error("Too few SENDF2 arguments on line %d of the script.", cmdLineCnt + 1);
            }
            scriptCmds[cmdLineCnt].op = SENDF2;
            scriptCmds[cmdLineCnt].fd1 = scriptLineComps[1];
            scriptCmds[cmdLineCnt].fd2 = scriptLine.substr(8 + scriptLineComps[1].length());
        }
        else if (scriptLineComps[0] == "LIST")
        {
            if (scriptLineComps.size() != 1)
            {
                Error("Invalid LIST command on line %d of the script.", cmdLineCnt + 1);
            }
            scriptCmds[cmdLineCnt].op = LIST;
        }
        else if (scriptLineComps[0] == "DELAY")
        {
            if (scriptLineComps.size() != 2)
            {
                Error("Invalid DELAY command on line %d of the script.", cmdLineCnt + 1);
            }
            scriptCmds[cmdLineCnt].op = DELAY;
            scriptCmds[cmdLineCnt].fd1 = scriptLineComps[1];
        }
        else if (scriptLineComps[0] == "ADDGROUP")
        {
            if (scriptLineComps.size() <= 1)
            {
                Error("Too few ADDGROUP arguments on line %d of the script.", cmdLineCnt + 1);
            }
            scriptCmds[cmdLineCnt].op = ADDGROUP;
            scriptCmds[cmdLineCnt].fd1 = scriptLine.substr(9);
        }
        else if (scriptLineComps[0] == "RMGROUP")
        {
            if (scriptLineComps.size() <= 1)
            {
                Error("Too few RMGROUP arguments on line %d of the script.", cmdLineCnt + 1);
            }
            scriptCmds[cmdLineCnt].op = RMGROUP;
            scriptCmds[cmdLineCnt].fd1 = scriptLine.substr(8);
        }
        else if (scriptLineComps[0] == "JOINGROUP")
        {
            if (scriptLineComps.size() <= 1)
            {
                Error("Too few JOINGROUP arguments on line %d of the script.", cmdLineCnt + 1);
            }
            scriptCmds[cmdLineCnt].op = JOINGROUP;
            scriptCmds[cmdLineCnt].fd1 = scriptLine.substr(10);
            // Log("kkkkkkkkkkkkkkkk--%d, %s", scriptCmds[cmdLineCnt].op, scriptCmds[cmdLineCnt].fd1.c_str());
        }
        else if (scriptLineComps[0] == "LEAVEGROUP")
        {
            if (scriptLineComps.size() <= 1)
            {
                Error("Too few LEAVEGROUP arguments on line %d of the script.", cmdLineCnt + 1);
            }
            scriptCmds[cmdLineCnt].op = LEAVEGROUP;
            scriptCmds[cmdLineCnt].fd1 = scriptLine.substr(11);
        }
        else if (scriptLineComps[0] == "SENDGROUP")
        {
            if (scriptLineComps.size() <= 2)
            {
                Error("Too few SENDGROUP arguments on line %d of the script.", cmdLineCnt + 1);
            }
            scriptCmds[cmdLineCnt].op = SENDGROUP;
            scriptCmds[cmdLineCnt].fd1 = scriptLineComps[1];
            scriptCmds[cmdLineCnt].fd2 = scriptLine.substr(11 + scriptLineComps[1].length());
        }
        else
        {
            Error("Unknown %s command on line %d of the script.", scriptLineComps[0], cmdLineCnt);
        }
        scriptLineComps.clear();
        cmdLineCnt++;
    }
}

int Send_Blocking(int sockFD, const BYTE * data, int len) {
	int nSent = 0;
	while (nSent < len) {
		int n = send(sockFD, data + nSent, len - nSent, 0);
		if (n >= 0) {
			nSent += n;
		} else if (n < 0 && (errno == ECONNRESET || errno == EPIPE)) {
			Log("Connection closed.");
			close(sockFD);
			return -1;
		} else {
			Error("Unexpected error %d: %s.", errno, strerror(errno));
		}
	}
	return 0;
}

int Recv_Blocking(int sockFD, BYTE * data, int len) {
	int nRecv = 0;
	while (nRecv < len) {
		int n = recv(sockFD, data + nRecv, len - nRecv, 0);
        // Log("%d data received.", n);
        struct pkt * dataPre = (struct pkt *)data;
		if (n > 0) {
			nRecv += n;
		} else if (n == 0 || (n < 0 && errno == ECONNRESET)) {
			Log("Connection closed.");
			close(sockFD);
			return -1;
		} else {
			Error("Unexpected error %d: %s.", errno, strerror(errno));
		}
	}
    // Log("recv finished.");
	return 0;
}

void * pos_thread_func(void * threadArg) {
    int cmdIndex = *((int *)threadArg);

	struct sockaddr_in serverAddr;
	memset(&serverAddr, 0, sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons((unsigned short) svrPort);
	inet_pton(AF_INET, svrIP, &serverAddr.sin_addr);

    int sockFD = socket(AF_INET, SOCK_STREAM, 0);
    if (sockFD == -1) {
        Error("Cannot create socket.");		
    }

    if (connect(sockFD, (const struct sockaddr *) &serverAddr, sizeof(serverAddr)) != 0) {
        Error("Cannot connect to server %s:%d.", svrIP, svrPort);
    }

    struct pkt * buf = (struct pkt *)malloc(sizeof(struct pkt));
    memset(buf, 0, sizeof(struct pkt));
    buf->op = scriptCmds[cmdIndex].op;
    buf->onlineID = onlineID;
    
    if (buf->op == REGISTER || buf->op == LOGIN || buf->op == SEND2 || buf->op == SENDA2 || buf->op == SENDF2 || buf->op == SENDGROUP)
    {
        if (scriptCmds[cmdIndex].fd1.length() > MAX_NAME_SIZE)
        {
            Error("Command no.%d has too long name field.", cmdIndex + 1);
        }
        else if (scriptCmds[cmdIndex].fd2.length() > MAX_MSG_SIZE)
        {
            Error("Command no.%d has too long message or password", cmdIndex + 1);
        }
        else
        {
            strcpy(buf->targetName, scriptCmds[cmdIndex].fd1.c_str());
            strcpy(buf->msg, scriptCmds[cmdIndex].fd2.c_str());
        }   
    }
    else if (buf->op == SEND || buf->op == SENDA || buf->op == SENDF)
    {
        if (scriptCmds[cmdIndex].fd1.length() > MAX_MSG_SIZE)
        {
            Error("Command no.%d has too long message or file name field.", cmdIndex + 1);
        }
        else
        {
            strcpy(buf->msg, scriptCmds[cmdIndex].fd1.c_str());
        }
    }
    else if (buf->op == ADDGROUP || buf->op == RMGROUP || buf->op == JOINGROUP || buf->op == LEAVEGROUP)
    {
        if (scriptCmds[cmdIndex].fd1.length() > MAX_NAME_SIZE)
        {
            Error("Command no.%d has too long group name field.", cmdIndex + 1);
        }
        else
        {
            strcpy(buf->targetName, scriptCmds[cmdIndex].fd1.c_str());
        }
    }
    
    std::cout << "Sending command no." << cmdIndex + 1 << ": op=" << buf->op << ", onlineID=" << buf->onlineID << ", targetName=" << buf->targetName << ", msg=" << buf->msg << "." << std::endl;

    if (Send_Blocking(sockFD, (BYTE *)buf, sizeof(struct pkt)) < 0)
    {
        free(buf);
        free(threadArg);
        return (void *)-1;
    }

    if (buf->op == SENDF || buf->op == SENDF2)
    {
        char fileBuffer[FILE_BUFFER_SIZE];
        bzero(fileBuffer, FILE_BUFFER_SIZE);

        FILE *fp = fopen(buf->msg, "r");
        if (NULL == fp)
        {
            Log("File--%s not found.", buf->msg);

            close(sockFD);
            free(buf);
            free(threadArg);

            return (void *)-1;
        }
        else
        {
            int readLen = 0;

            while ((readLen = fread(fileBuffer, sizeof(char), FILE_BUFFER_SIZE, fp)) > 0)
            {
                if (send(sockFD, fileBuffer, readLen, 0) < 0)
                {
                    Log("Failed to send file--%s to the server.", buf->msg);

                    close(sockFD);
                    free(buf);
                    free(threadArg);
                    fclose(fp);

                    return (void *)-1;
                }
                bzero(fileBuffer, FILE_BUFFER_SIZE);
            }

            // Log("Transmission of file--%s to the server success.", buf->msg);
        }
        fclose(fp);
    }
       
    int confirm = FAIL;
    if (Recv_Blocking(sockFD, (BYTE *)&confirm, 4) < 0)
    {
        free(buf);
        free(threadArg);
        return (void *)-1;
    }
    confirm = ntohl(confirm);

    if (confirm == OK)
    {
        if (buf->op == LOGIN)
        {
            isLogIn = 1;
        }
        else if(buf->op == LOGOUT)
        {
            sleep(3); // a very good substitute for mutex lock
            isLogIn = 2;
            Log("\n||||||||||You have logged out.||||||||||\n");
        }
        
        Log("Command no.%d has been handled by server correctly", cmdIndex + 1);
    }
    else if (buf->op == ADDGROUP || buf->op == RMGROUP || buf->op == JOINGROUP || buf->op == LEAVEGROUP)
    {
        if (confirm != 0)
        {
            Log("Group command no.%d has been handled by server correctly", cmdIndex + 1);
        }
    }
    else
    {
        Log("Command no.%d failed, status code:%d.", cmdIndex + 1, confirm);
    }

    close(sockFD);

    free(buf);
    free(threadArg);

    return (void *)0;
}

void * neg_thread_func(void * threadArg) {

    int fd = *((int *) threadArg);
    struct pkt * buf = (struct pkt *)malloc(sizeof(struct pkt));

    while (1)
    {   
        // Log("Starting loop");
        if (isLogIn == 0)
        {
            continue;
        }
        else if (isLogIn == 2)
        {
            break;
        }
        else
        {
            memset(buf, 0, sizeof(struct pkt));
            // Log("Waiting for pkt.");
            if (Recv_Blocking(fd, (BYTE *)buf, sizeof(struct pkt)) < 0)
            {
                continue;
            }
            
            // std::cout << "Received message: op=" << buf->op << ", targetName=" << buf->targetName << ", msg=" << buf->msg << "." << std::endl;

            if (buf->op == SEND2 || buf->op == SENDA2 || buf->op == SENDF2)
            {
                char from[MAX_NAME_SIZE];
                char flag[MAX_MSG_SIZE];
                char content[MAX_MSG_SIZE];
                strcpy(from, "Anony.");
                strcpy(flag, "");
                strcpy(content, buf->msg);

                if (buf->op != SENDA2)
                {
                    strcpy(from, buf->targetName);
                }
                if (buf->op == SENDF2)
                {
                    strcpy(flag, "FILE-");
                }
                
                Log("\n||||||||||%s sent to you: %s %s||||||||||\n", from, flag, content);
            }
            else if (buf->op == SEND || buf->op == SENDA || buf->op == SENDF)
            {
                char from[MAX_NAME_SIZE];
                char flag[MAX_MSG_SIZE];
                char content[MAX_MSG_SIZE];
                strcpy(from, "Anony.");
                strcpy(flag, "");
                strcpy(content, buf->msg);

                if (buf->op != SENDA)
                {
                    strcpy(from, buf->targetName);
                }
                if (buf->op == SENDF)
                {
                    strcpy(flag, "FILE-");
                }
                
                Log("\n||||||||||%s sent to everyone: %s %s||||||||||\n", from, flag, content);
            }
            else if (buf->op == SENDGROUP)
            {
                char group[MAX_NAME_SIZE];
                char content[MAX_MSG_SIZE];
                strcpy(group, buf->targetName);
                strcpy(content, buf->msg);

                Log("\n||||||||||Someone sent to everyone in group %s: %s||||||||||\n", group, content);
            }
            else
            {
                Log("\n||||||||||Online user List: %s||||||||||\n", buf->msg);
            }

            if (buf->op == SENDF2 || buf->op == SENDF)
            {
                int ready = htonl(1);
                if (Send_Blocking(fd, (BYTE *)&ready, 4) < 0)
                {
                    continue;
                }   

                char fileBuffer[FILE_BUFFER_SIZE];
                bzero(fileBuffer, FILE_BUFFER_SIZE);

                FILE *fp = fopen(buf->msg, "w");
                if (NULL == fp)
                {
                    Log("Can not open file--%s to write.", buf->msg);

                    continue;
                }

                int readLen = 0;
                // Log("Prepare to receive file.");

                struct timeval tv;
                tv.tv_sec = 1;
                tv.tv_usec = 0;
                setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

                while((readLen = recv(fd, fileBuffer, FILE_BUFFER_SIZE, 0)) > 0)
                {
                    // Log("Received %d size.", readLen);
                    if(fwrite(fileBuffer, sizeof(char), readLen, fp) < readLen)
                    {
                        // Log("Write to file--%s failed", buf->msg);
                        fclose(fp);
                        break;
                    }
                    // Log("%d size written.", readLen);
                    bzero(fileBuffer, FILE_BUFFER_SIZE);
                    // Log("File buffer reset.");
                }
                tv.tv_sec = 0;
                tv.tv_usec = 0;
                setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

                // Log("After the file has been received.");
                Log("Transmission of the file--%s from server is over.", buf->msg);
                fclose(fp);

                ready = htonl(3);
                if (Send_Blocking(fd, (BYTE *)&ready, 4) < 0)
                {
                    continue;
                }
            }
        }
    }
    close(fd);
    free(threadArg);
    free(buf);
    
    return (void *)0;
}

void DoClient() {
    int sleepTime;
    pthread_t cmdThreads[MAX_NUM_THREADS];
    pthread_t recvThread;
    int* arg;
    int* neg_arg;
    int threadCnt = 0;

    signal(SIGPIPE, SIG_IGN);

    struct sockaddr_in serverAddr;
	memset(&serverAddr, 0, sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons((unsigned short) svrPort);
	inet_pton(AF_INET, svrIP, &serverAddr.sin_addr);

    int sockFD = socket(AF_INET, SOCK_STREAM, 0);
    if (sockFD == -1) {
        Error("Cannot create socket.");		
    }

    if (connect(sockFD, (const struct sockaddr *) &serverAddr, sizeof(serverAddr)) != 0) {
        Error("Cannot connect to server %s:%d.", svrIP, svrPort);
    }

    struct pkt * buf = (struct pkt *)malloc(sizeof(struct pkt));
    memset(buf, 0, sizeof(struct pkt));	
    buf->op = INIT;

    if (Send_Blocking(sockFD, (BYTE *)buf, sizeof(struct pkt)) < 0)
    {
        return;
    }

    if (Recv_Blocking(sockFD, (BYTE *)&onlineID, 4) < 0)
    {
        return;
    }
    
    onlineID = ntohl(onlineID);

    if (onlineID == 0)
    {
        Error("Chatroom is full. Try another time.");
    }
    
    
    Log("\n||||||||||Get online in server: ID=%d.||||||||||\n", onlineID);

    free(buf);

    // Log("Before setting argument");
    neg_arg = (int *)malloc(sizeof(int));
    *neg_arg = sockFD;
    // Log("After setting argument");

    pthread_create(&recvThread, NULL, neg_thread_func, (void *)neg_arg);

    for (int i = 0; i < cmdLineCnt; i++)
    {
        // std::cout << "Found command no." << i + 1 << ": op=" << scriptCmds[i].op << ", fd1=" << scriptCmds[i].fd1 << ", fd2=" << scriptCmds[i].fd2 << "." << std::endl;

        if (scriptCmds[i].op == DELAY)
        {
            sleepTime = atoi(scriptCmds[i].fd1.c_str());
            sleep(sleepTime);
        }
        else
        {
            arg = (int *)malloc(sizeof(int));
            *arg = i;

            if (threadCnt > MAX_NUM_THREADS)
            {
                Error("Number of threads exceeds limit.");
            }
            pthread_create(&cmdThreads[threadCnt], NULL, pos_thread_func, (void *)arg);
            
            threadCnt++;
        }
    }

    for (int i = 0; i < threadCnt; i++)
    {
        pthread_join(cmdThreads[i], NULL);
    }

    pthread_join(recvThread, NULL);
}

int main(int argc, char const *argv[])
{
    cmdLineCnt = 0;
    memset(scriptCmds, 0, sizeof(scriptCmds));
    isLogIn = 0;

    if (argc != 4) {
        Log("Usage: %s [server IP] [server port] [script name]", argv[0]);
        return -1;
    }

    svrIP = argv[1]; 
    svrPort = atoi(argv[2]);
    const char* scriptName = argv[3];

    if (svrPort < 0)
    {
        Error("Invalid port.");
    }
    
    readScript(scriptName);

    DoClient();

    delete []scriptCmds;
    
    return 0;
}

