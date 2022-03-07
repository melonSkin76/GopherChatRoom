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

#define MAX_SAVED_USERS 100
#define MAX_ONLINE 32
#define MAX_NAME_SIZE 8
#define MAX_MSG_SIZE 256
#define FILE_BUFFER_SIZE 512
#define MAX_GROUPS 10

struct usr
{
    char name[MAX_NAME_SIZE];
    char passwd[MAX_MSG_SIZE];
};
struct pkt
{
    int op;
    int onlineID;
    char targetName[MAX_NAME_SIZE];
    char msg[MAX_MSG_SIZE];
};

int usrLineCnt;
int * onlineSlots = new int[MAX_ONLINE];
char ** OnlineNames = new char*[MAX_ONLINE];
usr * usrs = new usr[MAX_SAVED_USERS];
int * sendFds = new int[MAX_ONLINE];
pthread_mutex_t lock;
int * groupSlots = new int[MAX_GROUPS];
char ** groupNames = new char*[MAX_GROUPS];
int * groupMembers = new int[MAX_GROUPS * MAX_ONLINE]; // accessed by groups[groupID * MAX_ONLINE + onlineID];

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

void updateUsrs(const char* usrsRL) {
    // Log("Start of updateUsrs() function.");
    memset(usrs, 0, sizeof(usrs));

    std::ifstream usrsFile(usrsRL);
    if (!usrsFile.good())
    {
        Error("Invalid users file--%s", usrsRL);
    }
    
    std::string usrLine;
    std::vector<std::string> usrLineComps;

    usrLineCnt = 0;
    while (std::getline(usrsFile, usrLine))
    {
        if (usrLineCnt > MAX_SAVED_USERS)
        {
            Error("Number of saved users exceeds limit.");
        }
        
        split(usrLine, usrLineComps, " ");

        if (usrLineComps.size() != 2)
        {
            Error("Invalid user entry.");
        }
        else
        {
            // Log("comp1=%s, comp2=%s.", usrLineComps[0].c_str(), usrLineComps[1].c_str());
            // Log("Going to modify usrs[%d].", usrLineCnt);
            strcpy(usrs[usrLineCnt].name, usrLineComps[0].c_str());
            // Log("Modifying usrs[%d] finished half.", usrLineCnt);
            strcpy(usrs[usrLineCnt].passwd, usrLineComps[1].c_str());
            // Log("Modifying usrs[%d] finished.", usrLineCnt);
        }
        usrLineComps.clear();
        usrLineCnt++;
    } 
}

void addUsr(const char* usrsRL, char* usrName, char* usrPasswd) {
    // Log("Start of addUsr() function.");
    std::ofstream usrsFile;

    usrsFile.open(usrsRL, std::ios::app);

    usrsFile << usrName << " " << usrPasswd << std::endl;
    
    updateUsrs(usrsRL);
}

void clearUsrs(const char* usrsRL, char* usrName, char* usrPasswd) {
    std::ofstream usrsFile;
    usrsFile.open(usrsRL, std::ofstream::out | std::ofstream::trunc);
    usrsFile.close();

    updateUsrs(usrsRL);
}

int Send_Blocking(int sockFD, const BYTE * data, int len) {
	int nSent = 0;
	while (nSent < len) {
		int n = send(sockFD, data + nSent, len - nSent, 0);
        // Log("%d data sent.",n);
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
    // Log("Send finished.");
	return 0;
}

int Recv_Blocking(int sockFD, BYTE * data, int len) {
	int nRecv = 0;
	while (nRecv < len) {
		int n = recv(sockFD, data + nRecv, len - nRecv, 0);
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
	return 0;
}

int sendHandler(struct pkt sendInfo) {
    // Log("Start dealing with sends for %s.", sendInfo.msg);
    struct pkt * buf = (struct pkt *)malloc(sizeof(struct pkt));
    memset(buf, 0, sizeof(struct pkt));
    int ret = OK;

    if (sendInfo.op == SEND2 || sendInfo.op == SENDA2 || sendInfo.op == SENDF2)
    {
        int targetID = 0;
        for (int i = 0; i < MAX_ONLINE; i++)
        {
            if (strcmp(OnlineNames[i], sendInfo.targetName) == 0) {
                targetID = i + 1;
                break;
            }
        }
        if (targetID == 0)
        {
            Log("User name--%s not online or does not exist.", sendInfo.targetName);
            ret = ACCOUNT_INCORRECT;
        }
        else
        {
            buf->op = sendInfo.op;
            strcpy(buf->msg, sendInfo.msg);
            if (sendInfo.op != SENDA2)
            {
                strcpy(buf->targetName, OnlineNames[sendInfo.onlineID - 1]);
            }

            if (Send_Blocking(sendFds[targetID - 1], (BYTE *)buf, sizeof(struct pkt)) < 0)
            {
                ret = FAIL;
            }
            else
            {
                if (sendInfo.op == SENDF2)
                {
                    int ready = 0;
                    if (Recv_Blocking(sendFds[targetID - 1], (BYTE *)&ready, 4) < 0)
                    {
                        ret = FAIL;
                    }
                    else
                    {
                        ready = ntohl(ready);

                        if (ready != 1)
                        {
                            ret = FAIL;
                        }
                        else
                        {
                            char fileBuffer[FILE_BUFFER_SIZE];
                            bzero(fileBuffer, FILE_BUFFER_SIZE);

                            FILE *fp = fopen(sendInfo.msg, "r");
                            if (NULL == fp)
                            {
                                Log("File--%s not found.", buf->msg);

                                ret = FILE_NOT_FOUND;
                            }
                            else
                            {
                                int readLen = 0;

                                while ((readLen = fread(fileBuffer, sizeof(char), FILE_BUFFER_SIZE, fp)) > 0)
                                {
                                    if (send(sendFds[targetID - 1], fileBuffer, readLen, 0) < 0)
                                    {
                                        Log("Failed to send file--%s to the client %s.", buf->msg, sendInfo.targetName);

                                        ret = FILE_TRANSMISSION_FAILED;
                                        break;
                                    }
                                    bzero(fileBuffer, FILE_BUFFER_SIZE);
                                }

                                Log("Transmission of the file--%s to the client %s from %s is over.", sendInfo.msg, OnlineNames[targetID - 1], buf->targetName);
                            }
                            fclose(fp);

                            ready = 2;
                            if (Recv_Blocking(sendFds[targetID - 1], (BYTE *)&ready, 4) < 0)
                            {
                                ret = FAIL;
                            }
                            else
                            {
                                ready = ntohl(ready);

                                if (ready != 3)
                                {
                                    ret = FAIL;
                                }
                            }
                        }
                    }
                }
            }
        }     
    }
    else if(sendInfo.op == SEND || sendInfo.op == SENDA || sendInfo.op == SENDF)
    {
        // Log("Going to broadcast");
        for (int i = 0; i < MAX_ONLINE; i++)
        {
            if (strcmp(OnlineNames[i], "unknown") != 0)
            {
                // Log("Found user no.%d.", i + 1);
                if (sendInfo.onlineID == i + 1)
                {
                    continue;
                }
                
                memset(buf, 0, sizeof(struct pkt));
                buf->op = sendInfo.op;
                strcpy(buf->msg, sendInfo.msg);
                if (sendInfo.op != SENDA)
                {
                    strcpy(buf->targetName, OnlineNames[sendInfo.onlineID - 1]);
                }

                // std::cout << "going to send pkt to " << OnlineNames[i] << ": op=" << buf->op << ", onlineID=" << buf->onlineID << ", targetName=" << buf->targetName << ", msg=" << buf->msg << "." << std::endl;
                
                if (Send_Blocking(sendFds[i], (BYTE *)buf, sizeof(struct pkt)) < 0)
                {
                    ret = FAIL;
                    continue;
                }
                // std::cout << "Finish sending to send pkt to " << OnlineNames[i] << ": op=" << buf->op << ", onlineID=" << buf->onlineID << ", targetName=" << buf->targetName << ", msg=" << buf->msg << "." << std::endl;

                if (sendInfo.op == SENDF)
                {
                    int ready = 0;
                    if (Recv_Blocking(sendFds[i], (BYTE *)&ready, 4) < 0)
                    {
                        ret = FAIL;
                        continue;
                    }
                    ready = ntohl(ready);

                    if (ready != 1)
                    {
                        ret = FAIL;
                        continue;
                    }
                    
                    char fileBuffer[FILE_BUFFER_SIZE];
                    bzero(fileBuffer, FILE_BUFFER_SIZE);

                    FILE *fp = fopen(sendInfo.msg, "r");
                    if (NULL == fp)
                    {
                        Log("File--%s not found.", buf->msg);

                        ret = FILE_NOT_FOUND;
                        continue;
                    }
                    else
                    {
                        int readLen = 0;

                        while ((readLen = fread(fileBuffer, sizeof(char), FILE_BUFFER_SIZE, fp)) > 0)
                        {
                            if (send(sendFds[i], fileBuffer, readLen, 0) < 0)
                            {
                                Log("Failed to send file--%s to the client %s.", buf->msg, sendInfo.targetName);

                                ret = FILE_TRANSMISSION_FAILED;
                                break;
                            }
                            bzero(fileBuffer, FILE_BUFFER_SIZE);
                        }
                        Log("Transmission of the file--%s to the client %s from %s is over.", sendInfo.msg, OnlineNames[i], buf->targetName);
                    }
                    fclose(fp);

                    ready = 2;
                    if (Recv_Blocking(sendFds[i], (BYTE *)&ready, 4) < 0)
                    {
                        ret = FAIL;
                    }
                    else
                    {
                        ready = ntohl(ready);

                        if (ready != 3)
                        {
                            ret = FAIL;
                        }
                    }
                }
            }
        }
    }
    else if (sendInfo.op == SENDGROUP)
    {
        int groupID = 0;
        for (int i = 0; i < MAX_GROUPS; i++)
        {
            if (strcmp(groupNames[i], sendInfo.targetName) == 0)
            {
                groupID = i + 1;
                break;
            }
        }

        if (groupID == 0)
        {
            Log("\n||||||||||User--%s cannot send message to group--%s because it does not exist.||||||||||\n", OnlineNames[sendInfo.onlineID - 1], sendInfo.targetName);
            ret = GROUP_NOT_FOUND;
        }
        else if (groupMembers[(groupID - 1) * MAX_ONLINE + (sendInfo.onlineID - 1)] != 1)
        {
            Log("\n||||||||||User--%s cannot send message to group--%s because he is not a member.||||||||||\n", OnlineNames[sendInfo.onlineID - 1], sendInfo.targetName);
            ret = USER_NOT_IN_GROUP;
        }
        else
        {
            for (int i = 0; i < MAX_ONLINE; i++)
            {
                if (sendInfo.onlineID == i + 1)
                {
                    continue;
                }
                else if (groupMembers[(groupID - 1) * MAX_ONLINE + i] == 1)
                {
                    memset(buf, 0, sizeof(struct pkt));
                    buf->op = sendInfo.op;
                    strcpy(buf->msg, sendInfo.msg);
                    strcpy(buf->targetName, groupNames[groupID - 1]);

                    if (Send_Blocking(sendFds[i], (BYTE *)buf, sizeof(struct pkt)) < 0)
                    {
                        ret = FAIL;
                        continue;
                    }
                }
            }
        }
    }
    else
    {
        buf->op = sendInfo.op;
        char nameList[MAX_MSG_SIZE];
        strcpy(nameList, "\n");
        for (int i = 0; i < MAX_ONLINE; i++)
        {
            if (strcmp(OnlineNames[i], "unknown") != 0)
            {
                strcat(nameList, OnlineNames[i]);
                strcat(nameList, "\n");
            }
        }
        strcpy(buf->msg, nameList);
        if (Send_Blocking(sendFds[sendInfo.onlineID - 1], (BYTE *)buf, sizeof(struct pkt)) < 0)
        {
            ret = FAIL;
        }
    }
    free(buf);

    return ret;
}

void * thread_func(void * arg) {
    // Log("KKKKKKKKKKKKKKKKKKK: onlineNames[0]=%s.", OnlineNames[0]);
    // Log("XXXXXXXXXXXXXXXXXXX: usrs[0]=%s.", usrs[0].name);

    int fd = *((int *) arg);

    int confirm;

    struct pkt * buf = (struct pkt *)malloc(sizeof(struct pkt));
    if(Recv_Blocking(fd, (BYTE *)buf, sizeof(struct pkt)) < 0){
        free(arg);
        free(buf);
        return (void *)-1;
    }

    std::cout << "Received command: op=" << buf->op << ", onlineID=" << buf->onlineID << ", targetName=" << buf->targetName << ", msg=" << buf->msg << "." << std::endl;

    if (buf->op == INIT)
    {
        int onlineID = 0;
        for (int i = 0; i < MAX_ONLINE; i++)
        {
            if (onlineSlots[i] == 0)
            {
                onlineSlots[i] = 1;
                onlineID = i + 1;
                break;
            }
        }
        if (onlineID == 0)
        {
            Log("Online users exceed limit.");
        }
        else
        {
            // Log("Saving sockFD--%d.", fd);
            sendFds[onlineID - 1] = fd;
        }
        onlineID = htonl(onlineID);
        if (Send_Blocking(fd, (BYTE *)&onlineID, 4) < 0)
        {
            free(arg);
            free(buf);
            return (void *)-1;
        }
    }
    else if (buf->onlineID > MAX_ONLINE || buf->onlineID < 1 || onlineSlots[buf->onlineID - 1] != 1)
    {
        Log("Invalid onlineID:%d.", buf->onlineID);
        confirm = htonl(INVALID_ONLINE_ID);
        Send_Blocking(fd, (BYTE *)&confirm, 4);
        free(arg);
        free(buf);
        return (void *)-1;
    }
    else if (buf->op != REGISTER && buf->op != LOGIN)
    {
        if (strcmp(OnlineNames[buf->onlineID - 1], "unknown") == 0)
        {
            Log("\n||||||||||User with id %d Not logged in.||||||||||\n", buf->onlineID);
            confirm = htonl(NOT_LOGGED_IN);
            Send_Blocking(fd, (BYTE *)&confirm, 4);
            free(arg);
            free(buf);
            return (void *)-1;
        }
        else
        {
            // Log("User with name %s starting op--%d.", OnlineNames[buf->onlineID - 1], buf->op);

            if (buf->op == LOGOUT)
            {
                Log("\n||||||||||User %s has logged out.||||||||||\n", OnlineNames[buf->onlineID - 1]);
                onlineSlots[buf->onlineID - 1] = 0;
                strcpy(OnlineNames[buf->onlineID - 1], "unknown");
                sendFds[buf->onlineID - 1] = 0;
                confirm = htonl(OK);
                Send_Blocking(fd, (BYTE *)&confirm, 4);
            }
            else if (buf->op == ADDGROUP)
            {
                int groupID = 0;
                for (int i = 0; i < MAX_GROUPS; i++)
                {
                    if (strcmp(groupNames[i], buf->targetName) == 0)
                    {
                        groupID = i + 1;
                        break;
                    }
                }
                if (groupID != 0)
                {
                    Log("\n||||||||||Group with name--%s already exists.||||||||||\n", buf->targetName);
                    groupID = 0;
                }
                else
                {
                    for (int i = 0; i < MAX_GROUPS; i++)
                    {
                        if (groupSlots[i] == 0)
                        {
                            groupSlots[i] = 1;
                            groupID = i + 1;
                            break;
                        }
                    }

                    if (groupID == 0)
                    {
                        Log("\n||||||||||Group number exceeds limit.||||||||||\n");
                    }
                    else
                    {
                        strcpy(groupNames[groupID - 1], buf->targetName);
                        Log("\n||||||||||New group--%s has been added.||||||||||\n", buf->targetName);
                    }

                    groupID = htonl(groupID);
                    if (Send_Blocking(fd, (BYTE *)&groupID, 4) < 0)
                    {
                        free(arg);
                        free(buf);
                        return (void *)-1;
                    }
                }
            }
            else if (buf->op == RMGROUP)
            {
                int groupID = 0;
                for (int i = 0; i < MAX_GROUPS; i++)
                {
                    if (strcmp(groupNames[i], buf->targetName) == 0)
                    {
                        groupID = i + 1;
                        break;
                    }
                }

                if (groupID == 0)
                {
                    Log("\n||||||||||Group--%s does not exit.||||||||||\n", buf->targetName);
                }
                else
                {
                    groupSlots[groupID - 1] = 0;
                    strcpy(groupNames[groupID - 1], "unused"); 
                    Log("\n||||||||||Group--%s has been removed.||||||||||\n", buf->targetName);
                }

                groupID = htonl(groupID);
                if (Send_Blocking(fd, (BYTE *)&groupID, 4) < 0)
                {
                    free(arg);
                    free(buf);
                    return (void *)-1;
                }
            }
            else if (buf->op == JOINGROUP)
            {
                int groupID = 0;
                for (int i = 0; i < MAX_GROUPS; i++)
                {
                    if (strcmp(groupNames[i], buf->targetName) == 0)
                    {
                        groupID = i + 1;
                        break;
                    }
                }

                if (groupID == 0)
                {
                    Log("\n||||||||||Group--%s does not exit.||||||||||\n", buf->targetName);
                }
                else
                {
                    groupMembers[(groupID - 1) * MAX_ONLINE + (buf->onlineID - 1)] = 1;
                    Log("\n||||||||||User--%s is in group--%s now.||||||||||\n", OnlineNames[buf->onlineID - 1], buf->targetName);
                }

                groupID = htonl(groupID);
                if (Send_Blocking(fd, (BYTE *)&groupID, 4) < 0)
                {
                    free(arg);
                    free(buf);
                    return (void *)-1;
                }
            }
            else if (buf->op == LEAVEGROUP)
            {
                int groupID = 0;
                for (int i = 0; i < MAX_GROUPS; i++)
                {
                    if (strcmp(groupNames[i], buf->targetName) == 0)
                    {
                        groupID = i + 1;
                        break;
                    }
                }

                if (groupID == 0)
                {
                    Log("\n||||||||||Group--%s does not exist.||||||||||\n", buf->targetName);
                }
                else
                {
                    groupMembers[(groupID - 1) * MAX_ONLINE + (buf->onlineID - 1)] = 0;
                    Log("\n||||||||||User--%s is not in group--%s now.||||||||||\n", OnlineNames[buf->onlineID - 1], buf->targetName);
                }

                groupID = htonl(groupID);
                if (Send_Blocking(fd, (BYTE *)&groupID, 4) < 0)
                {
                    free(arg);
                    free(buf);
                    return (void *)-1;
                }
            }
            else
            {
                if (buf->op == SENDF || buf->op == SENDF2)
                {
                    char fileBuffer[FILE_BUFFER_SIZE];
                    bzero(fileBuffer, FILE_BUFFER_SIZE);

                    FILE *fp = fopen(buf->msg, "w");
                    if (NULL == fp)
                    {
                        Log("Can not open file--%s to write.", buf->msg);
                        confirm = htonl(CANNOT_WRITE_FILE);
                        Send_Blocking(fd, (BYTE *)&confirm, 4);

                        free(arg);
                        free(buf);
                        return (void *)0;
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
                            confirm = htonl(CANNOT_WRITE_FILE);
                            Send_Blocking(fd, (BYTE *)&confirm, 4);

                            free(arg);
                            free(buf);
                            fclose(fp);
                            return (void *)-1;

                        }
                        // Log("%d size written.", readLen);
                        bzero(fileBuffer, FILE_BUFFER_SIZE);
                        // Log("File buffer reset.");
                    }
                    tv.tv_sec = 0;
                    tv.tv_usec = 0;
                    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

                    // Log("After the file has been received.");
                    Log("Transmission of the file--%s from client is over.", buf->msg);
                    fclose(fp);
                }
                
                pthread_mutex_lock(&lock);
                // std::cout << "Handler locked: op=" << buf->op << ", onlineID=" << buf->onlineID << ", targetName=" << buf->targetName << ", msg=" << buf->msg << "." << std::endl;
                confirm = htonl(sendHandler(*buf));
                // std::cout << "Handler unlocked: op=" << buf->op << ", onlineID=" << buf->onlineID << ", targetName=" << buf->targetName << ", msg=" << buf->msg << "." << std::endl;
                pthread_mutex_unlock(&lock);
                Send_Blocking(fd, (BYTE *)&confirm, 4);
            }
        }     
    }
    else
    {
        // Log("Start dealing with REGISTER/LOGIN for user with id %d.", buf->onlineID);

        if (buf->op == REGISTER)
        {   
            if (usrLineCnt > 0)
            {
                // Log("When there is already some users.");
                int actFnd = 0;
                for (int i = 0; i < usrLineCnt; i++)
                {
                    if (strcmp(usrs[i].name, buf->targetName) == 0) {
                        actFnd = 1;
                        break;
                    }
                }
                if (actFnd == 1)
                {
                    Log("\n||||||||||User name--%s already exists.||||||||||\n", buf->targetName);
                    confirm = htonl(ACCOUNT_INCORRECT);
                }
                else
                {
                    Log("\n||||||||||Account registered--%s.||||||||||\n", buf->targetName);
                    addUsr("userList.txt", buf->targetName, buf->msg);
                    confirm = htonl(OK);
                }
            }
            else
            {
                Log("\n||||||||||Account registered--%s.||||||||||\n", buf->targetName);
                addUsr("userList.txt", buf->targetName, buf->msg);
                confirm = htonl(OK); 
            }  
        }
        else
        {
            int actFnd = 0;
            for (int i = 0; i < usrLineCnt; i++)
            {
                if (strcmp(usrs[i].name, buf->targetName) == 0) {
                    if (strcmp(usrs[i].passwd, buf->msg) == 0)
                    {
                        actFnd = 1;
                        break;
                    }
                }
            }

            if (actFnd == 1)
            {
                // Log("Going to change online users, corresponding command op--%d, targetName--%s, msg--%s.", buf->op, buf->targetName, buf->msg);
                strcpy(OnlineNames[buf->onlineID - 1], buf->targetName);

                Log("\n||||||||||User %s has logged in.||||||||||\n", OnlineNames[buf->onlineID - 1]);
                confirm = htonl(OK);
            }
            else
            {
                Log("\n||||||||||User name--%s not exist or password--%s incorrect.||||||||||\n", buf->targetName, buf->msg);
                confirm = htonl(ACCOUNT_INCORRECT);
            }
        }
        Send_Blocking(fd, (BYTE *)&confirm, 4);
    }
    
    free(arg);
    free(buf);

    return (void *)0;
}

void DoServer(int svrPort) {
    pthread_t thread;
    int * thread_arg;
	
    if (pthread_mutex_init(&lock, NULL) != 0) {
        Error("mutex_init failed.");
    }
	int listenFD = socket(AF_INET, SOCK_STREAM, 0);
	if (listenFD < 0) {
		Error("Cannot create listening socket.");
	}
	
	struct sockaddr_in serverAddr;
	memset(&serverAddr, 0, sizeof(struct sockaddr_in));	
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons((unsigned short) svrPort);
	serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    int optval = 1;
	int r = setsockopt(listenFD, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	if (r != 0) {
		Error("Cannot enable SO_REUSEADDR option.");
	}
    signal(SIGPIPE, SIG_IGN);

    if (bind(listenFD, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) != 0) {
		Error("Cannot bind to port %d.", svrPort);
	}
	
	if (listen(listenFD, 16) != 0) {
		Error("Cannot listen to port %d.", svrPort);
	}

    Log("\n||||||||||listening on port %d.||||||||||\n", svrPort);

    while (1)
    {
        struct sockaddr_in clientAddr;
		socklen_t clientAddrLen = sizeof(clientAddr);			
		int fd = accept(listenFD, (struct sockaddr *)&clientAddr, &clientAddrLen);
		if (fd == -1) {
			Log("Cannot accept an incoming connection request.");
            continue;
		}

        Log("New Connection setup: ip--%s, port--%d.", inet_ntoa(clientAddr.sin_addr), clientAddr.sin_port);

        thread_arg = (int *)malloc(sizeof(int));
        *thread_arg = fd;

        pthread_create(&thread, NULL, thread_func, (void *)thread_arg);
    }

    pthread_mutex_destroy(&lock);
}

int main(int argc, char const *argv[])
{
    // Log("XXXXXXXXXXXXXXXXXXX: usrs[0]=%s.", usrs[0].name);
    updateUsrs("userList.txt");
    // Log("XXXXXXXXXXXXXXXXXXX: usrs[0]=%s.", usrs[0].name);
    memset(onlineSlots, 0, sizeof(onlineSlots));
    memset(groupSlots, 0, sizeof(groupSlots));
    memset(groupMembers, 0, sizeof(groupMembers));
    memset(sendFds, 0, sizeof(sendFds));
    for (int i = 0; i < MAX_ONLINE; i++)
    {
        OnlineNames[i] = new char[MAX_NAME_SIZE];
        strcpy(OnlineNames[i], "unknown");
    }
    for (int i = 0; i < MAX_GROUPS; i++)
    {
        groupNames[i] = new char[MAX_NAME_SIZE];
        strcpy(groupNames[i], "unused");
    }

    if (argc != 2) {
        Log("Usage: %s [server port]", argv[0]);
        return -1;
    }

    int port = atoi(argv[1]);

    if (port < 0)
    {
        Error("Invalid port.");
    }

    DoServer(port);


    delete []onlineSlots;
    delete []OnlineNames;
    delete []usrs;
    delete []sendFds;
    delete []groupSlots;
    delete []groupNames;
    delete []groupMembers;
    
    return 0;
}