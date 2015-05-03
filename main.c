#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/user.h>
#include <sys/syscall.h>   /* For SYS_write etc */
#include <sys/reg.h>
#include <fcntl.h>

void catchinterrupt(int signo);	//signal handler

pid_t child;	//global metablhth gia na perastei ws orisma sthn kill pou kaloume ston signal handler (catchinterrupt)

int main (int argc, char* argv[])
{
int trace_p_ctrl = -1;	//0 if trace process-control disabled, 1 otherwise (disabled by default)
int trace_f_mngmt = -1;	//0 if trace file_management disabled, 1 otherwise (disabled by default)
int bl_mode = -1;	//blocking-mode off by default (-1), when blocking-mode on-> bl_mode = 1
int limit_trace = -1;	//limit-trace not defined

//REDIRECTION DISABLED BY DEFAULT
int redirect_input = -1;
int redirect_output = -1;
int redirect_error = -1;

char* filename_input;	//<filename> from redirect stdin <filename>
char* filename_output;	//<filename> from redirect stdout <filename>
char* filename_error;	//<filename> from redirect stderr <filename>

char* str = malloc(100*sizeof(char));	//string given in stdin by user
char * pch;	//token of the string

int count_p_ctrl = 0;	//number of detected process-control syscalls
int count_f_mngmt = 0;	//number of detected file-management syscalls

long orig_eax, eax;
int status;	//argument for wait
int insyscall;	
int entolh_go;	//0 if command "go" wasn't given in this loop, 1 if it was given

int trace_p_ctrl_changed = 0;
int trace_f_mngmt_changed = 0;

while(1){	//this loop will stop (normally) only when we give the "quit" (or "q") command
	if(trace_p_ctrl_changed == 1)
		trace_p_ctrl = 1;
	if(trace_f_mngmt_changed == 1)
		trace_f_mngmt = 1;

	entolh_go = -1;	//no commands given in this loop yet
	insyscall = -1;

	trace_p_ctrl_changed = 0;
	trace_f_mngmt_changed = 0;

	printf("give me a string\n");
	fgets(str, 100, stdin);		//reading string from stdin
	pch = strtok (str," \n");	//Splitting string into tokens
	while (pch != NULL)	//if (pch==NULL) given string is already fully read
	{
		if((strcmp(pch, "trace") == 0) || (strcmp(pch, "t") == 0))	//command given is "trace" or "t"
		{
			pch = strtok (NULL, " \n");	//Splitting string into tokens-necessary <category> after command trace
			if(strcmp(pch, "process-control") == 0)	//we want to monitor process-control syscalls
			{
				trace_f_mngmt = -1;	//since there wasn't given trace all -or t all- command, monitoring file-management syscalls is disabled
				count_f_mngmt = 0;	//monitoring file-management syscalls is disabled, so no file-management syscalls are detected
				trace_p_ctrl = 1;	//enable monitoring process-control syscalls
			}
			else if(strcmp(pch, "file-management") == 0)	//we want to monitor file-management syscalls
			{
				trace_p_ctrl = -1;	//since there wasn't given trace all -or t all- command, monitoring process-control syscalls is disabled
				count_p_ctrl = 0;	//monitoring process-control syscalls is disabled, so no process-control syscalls are detected
				trace_f_mngmt = 1;	//enable monitoring file-management syscalls
			}
			else if(strcmp(pch, "all") == 0)	//we want to monitor all the above syscalls
			{
				trace_p_ctrl = 1;	//enable monitoring process-control syscalls
				trace_f_mngmt = 1;	//enable monitoring file-management syscalls
			}
			else
			{
				printf("wrong argument after trace\n");
			}
		}

		else if((strcmp(pch, "redirect") == 0) || (strcmp(pch, "r") == 0))	//we want to redirect one of the 3 input/output standard streams
		{
                        pch = strtok (NULL, " \n");	//Splitting string into tokens-necessary <stream> after command redirect
                        if(strcmp(pch, "stdin") == 0)
			{
				redirect_input = 1;	//redirection of stdin enabled
				pch = strtok (NULL, " \n");	//Splitting string into tokens-necessary <filename> after command redirect stdin
				if(pch == NULL)	//if there are no more tokens
				{
					printf("no argument after redirect input, redirection cancelled\n");
					redirect_input = -1;	//redirection of stdin cancelled
				}
				else
				{
					filename_input = malloc(sizeof(pch));	//<filename> after command redirect stdin
					strcpy(filename_input, pch);
				}
			}
			else if(strcmp(pch, "stdout") == 0)
			{
				redirect_output = 1;	//redirection of stdout enabled
				pch = strtok (NULL, " \n");	//Splitting string into tokens-necessary <filename> after command redirect stdout
				if(pch == NULL)	//if there are no more tokens
				{
					printf("no argument after redirect input, redirection cancelled\n");
					redirect_output = -1;	//redirection of stdout cancelled
				}
				else
				{
					filename_output = malloc(sizeof(pch));   //<filename> after command redirect stdout
					strcpy(filename_output, pch);
				}
			}
                        else if(strcmp(pch, "stderr") == 0)
                        {
				redirect_error = 1;	//redirection of stderr enabled
				pch = strtok (NULL, " \n");	//Splitting string into tokens-necessary <filename> after command redirect stderr
				if(pch == NULL)	//if there are no more tokens
				{
					printf("no argument after redirect input, redirection cancelled\n");
					redirect_error = -1;	//redirection of stderr cancelled
				}
				else
				{
					filename_error = malloc(sizeof(pch));	//<filename> after command redirect stderr
					strcpy(filename_error, pch);
				}
                        }
			else
			{
				printf("wrong argument after redirect\n");
			}
		}

		else if((strcmp(pch, "blocking-mode") == 0) || (strcmp(pch, "b") == 0))	//we want to set bl_mode on or off
		{
			pch = strtok (NULL, " \n");	//Splitting string into tokens-necessary <mode> after command blocking-mode
			if(strcmp(pch, "on") == 0)
			{
				bl_mode = 1;	//enable blocking-mode
			}
			else if(strcmp(pch, "off") == 0)
			{
				bl_mode = -1;	//disable blocking-mode
			}
                        else
                        {
				printf("wrong argument after blocking-mode\n");
                        }
		}

		else if((strcmp(pch, "limit-trace") == 0) || (strcmp(pch, "l") == 0))	 //we want to set a limit-trace
		{
			pch = strtok (NULL, " \n");     //Splitting string into tokens-necessary <number> after command limit-trace
			limit_trace = atoi(pch);

			//limit-trace is reset->check if you can monitor more syscalls
			if((limit_trace != -1) && (count_p_ctrl != 0) && (count_p_ctrl < limit_trace))
				trace_p_ctrl = 1;	//more process-control syscalls will be monitored
			if((limit_trace != -1) && (count_f_mngmt != 0) && (count_f_mngmt < limit_trace))
				trace_f_mngmt = 1;	//more file-management syscalls will be monitored
			count_p_ctrl = 0;	//limit-trace is reset, counter turns to zero
			count_f_mngmt = 0;	//limit-trace is reset, counter turns to zero
		}

		else if((strcmp(pch, "go") == 0) || (strcmp(pch, "g") == 0))	//we want to start the execution
		{
			entolh_go = 1;	//command "go" was given in this loop
			break;	//ignore the rest of the string, start the execution
		}

		else if((strcmp(pch, "quit") == 0) || (strcmp(pch, "q") == 0))
		{
			return 0;	//termination of picodb
		}

		else if((strcmp(pch, "help") == 0) || (strcmp(pch, "h") == 0))	//we want to give some guidance about the commands
		{
			//TYPWSE CLI ENTOLES MAZI ME SUNTOMH PERIGRAFH
			printf("COMMAND\t\t\t\tDESCRIPTION\n");
			printf("-------\t\t\t\t-----------\n");
			printf("trace <category>\t\tRequest for monitoring all the system calls of <category>. Parameter <category> could be:\n");
			printf("\t\t\t\t\"process control\": Particular category of syscalls (execve, fork, wait4, kill)\n");
			printf("\t\t\t\t\"file management\": Particular category of syscalls (open, close, read, write)\n");
			printf("\t\t\t\t\"all\": Monitors all the above categories of system calls. Practically it's like the user gave the commands\n");
 			printf("\t\t\t\t\t\"trace process-control\" and \"trace file-management\"\n\n");
			printf("redirect <stream> <filename>\tRequest for redirecting one of the three standard input/output streams from/to file, of the "
				"program which will be executed.\n");
			printf("\t\t\t\tThe parameter <filename> is the name of a file. <stream> could be:\n");
			printf("\t\t\t\tstdin: Request for redirecting the input of the program which will be executed, from the file <filename>.\n");
			printf("\t\t\t\t\tThe file has to exist, otherwise an error message is printed\n");
			printf("\t\t\t\tstdout: Request for redirecting the output stdout of the program which will be executed, to the file <filename>.\n");
			printf("\t\t\t\t\tIf the file doesn't exist, it is created. If the file exists,"
				"its old contents should be deleted when the execution begins\n");
                        printf("\t\t\t\tstderr: Request for redirecting the output stderr of the program which will be executed, to the file <filename>.\n");
                        printf("\t\t\t\t\tIf the file doesn't exist, it is created. If the file exists,"
                                "its old contents should be deleted when the execution begins\n\n");
			printf("blocking-mode <mode>\t\tSets the parameter blocking-mode on condition <mode>. The parameter <mode could be:\n");
			printf("\t\t\t\ton: The execution of the monitored program is freezed every time that one of the monitored system calls is called\n");
			printf("\t\t\t\t\tand the user is asked if he/she wants the monitored execution to be continued.\n");
			printf("\t\t\t\t\tFor the continuation of the execution the user will respond y "
				"and for stopping the execution the user will respond n.\n");
			printf("\t\t\t\toff: The program is executed without interruption\n\n");
			printf("limit-trace <number>\t\tSets a limit on how many system calls of every category will be monitored.\n");
			printf("\t\t\t\tIf the limit-trace is set, after <number> calls of every category, the rest calls of this category will be ignored.\n");
			printf("\t\t\t\tIf the limit-trace is not set, picodb will monitor all calls of system calls"
				" of the categories which were defined via CLI\n\n");
			printf("go\t\t\t\tThe program which was given to picodb as argument is executed and it is monitored"
				" according to the commands that the user gave via CLI.\n"); 
			printf("\t\t\t\tWhen the monitored program is terminated, the information that the user asked via CLI,"
				" before giving the command go, will be printed.\n\n");
			printf("quit\t\t\t\tPicodb is terminated.\n\n");
			printf("help\t\t\t\tAll CLI commands supported by picpdb and are available to the user are printed, with a short description\n\n");	
		}

		else
		{
			printf("invalid command given\n");
		}

		pch = strtok (NULL, " \n");	//Splitting string into tokens
	}

	if(entolh_go == -1)	//if command "go" was not given in this loop
		continue;	//ask again for string, until you receive "go"



	child = fork();	//creating a child- this is the program to be monitored
	if(child == 0)	//child code
	{
		if(redirect_input == 1)	//if redirection of stdin is enabled
		{
			int filedesc1 = open(filename_input, O_RDONLY);	//open the file filename_input
			if(filedesc1 < 0)
				printf("This file doesn't exist! Redirection of stdin cancelled\n");
			else
			{
				//redirection using pipes and forked processes
				int fd1[2];
				if(pipe(fd1) == -1 )	//creating a pipe
				{
					perror("pipe");
					exit(1);
				}
				int pid1;
				if((pid1=fork( )) == -1)	//creating a child
				{
					perror("fork");
					exit(1);
				}
				dup2(filedesc1, 0);	//kleinei ton perigrafea 0 (ean einai desmeumenos) 
							//kai ton antistoixei sthn idia ontothta me ton perigrafea filedesc
				if(pid1 == 0)	//child code
				{
					close(fd1[1]);	//we just want to read from the pipe, not write
					dup2(fd1[0], filedesc1);	//kleinei ton perigrafea filedesc1
									//kai ton antistoixei sthn idia ontothta me ton perigrafea fd1[0]
					close(fd1[0]);	//kleinei ton perigrafea fd1[0] akro diabasmatos tou swlhna
					exit(0);
				}
				else
					wait(NULL);
			}
		}
		if(redirect_output == 1) //if redirection of stdout is enabled
		{
			mode_t fdmode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;	//dikaiwmata arxeiou: anagnwsh-grafh idiokthth, anagnwsh omada, anagnwsh loipoi
                        int filedesc2 = open(filename_output, O_WRONLY | O_CREAT | O_TRUNC, fdmode); //open the file filename_output
                        if(filedesc2 < 0)
                                printf("Open failed! Redirection of stdout cancelled\n");
                        else
                        {
				//redirection using pipes and forked processes
                                int fd2[2];
                                if(pipe(fd2) == -1 )	//creating a pipe
                                {
                                        perror("pipe");
                                        exit(1);
                                }
                                int pid2;
                                if((pid2=fork( )) == -1)	//creating a child
                                {
                                        perror("fork");
                                        exit(1);
                                }
                                dup2(filedesc2, 1);     //kleinei ton perigrafea 1 (ean einai desmeumenos)
                                                        //kai ton antistoixei sthn idia ontothta me ton perigrafea filedesc
                                if(pid2 == 0)	//child code
                                {
                                        close(fd2[0]);   //we just want to write in the pipe, not read
                                        dup2(fd2[1], filedesc2);	//kleinei ton perigrafea filedesc2
									//kai ton antistoixei sthn idia ontothta me ton perigrafea fd2[1]
                                        close(fd2[1]);	//kleinei ton perigrafea fd2[1] akro grapsimatos tou swlhna
                                        exit(0);
                                }
                                else
                                        wait(NULL);
			}
		}
		if(redirect_error == 1)	//if redirection of stderr is enabled
		{
			mode_t fdmode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;	//dikaiwmata arxeiou: anagnwsh-grafh idiokthth, anagnwsh omada, anagnwsh loipoi
                        int filedesc3 = open(filename_error, O_WRONLY| O_CREAT | O_TRUNC, fdmode);	 //open the file filename_error
                        if(filedesc3 < 0)
                                printf("Open failed! Redirection of stderr cancelled\n");
                        else
                        {
                                int fd3[2];
                                if(pipe(fd3) == -1 )	//creating a pipe
                                {
                                        perror("pipe");
                                        exit(1);
                                }
                                int pid3;
                                if((pid3=fork( )) == -1)	//creating a child
                                {
                                        perror("fork");
                                        exit(1);
                                }
                                dup2(filedesc3, 2);     //kleinei ton perigrafea 2 (ean einai desmeumenos)
                                                        //kai ton antistoixei sthn idia ontothta me ton perigrafea filedesc3
                                if(pid3 == 0)
                                {
                                        close(fd3[0]);   //we just want to write in the pipe, not read
                                        dup2(fd3[1], filedesc3);       //kleinei ton perigrafea filedesc3
                                                                        //kai ton antistoixei sthn idia ontothta me ton perigrafea fd3[1]
                                        close(fd3[1]);	//kleinei ton perigrafea fd3[1] akro grapsimatos tou swlhna
                                        exit(0);
                                }
                                else
                                        wait(NULL);
                        }
		}

		ptrace(PTRACE_TRACEME, 0, NULL, NULL);	//child want to be traced

		execl(argv[1], NULL);	//allazei thn eikona mnhmhs tou programmatos
    	}
    	else
	{
		//CATCHING SIGNALS
		static struct sigaction act ;
		act.sa_handler = catchinterrupt ;	//not any more the default signal handler
		sigemptyset (&( act.sa_mask ));
		sigaddset (&( act.sa_mask ), SIGINT ); // add signal SIGINT
		sigaddset (&( act.sa_mask ), SIGTERM ); // add signal SIGTERM
		sigaddset (&( act.sa_mask ), SIGHUP ); // add signal SIGHUP
		sigaction (SIGINT , &act , NULL );
		sigaction (SIGTERM , &act , NULL );
		sigaction (SIGHUP , &act , NULL );

       		while(1)	//this loop will stop only by a signal sent to child or normally when the child will terminate
		{
			int ask = 0;	//1 when a signal we want to monitor is detected, 0 otherwise
        		
			wait(&status);
        		if(WIFEXITED(status))	//normal termination
          			break;
			else if(WIFSIGNALED(status))	//termination caused bu signal
			{
				printf("the child process was terminated by a signal\n");
				break;
			}

          		orig_eax = ptrace(PTRACE_PEEKUSER, child, 4 * ORIG_EAX, NULL);

			if(trace_f_mngmt == 1)	//file-management syscalls are being traced
			{
				if(orig_eax == SYS_write)	//signal caused by write
				{
	             			if(insyscall == 0)	//when insyscall==0 we entry the signal
					{
	                			/* Syscall entry */
	                			insyscall = 1;	//next time we will exit the signal
						printf("Entry write\n");
						ask = 1;	//a signal we want to monitor is detected
	                		}
	          			else
					{ 
						/* Syscall exit */
	                			eax = ptrace(PTRACE_PEEKUSER,child, 4 * EAX, NULL);
				                printf("Write returned with %ld\n", eax);
						ask = 1;	//a signal we want to monitor is detected
				                insyscall = 0;	//next time we will entry the signal
						count_f_mngmt++;	//one more file-management syscall was detected
						if((limit_trace != -1) && (count_f_mngmt == limit_trace))	//we have already detected 
														//as many signals as we were asked to
						{
							trace_f_mngmt = -1;	//file-management signals will no longer be monitored
						}
	                		}
				}

                                if(orig_eax == SYS_read)	//signal caused by read
                                {
                                        if(insyscall == 0)      //when insyscall==0 we entry the signal
                                        {
                                                /* Syscall entry */
                                                insyscall = 1;  //next time we will exit the signal
                                                printf("Entry read\n");
						ask = 1;        //a signal we want to monitor is detected
                                        }
                                        else
                                        {
                                                /* Syscall exit */
                                                eax = ptrace(PTRACE_PEEKUSER,child, 4 * EAX, NULL);
                                                printf("Read returned with %ld\n", eax);
						ask = 1;       //a signal we want to monitor is detected
                                                insyscall = 0;  //next time we will entry the signal
                                                count_f_mngmt++;        //one more file-management syscall was detected
                                                if((limit_trace != -1) && (count_f_mngmt == limit_trace))       //we have already detected
                                                                                                                //as many signals as we were asked to
                                                {
							trace_f_mngmt = -1;     //file-management signals will no longer be monitored
						}
                                        }
                                }

                                if(orig_eax == SYS_close)        //signal caused by close
                                {
                                        if(insyscall == 0)      //when insyscall==0 we entry the signal
                                        {
                                                /* Syscall entry */
                                                insyscall = 1;  //next time we will exit the signal
                                                printf("Entry close\n");
						ask = 1;        //a signal we want to monitor is detected
                                        }
                                        else
                                        {
                                                /* Syscall exit */
                                                eax = ptrace(PTRACE_PEEKUSER,child, 4 * EAX, NULL);
                                                printf("Close returned with %ld\n", eax);
						ask = 1;       //a signal we want to monitor is detected
                                                insyscall = 0;  //next time we will entry the signal
                                                count_f_mngmt++;        //one more file-management syscall was detected
                                                if((limit_trace != -1) && (count_f_mngmt == limit_trace))       //we have already detected
                                                                                                                //as many signals as we were asked to
                                                {
							trace_f_mngmt = -1;     //file-management signals will no longer be monitored
						}
                                        }
                                }

                                if(orig_eax == SYS_open)       //signal caused by open
                                {
                                        if(insyscall == 0)     //when insyscall==0 we entry the signal
                                        {
                                                /* Syscall entry */
                                                insyscall = 1;  //next time we will exit the signal
                                                printf("Entry open\n");
						ask = 1;        //a signal we want to monitor is detected
                                        }
                                        else
                                        {
                                                /* Syscall exit */
                                                eax = ptrace(PTRACE_PEEKUSER,child, 4 * EAX, NULL);
                                                printf("Open returned with %ld\n", eax);
						ask = 1;     //a signal we want to monitor is detected
                                                insyscall = 0;  //next time we will entry the signal
                                                count_f_mngmt++;        //one more file-management syscall was detected
                                                if((limit_trace != -1) && (count_f_mngmt == limit_trace))       //we have already detected
                                                                                                                //as many signals as we were asked to
                                                {
							trace_f_mngmt = -1;     //file-management signals will no longer be monitored
						}
                                        }
                                }

            		}

			if(trace_p_ctrl == 1)  //process-control syscalls are being traced
			{
                                if(orig_eax == SYS_execve)       //signal caused by execve
                                {
                                        if(insyscall == 0)     //when insyscall==0 we entry the signal
                                        {
                                                /* Syscall entry */
                                                insyscall = 1;  //next time we will exit the signal
                                                printf("Entry exec\n");
						ask = 1;    //a signal we want to monitor is detected
                                        }
                                        else
                                        {
                                                /* Syscall exit */
                                                eax = ptrace(PTRACE_PEEKUSER,child, 4 * EAX, NULL);
                                                printf("Exec returned with %ld\n", eax);
						ask = 1;    //a signal we want to monitor is detected
                                                insyscall = 0;  //next time we will entry the signal
                                                count_p_ctrl++;       //one more process-control syscall was detected
                                                if((limit_trace != -1) && (count_p_ctrl == limit_trace))       //we have already detected
                                                                                                               //as many signals as we were asked to
                                                {
							trace_p_ctrl = -1;     //process-control signals will no longer be monitored
						}
                                        }
                                }

				if(orig_eax == SYS_fork)       //signal caused by fork
                                {
                                        if(insyscall == 0)    //when insyscall==0 we entry the signal
                                        {
                                                /* Syscall entry */
                                                insyscall = 1;  //next time we will exit the signal
                                                printf("Entry fork\n");
						ask = 1;    //a signal we want to monitor is detected
                                        }
                                        else
                                        {
                                                /* Syscall exit */
                                                eax = ptrace(PTRACE_PEEKUSER,child, 4 * EAX, NULL);
                                                printf("Fork returned with %ld\n", eax);
						ask = 1;    //a signal we want to monitor is detected
                                                insyscall = 0;  //next time we will entry the signal
                                                count_p_ctrl++;      //one more process-control syscall was detected
                                                if((limit_trace != -1) && (count_p_ctrl == limit_trace))       //we have already detected
                                                                                                               //as many signals as we were asked to
                                                {
							trace_p_ctrl = -1;    //process-control signals will no longer be monitored
						}
                                        }
                                }

                                if(orig_eax == SYS_wait4)       //signal caused by wait4
                                {
                                        if(insyscall == 0)    //when insyscall==0 we entry the signal
                                        {
                                                /* Syscall entry */
                                                insyscall = 1;  //next time we will exit the signal
                                                printf("Entry wait4\n");
						ask = 1;   //a signal we want to monitor is detected
                                        }
                                        else
                                        {
                                                /* Syscall exit */
                                                eax = ptrace(PTRACE_PEEKUSER,child, 4 * EAX, NULL);
                                                printf("Wait4 returned with %ld\n", eax);
						ask = 1;   //a signal we want to monitor is detected
                                                insyscall = 0;  //next time we will entry the signal
                                                count_p_ctrl++;     //one more process-control syscall was detected
                                                if((limit_trace != -1) && (count_p_ctrl == limit_trace))      //we have already detected
                                                                                                               //as many signals as we were asked to
                                                {
							trace_p_ctrl = -1;    //process-control signals will no longer be monitored
						}
                                        }
                                }

                                if(orig_eax == SYS_kill)       //signal caused by kill
                                {
                                        if(insyscall == 0)    //when insyscall==0 we entry the signal
                                        {
                                                /* Syscall entry */
                                                insyscall = 1;  //next time we will exit the signal
                                                printf("Entry kill\n");
						ask = 1;  //a signal we want to monitor is detected
	                                }
                                        else
                                        {
                                                /* Syscall exit */
                                                eax = ptrace(PTRACE_PEEKUSER,child, 4 * EAX, NULL);
                                                printf("Kill returned with %ld\n", eax);
						ask = 1;  //a signal we want to monitor is detected
                                                insyscall = 0;  //next time we will entry the signal
                                                count_p_ctrl++;     //one more process-control syscall was detected
                                                if((limit_trace != -1) && (count_p_ctrl == limit_trace))      //we have already detected
                                                                                                               //as many signals as we were asked to
						{
							trace_p_ctrl = -1;    //process-control signals will no longer be monitored
						}
                                        }
                                }
			}

			if((bl_mode == 1) && ((trace_p_ctrl != -1) || (trace_f_mngmt != -1)) && (ask == 1))	//blocking-mode is on, at least one category is 
														//being monitored and we have detected a signal 
														//we are interested in
			{
				int flag = 0;
				char answer;	//answer given in stdin by user
				printf("Want to continue tracing execution?\n");
				answer = fgetc(stdin);
				fgetc(stdin);	//reading \n

				while((answer != 'n') && (answer != 'y'))
				{
					printf("VALID ANSWERS ONLY: 'y' or 'n' Want to continue tracing execution?\n");
					answer = fgetc(stdin);
					fgetc(stdin);
                                        if((answer == '\n') && (flag == 0))
					{
                                                printf("Please click enter and after that give your answer!\n");
						flag = 1;
					}
					else if((answer == '\n') && (flag == 1))
                                                flag = 0;
				}

				if(answer == 'n')	//user wants to stop tracing
				{
					if(trace_p_ctrl == 1)	//if trace process-control is enabled
					{
						trace_p_ctrl = -1;	//disable it
						trace_p_ctrl_changed = 1;	//trace process-control was disabled because user wanted so
					}
					if(trace_f_mngmt == 1)   //if trace file-management is enabled
					{
						trace_f_mngmt = -1;      //disable it
						trace_f_mngmt_changed = 1;  //trace file-management was disabled because user wanted so
					}
				}
			}

			if(insyscall == -1)	//when the execution starts, insyscall = -1
				insyscall = 0;

            		ptrace(PTRACE_SYSCALL,child, NULL, NULL);	//trace your child
        	}
	}
	wait(&status);

}

	free(str);
	return 0;
}


void catchinterrupt(int signo)	//signal handler
{
        printf("\nSending to child signal\n");
	if(kill(child, SIGKILL) != 0)
		printf("failure is sending to child a signal\n");
}
