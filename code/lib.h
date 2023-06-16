void cleanup_handler()
{
    ptintf("a thread cancel\n");
}
void *setIPpool(void *arg) //procsee_id=IPpool[i],IP=192.168.53.i+5,procsee_id
{
    pthread_cleanup_push(cleanup_handler, NULL);
    int msgid = *((int *)arg);
    while (1)
    {
        struct msgbuf1 msg;
        if (msgrcv(msgid, &msg, 8, 1, 0) == -1)
        {
            perror("msgrcv");
            exit(1);
        }
        if (msg.optype == 1)
        {
            for (int i = 0; i < 200; i++)
            {
                if (IPpool[i] == 0)
                {
                    IPpool[i] = msg.id;
                    struct msgbuf1 ret_msg;
                    ret_msg.mtype = 2;
                    ret_msg.optype = i + 5;
                    ret_msg.id = i + 5;
                    if (msgsnd(msgid, &ret_msg, 8, 0) == -1)
                    {
                        perror("msgsnd");
                        exit(EXIT_FAILURE);
                    }
                    return NULL;
                }
            }
            perror("ip_out");
            exit(EXIT_FAILURE);
        }
        else
        {
            int add = msg.id - 5;
            IPpool[add] = 0;
        }
    }
    pthread_cleanup_pop(0);
    pthread_exit(NULL);
}
void *readTUN(void *arg)
{
    /*
    int msgid = *((int *)arg);
    struct msgbuf
    {
        long mtype;      // 消息类型
        char mtext[256]; // 消息体
    };
    struct msgbuf msg;
    memset(&msg, 0, sizeof(msg));
    msg.mtype = 1;
    strcpy(msg.mtext, "Hello world!");
    if (msgsnd(msgid, &msg, sizeof(msg.mtext), 0) == -1)
    {
        perror("msgsnd");
        exit(EXIT_FAILURE);
    }
    */
    return NULL;
}
int creat_msg()
{
    key_t key;
    if ((key = ftok("/home/seed/miniVPN/code/README", '1')) < 0)
    {
        perror("ftok error");
        exit(1);
    }
    // 创建消息队列
    int msgid;
    if ((msgid = msgget(key, IPC_CREAT | 0666)) == -1)
    {
        perror("msgget error");
        exit(1);
    }
    return msgid;
}