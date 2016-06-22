

int main(int argc, char **argv)
{
    int rv = 0;

    rv = so_telnetd_init(argc, argv);

    while (1)
    {
        sleep(100);    
    }

    return rv;
}
