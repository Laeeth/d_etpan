module connection;

struct EmailClient
{
  static int[] imapOkayTable=[MAILIMAP_NO_ERROR,MAILIMAP_NO_ERROR_AUTHENTICATED,MAILIMAP_NO_ERROR_NON_AUTHENTICATED];
  static int[string] storageTable=[ "POP3": POP3_STORAGE,
                                    "IMAP": IMAP_STORAGE,
                                    "NNTP": NNTP_STORAGE,
                                    "MBOX": MBOX_STORAGE,
                                    "MH": MH_STORAGE,
                                    "MAILDIR": MAILDIR_STORAGE,
                                    "FEED": FEED_STORAGE];

  int driver;
  char* server;
  int port;
  int connection_type =  IMAP_STORAGE;
  char* user;
  char* password;
  int auth_type =   IMAP_AUTH_TYPE_PLAIN;
  char* path;
  char* cache_directory;
  char* flags_directory;
  int cached=0;

  mailstorage *storage;
  mailimap * imap=null;
  mailpop3 * pop3=null;

  this(string server, string auth)
  {
    int r;
    auto parse=parseURI(server);
    this.server=toZString(parse[1]);
    this.port=to!short(parse[2]);
    this.connection_type=toZString(storageTable[parse[0]]);
    this.auth_type=toZString(authtype(auth,ret[0]));
    this.flags_directory="/tmp";

    switch(this.connection_type)
    {
      case POP3_STORAGE:
        enforce((r=pop3_mailstorage_init(storage, server, port, NULL, connection_type,
          auth_type, user, password, cached, cache_directory, flags_directory))==MAIL_NO_ERROR,
          new EmailException(EmailException.Kind.libetpan_abort,
            "EmailClient: libetpan error initializing POP3 connection",r));
        break;

      case IMAP_STORAGE:
        enforce((r=imap_mailstorage_init(storage, server, port, NULL, connection_type,
          IMAP_AUTH_TYPE_PLAIN, user, password, cached, cache_directory))==MAIL_NO_ERROR,
          new EmailException(EmailException.Kind.libetpan_abort,
            "EmailClient: libetpan error initializing IMAP connection",r));
        break;

      case NNTP_STORAGE:
        enforce((r=nntp_mailstorage_init(storage, server, port, NULL, connection_type,
          NNTP_AUTH_TYPE_PLAIN, user, password, cached, cache_directory, flags_directory))==MAIL_NO_ERROR,
          new EmailException(EmailException.Kind.libetpan_abort,
            "EmailClient: libetpan error initializing NNTP connection",r));
        break;

      case MBOX_STORAGE:
        enforce((r=mbox_mailstorage_init(storage, path, cached, cache_directory, flags_directory))==MAIL_NO_ERROR,
          new EmailException(EmailException.Kind.libetpan_abort,
            "EmailClient: libetpan error initializing MBOX storage",r));
        break;

      case MH_STORAGE:
        enforce((r=mh_mailstorage_init(storage, path, cached, cache_directory, flags_directory))==MAIL_NO_ERROR,
          new EmailException(EmailException.Kind.libetpan_abort,
            "EmailClient: libetpan error initialzing MH storage",r));
        break;

      case MAILDIR_STORAGE:
        enforce((r=maildir_mailstorage_init(storage, path, cached, cache_directory, flags_directory))==MAIL_NO_ERROR,
          new EmailException(EmailException.Kind.libetpan_abort,
            "EmailClient: libetpan error initializing MAILDIR storage",r));
        break;

      case FEED_STORAGE:
        enforce((r=feed_mailstorage_init(storage, path, cached, cache_directory, flags_directory))==MAIL_NO_ERROR,
          new EmailException(EmailException.Kind.libetpan_abort,
            "EmailClient: libetpan error initialzing FEED storage",r));         
        break;

      default:
          new EmailException(EmailException.Kind.error,
            "EmailClient: error initiialzing unknown storage type: "~this.connection_type);         
      }
  } 

  
  ~this()
  {
    switch(this.connection_type)
    {
      case IMAPS_STORAGE:
      case IMAP_STORAGE:
        mailimap_logout(imap);
        mailimap_free(imap);
        break;
      case POP3_STORAGE:
        mailpop3_quit(pop3);
        mailpop3_free(pop3);
        break;
      default:
        break;
    }
  }


  void login(string user, string password)
  {
    int r;
    this.user=user;
    this.password=password;

    switch(this.connection_type)
    {
        case IMAPS_STORAGE:
          this.imap = mailimap_new(0, NULL);
          enforce(imapOkayTable.contains(r=mailimap_ssl_connect(imap, this.server,this.port)),
            new EmailException(EmailException.Kind.libetpan_abort,
                  "EmailClient: libetpan error making IMAP connection",r));         
          enforce(imapOkayTable.contains(r=mailimap_login(imap, argv[1], argv[2]),imapErrorTable)),
            new EmailAuthException(EmailException.Kind.libetpan_auth,
                  "EmailClient: IMAP authentication failed for user "~user,r));
          break;

        case POP3_STORAGE:
          this.pop3 = mailpop3_new(0, NULL);
          enforce((r=mailpop3_ssl_connect(pop3, host, port))==MAILPOP3_NO_ERROR,
            new EmailException(EmailException.Kind.libetpan_abort,
                  "EmailClient: libetpan error making POP3 connection",r));         
          enforce((r=mailpop3_user(pop3, user))==MAILPOP3_NO_ERROR,
            new EmailException(EmailException.Kind.libetpan_abort,
                  "EmailClient: libetpan error setting POP3 user for"~ ZtoString(user),r));         
          enforce((r=mailpop3_pass(pop3, pass))==MAILPOP3_NO_ERROR,
            new EmailException(EmailException.Kind.libetpan_abort,
                  "EmailClient: libetpan error setting POP3 password for"~ ZtoString(user),r));         
        default:
          throw new EmailException(EmailException.Kind.args,
                  "EmailClient: "~this.connection_type~" not yet implemented in wrappers");
          break;
    } 
    return;
  }

  // should really return server response
  void logout()
  {
    switch(this.connection_type)
    {
      case IMAP_STORAGE:
        mailimap_logout(imap);
        mailimap_free(imap);
        break;
      default:
        break;
    }
  }

  string[] capabilities()
  {
    return [""];
  }

  bool hasCapability(string capability)  
  {

  }

  void idle()
  {

  }

  string[2][] idleCheck()
  {

  }

  string[] idleDone()
  {

  }
  // return folder type - should be Returns a dictionary containing the SELECT response. At least the EXISTS, FLAGS and RECENT keys are guaranteed to exist
  // string[][2][]
  void openFolder(string folderName)
  {
    enforce(imapOkayTable.contains(r=mailimap_select(imap, toZString(folderName))),
      new EmailAuthException(EmailException.Kind.libetpan_auth,
        "EmailClient: openFolder failed for: "~foldername,r));
  }
   
}



struct UUID
{
  mailstorage* storage;
  mailfolder *folder;

  void this(int driver, string server, int port, int connection_type,
              string user,string password, int auth_type,string  path,string  cache_directory,string  flags_directory)
  {
    throwOnError(storage = mailstorage_new(NULL));
    throwOnError(init_storage(storage, driver, server, port, connection_type, user, password, auth_type, path, cache_directory, flags_directory),MAIL_NO_ERROR);
    throwOnError(mailfolder * folder = mailfolder_new(storage, path, NULL));
    throwOnError(mailfolder_connect(folder),MAIL_NO_ERROR);
  }

  void ~this()
  {
    mailfolder_free(folder);
    mailstorage_free(storage);

  }

}

