import std.file;
import std.stdio;
import std.concurrency;
import core.stdc.time;
import std.c.linux.linux;
import std.c.linux.pthread;
//import core.time;
/** 
Port of libetpan IMAP library to the D programming Language
written in 2014 by Laeeth Isharc

see end of file for COPYRIGHT etc

 */


extern(C)
{
	/**
		following aliases are checked and correct
	*/
	alias pid_t=int;
	mailmime_content * mailmime_get_content(char * mime_type);
	alias mailmime_content_new_with_str= mailmime_get_content;
	alias chashiter=chashcell;
	alias timeval=time_t;
	/**
		following are not correct

		missing - mailmime_fields_new_encoding, mailmime_param_new_with_data, mailmime_new_empty, mailmime_set_body_text
	*/
	enum PATH_MAX=32000;
	/**
	====================
	*/

	alias uint8_t=ubyte;
	alias uint16_t=ushort;
	alias uint32_t=uint;
	alias uint64_t=ulong;
	alias int16_t=short;
	alias int32_t=int;
	alias ssize_t=size_t;
	enum no_argument        =0;
	enum required_argument  =1;
	enum optional_argument  =2;

	struct option {
		/*const */char *name;
		int has_arg;
		int *flag;
		int val;
	}
	enum LIBETPAN_REENTRANT=1;
	enum HAVE_PTHREAD_H=1;
	enum IGNORE_PTHREAD_H=0;
	enum USE_SSL=1;
	enum USE_GNUTLS=0;
	struct mailstream_ssl_context
	{
  		int fd;
		static if(USE_SSL==1)
		{
			static if(USE_GNUTLS!=1)
			{
	  			//SSL_CTX * openssl_ssl_ctx;
	  			void *openssl_ssl_ctx;
	  			//X509* client_x509;
	  			void* client_x509;
	  			//EVP_PKEY *client_pkey;
	  			void* *client_pkey;
	  		}
			else
			{
	  			gnutls_session session;
				gnutls_x509_crt client_x509;
				gnutls_x509_privkey client_pkey;
				gnutls_certificate_credentials_t gnutls_credentials;
			}
		}
	}
		

	struct mailengine
	{
		mailprivacy * privacy;
  		static if (LIBETPAN_REENTRANT==1)
  		{
			static if( (HAVE_PTHREAD_H==1) && (IGNORE_PTHREAD_H!=1))
  			{
  				pthread_mutex_t storage_hash_lock;
  			}
  		}
	  chash * storage_hash;
	}

	int	getopt_long(int, char **,char *, option *, int *);

//	int	getopt_long(int, (char * /*const*/) *, (/*const */char) *, (/*const*/ option) *, int *);
	int	getopt_long_only(int, char **, char *, option *, int *);
//	int	getopt_long_only(int, char * const *, const char *, const option *, int *);
	int	getopt(int, char **  ,  char *);
//	int	getopt(int, char ** const , const char *);

	__gshared char *optarg;			/* getopt(3) external variables */
	__gshared int optind, opterr, optopt;
	__gshared int optreset;			/* getopt(3) external variable */

	struct db_session_state_data {
	  char db_filename[PATH_MAX];
	  mail_flags_store * db_flags_store;
	}

	struct db_mailstorage {
	  char * db_pathname;
	};
	__gshared mailsession_driver * db_session_driver;

	int db_mailstorage_init(mailstorage * storage, char * db_pathname);
	int maildirdriver_maildir_error_to_mail_error(int error);
	uint32_t maildirdriver_maildir_flags_to_flags(uint32_t md_flags);
	uint32_t maildirdriver_flags_to_maildir_flags(uint32_t flags);
	//int maildir_get_messages_list(mailsession * session, maildir * md, mailmessage_driver * message_driver, mailmessage_list ** result); mailsession_driver * maildir_cached_session_driver;
	int maildir_mailstorage_init(mailstorage * storage, const char * md_pathname, int md_cached, const char * md_cache_directory, const char * md_flags_directory);

	struct maildir_session_state_data {
	  maildir * md_session;
	  mail_flags_store * md_flags_store;
	}

	enum {
	  MAILDIRDRIVER_CACHED_SET_CACHE_DIRECTORY = 1,
	  MAILDIRDRIVER_CACHED_SET_FLAGS_DIRECTORY
	};

	struct maildir_cached_session_state_data {
	  mailsession * md_ancestor;
	  char * md_quoted_mb;
	  mail_flags_store * md_flags_store;
	  char[PATH_MAX] md_cache_directory;
	  char[PATH_MAX] md_flags_directory;
	}

	struct maildir_mailstorage {
	  char * md_pathname;
	  
	  int md_cached;
	  char * md_cache_directory;
	  char * md_flags_directory;
	}


	int pop3_mailstorage_init(mailstorage * storage, const char * pop3_servername, uint16_t pop3_port, const char * pop3_command, int pop3_connection_type, int pop3_auth_type, const char * pop3_login, const char * pop3_password, int pop3_cached, const char * pop3_cache_directory, const char * pop3_flags_directory);
	int pop3_mailstorage_init_sasl(mailstorage * storage, const char * pop3_servername, uint16_t pop3_port, const char * pop3_command, int pop3_connection_type, const char * auth_type, const char * server_fqdn, const char * local_ip_port, const char * remote_ip_port, const char * login, const char * auth_name, const char * password, const char * realm, int pop3_cached, const char * pop3_cache_directory, const char * pop3_flags_directory);
	int pop3_mailstorage_init_sasl_with_local_address(mailstorage * storage, const char * pop3_servername, uint16_t pop3_port, const char * imap_local_address, uint16_t imap_local_port, const char * pop3_command, int pop3_connection_type, const char * auth_type, const char * server_fqdn, const char * local_ip_port, const char * remote_ip_port, const char * login, const char * auth_name, const char * password, const char * realm, int pop3_cached, const char * pop3_cache_directory, const char * pop3_flags_directory);
	__gshared mailsession_driver * pop3_session_driver;
	int pop3driver_pop3_error_to_mail_error(int error);
	int pop3driver_retr(mailsession * session, uint32_t indx, char ** result, size_t * result_len);
	int pop3driver_header(mailsession * session, uint32_t indx, char ** result, size_t * result_len);
	int pop3driver_size(mailsession * session, uint32_t indx, size_t * result);
	int pop3driver_get_cached_flags(mail_cache_db * cache_db, MMAPString * mmapstr, mailsession * session, uint32_t num, mail_flags ** result);
	int pop3driver_write_cached_flags(mail_cache_db * cache_db, MMAPString * mmapstr, char * uid, mail_flags * flags);
	int pop3_get_messages_list(mailpop3 * pop3, mailsession * session, mailmessage_driver * driver, mailmessage_list ** result);
	__gshared mailsession_driver * pop3_cached_session_driver;

	enum {
	  POP3DRIVER_SET_AUTH_TYPE = 1
	}

	enum {
	  POP3DRIVER_AUTH_TYPE_PLAIN = 0,
	  POP3DRIVER_AUTH_TYPE_APOP,
	  POP3DRIVER_AUTH_TYPE_TRY_APOP
	}

	struct pop3_session_state_data
	{
	  int pop3_auth_type;
	  mailpop3 * pop3_session;
	  void function(mailstream_ssl_context * ssl_context, void * data) pop3_ssl_callback;
	  void * pop3_ssl_cb_data;
	}

	enum {
	  /* the mapping of the parameters should be the same as for pop3 */
	  POP3DRIVER_CACHED_SET_AUTH_TYPE = 1,
	  POP3DRIVER_CACHED_SET_SSL_CALLBACK = 2,
	  POP3DRIVER_CACHED_SET_SSL_CALLBACK_DATA = 3,
	  /* cache specific */
	  POP3DRIVER_CACHED_SET_CACHE_DIRECTORY = 1001,
	  POP3DRIVER_CACHED_SET_FLAGS_DIRECTORY = 1002
	}

	struct pop3_cached_session_state_data {
	  mailsession * pop3_ancestor;
	  char pop3_cache_directory[PATH_MAX];
	  char pop3_flags_directory[PATH_MAX];
	  chash * pop3_flags_hash;
	  carray * pop3_flags_array;
	  mail_flags_store * pop3_flags_store;
	}

	struct pop3_mailstorage {
	  char * pop3_servername;
	  uint16_t pop3_port;
	  char * pop3_command;
	  int pop3_connection_type;

	  int pop3_auth_type;
	  char * pop3_login; /* deprecated */
	  char * pop3_password; /* deprecated */

	  int pop3_cached;
	  char * pop3_cache_directory;
	  char * pop3_flags_directory;
	  
	  struct pop3_sasl_t {
	    int sasl_enabled;
	    char * sasl_auth_type;
	    char * sasl_server_fqdn;
	    char * sasl_local_ip_port;
	    char * sasl_remote_ip_port;
	    char * sasl_login;
	    char * sasl_auth_name;
	    char * sasl_password;
	    char * sasl_realm;
	  }
	  pop3_sasl_t pop3_sasl;
	  
	  char * pop3_local_address;
	  uint16_t pop3_local_port;
	}

	/* this is the type of POP3 authentication */

	enum {
	  POP3_AUTH_TYPE_PLAIN,             /* plain text authentication */
	  POP3_AUTH_TYPE_APOP,              /* APOP authentication */
	  POP3_AUTH_TYPE_TRY_APOP,          /* first, try APOP, if it fails,
	                                       try plain text */
	  POP3_AUTH_TYPE_SASL_ANONYMOUS,    /* SASL anonymous */
	  POP3_AUTH_TYPE_SASL_CRAM_MD5,     /* SASL CRAM MD5 */
	  POP3_AUTH_TYPE_SASL_KERBEROS_V4,  /* SASL KERBEROS V4 */
	  POP3_AUTH_TYPE_SASL_PLAIN,        /* SASL plain */
	  POP3_AUTH_TYPE_SASL_SCRAM_MD5,    /* SASL SCRAM MD5 */
	  POP3_AUTH_TYPE_SASL_GSSAPI,       /* SASL GSSAPI */
	  POP3_AUTH_TYPE_SASL_DIGEST_MD5    /* SASL digest MD5 */
	};

	enum POP3_SASL_AUTH_TYPE_APOP="X-LIBETPAN-APOP";
	enum POP3_SASL_AUTH_TYPE_TRY_APOP="X-LIBETPAN-TRY-APOP";

	
	int mh_mailstorage_init(mailstorage * storage,
	    const char * mh_pathname, int mh_cached,
	    const char * mh_cache_directory, const char * mh_flags_directory);


	struct mh_session_state_data {
	  mailmh * mh_session;
	  mailmh_folder * mh_cur_folder;
	  clist * mh_subscribed_list;
	}

	enum {
	  MHDRIVER_CACHED_SET_CACHE_DIRECTORY = 1,
	  MHDRIVER_CACHED_SET_FLAGS_DIRECTORY
	}

	struct mh_cached_session_state_data {
	  mailsession * mh_ancestor;
	  char * mh_quoted_mb;
	  char mh_cache_directory[PATH_MAX];
	  char mh_flags_directory[PATH_MAX];
	  mail_flags_store * mh_flags_store;
	}

	struct mh_mailstorage {
	  char * mh_pathname;
	  int mh_cached;
	  char * mh_cache_directory;
	  char * mh_flags_directory;
	}

	__gshared mailmessage_driver * mh_message_driver;
	__gshared mailmessage_driver * mh_cached_message_driver;
	__gshared mailsession_driver * mh_cached_session_driver;
	int mhdriver_mh_error_to_mail_error(int error);
	int mhdriver_fetch_message(mailsession * session, uint32_t indx, char ** result, size_t * result_len);
	int mhdriver_fetch_header(mailsession * session, uint32_t indx, char ** result, size_t * result_len);
	int mhdriver_fetch_size(mailsession * session, uint32_t indx, size_t * result);
	int mhdriver_get_cached_flags(mail_cache_db * cache_db, MMAPString * mmapstr, mailsession * session,
	    uint32_t num, mail_flags ** result);
	int mhdriver_write_cached_flags(mail_cache_db * cache_db, MMAPString * mmapstr, char * uid, mail_flags * flags);
	int mh_get_messages_list(mailmh_folder * folder, mailsession * session, mailmessage_driver * driver, mailmessage_list ** result);
	__gshared mailmessage_driver * nntp_message_driver;
	__gshared mailmessage_driver * nntp_cached_message_driver;
	__gshared mailsession_driver * nntp_session_driver;
	__gshared  mailsession_driver * nntp_cached_session_driver;
	int nntpdriver_nntp_error_to_mail_error(int error);
	int nntpdriver_authenticate_password(mailsession * session);
	int nntpdriver_authenticate_user(mailsession * session);
	int nntpdriver_article(mailsession * session, uint32_t indx, char ** result, size_t * result_len);
	int nntpdriver_head(mailsession * session, uint32_t indx, char ** result, size_t * result_len);
	int nntpdriver_size(mailsession * session, uint32_t indx, size_t * result);
	int nntpdriver_get_cached_flags(mail_cache_db * cache_db, MMAPString * mmapstr, uint32_t num, mail_flags ** result);
	int nntpdriver_write_cached_flags(mail_cache_db * cache_db, MMAPString * mmapstr, uint32_t num, mail_flags * flags);
	int nntpdriver_select_folder(mailsession * session, const char * mb);
	int nntp_get_messages_list(mailsession * nntp_session, mailsession * session, mailmessage_driver * driver, mailmessage_list ** result);
	int nntpdriver_mode_reader(mailsession * session);
	int nntp_mailstorage_init(mailstorage * storage, const char * nntp_servername, uint16_t nntp_port,
	    const char * nntp_command, int nntp_connection_type, int nntp_auth_type, const char * nntp_login, const char * nntp_password,
	    int nntp_cached, const char * nntp_cache_directory, const char * nntp_flags_directory);
	int nntp_mailstorage_init_with_local_address(mailstorage * storage, const char * nntp_servername, uint16_t nntp_port,
	    const char * nntp_local_servername, uint16_t nntp_local_port, const char * nntp_command, int nntp_connection_type, int nntp_auth_type,
	    const char * nntp_login, const char * nntp_password, int nntp_cached, const char * nntp_cache_directory, const char * nntp_flags_directory);

	enum {
	  NNTPDRIVER_SET_MAX_ARTICLES = 1
	};

	struct nntp_session_state_data {
	  newsnntp * nntp_session;
	  char * nntp_userid;
	  char * nntp_password;

	  newsnntp_group_info * nntp_group_info;
	  char * nntp_group_name;

	  clist * nntp_subscribed_list;

	  uint32_t nntp_max_articles;

	  int nntp_mode_reader;
	};

	enum {
	  NNTPDRIVER_CACHED_SET_MAX_ARTICLES = 1,
	  NNTPDRIVER_CACHED_SET_CACHE_DIRECTORY,
	  NNTPDRIVER_CACHED_SET_FLAGS_DIRECTORY
	};

	struct nntp_cached_session_state_data {
	  mailsession * nntp_ancestor;
	  char nntp_cache_directory[PATH_MAX];
	  char nntp_flags_directory[PATH_MAX];
	  mail_flags_store * nntp_flags_store;
	}


	struct nntp_mailstorage {
	  char * nntp_servername;
	  uint16_t nntp_port;
	  char * nntp_command;
	  int nntp_connection_type;

	  int nntp_auth_type;
	  char * nntp_login;
	  char * nntp_password;

	  int nntp_cached;
	  char * nntp_cache_directory;
	  char * nntp_flags_directory;

	  char * nntp_local_address;
	  uint16_t nntp_local_port;
	};

	/* this is the type of NNTP authentication */

	enum {
	  NNTP_AUTH_TYPE_PLAIN  /* plain text authentication */
	};

	__gshared mailmessage_driver * mime_message_driver;
	__gshared mailmessage * mime_message_init(mailmime * mime);
	void mime_message_detach_mime(mailmessage * msg);
	int mime_message_set_tmpdir(mailmessage * msg, char * tmpdir);
	__gshared mailsession_driver * imap_cached_session_driver;
	int imap_mailstorage_init(mailstorage * storage, const char * imap_servername, uint16_t imap_port, const char * imap_command, int imap_connection_type, int imap_auth_type, const char * imap_login, const char * imap_password, int imap_cached, const char * imap_cache_directory);
	int imap_mailstorage_init_sasl(mailstorage * storage, const char * imap_servername, uint16_t imap_port, const char * imap_command, int imap_connection_type, const char * auth_type, const char * server_fqdn, const char * local_ip_port, const char * remote_ip_port, const char * login, const char * auth_name, const char * password, const char * realm, int imap_cached, const char * imap_cache_directory);
	int imap_mailstorage_init_sasl_with_local_address(mailstorage * storage, const char * imap_servername, uint16_t imap_port, const char * imap_local_address, uint16_t imap_local_port, const char * imap_command, int imap_connection_type, const char * auth_type, const char * server_fqdn, const char * local_ip_port, const char * remote_ip_port, const char * login, const char * auth_name, const char * password, const char * realm, int imap_cached, const char * imap_cache_directory);


	struct imap_session_state_data {
	  mailimap * imap_session;
	  char * imap_mailbox;
	  mail_flags_store * imap_flags_store;
	  void function(mailstream_ssl_context * ssl_context, void * data) imap_ssl_callback;
	  void * imap_ssl_cb_data;
	};

	enum {
	  IMAP_SECTION_MESSAGE,
	  IMAP_SECTION_HEADER,
	  IMAP_SECTION_MIME,
	  IMAP_SECTION_BODY
	};

	/* cached IMAP driver for session */

	enum {
	  IMAPDRIVER_CACHED_SET_SSL_CALLBACK = 1,
	  IMAPDRIVER_CACHED_SET_SSL_CALLBACK_DATA = 2,
	  /* cache */
	  IMAPDRIVER_CACHED_SET_CACHE_DIRECTORY = 1001
	};

	struct imap_cached_session_state_data {
	  mailsession * imap_ancestor;
	  char * imap_quoted_mb;
	  char imap_cache_directory[PATH_MAX];
	  carray * imap_uid_list;
	  uint32_t imap_uidvalidity;
	};


	struct imap_mailstorage {
	  char * imap_servername;
	  uint16_t imap_port;
	  char * imap_command;
	  int imap_connection_type;
	  
	  int imap_auth_type;
	  char * imap_login; /* deprecated */
	  char * imap_password; /* deprecated */
	  
	  int imap_cached;
	  char * imap_cache_directory;
	  
	  struct imap_sasl_t 
	  {
	    int sasl_enabled;
	    char * sasl_auth_type;
	    char * sasl_server_fqdn;
	    char * sasl_local_ip_port;
	    char * sasl_remote_ip_port;
	    char * sasl_login;
	    char * sasl_auth_name;
	    char * sasl_password;
	    char * sasl_realm;
	  }
	  imap_sasl_t imap_sasl;
	  
	  char * imap_local_address;
	  uint16_t imap_local_port;
	};

	/* this is the type of IMAP4rev1 authentication */

	enum {
	  IMAP_AUTH_TYPE_PLAIN,            /* plain text authentication */
	  IMAP_AUTH_TYPE_SASL_ANONYMOUS,   /* SASL anonymous */
	  IMAP_AUTH_TYPE_SASL_CRAM_MD5,    /* SASL CRAM MD5 */
	  IMAP_AUTH_TYPE_SASL_KERBEROS_V4, /* SASL KERBEROS V4 */
	  IMAP_AUTH_TYPE_SASL_PLAIN,       /* SASL plain */
	  IMAP_AUTH_TYPE_SASL_SCRAM_MD5,   /* SASL SCRAM MD5 */
	  IMAP_AUTH_TYPE_SASL_GSSAPI,      /* SASL GSSAPI */
	  IMAP_AUTH_TYPE_SASL_DIGEST_MD5   /* SASL digest MD5 */
	};

	__gshared mailsession_driver * imap_session_driver;
	__gshared mailmessage_driver * imap_cached_message_driver;
	__gshared mailmessage_driver * imap_message_driver;
	int imapdriver_get_cached_envelope(mail_cache_db * cache_db, MMAPString * mmapstr, mailsession * session, mailmessage * msg, mailimf_fields ** result);
	int imapdriver_write_cached_envelope(mail_cache_db * cache_db, MMAPString * mmapstr, mailsession * session, mailmessage * msg, mailimf_fields * fields);
	int imap_error_to_mail_error(int error);
	int imap_store_flags(mailimap * imap, uint32_t first, uint32_t last, mail_flags * flags);
	int imap_fetch_flags(mailimap * imap, uint32_t indx, mail_flags ** result);
	int imap_get_messages_list(mailimap * imap, mailsession * session, mailmessage_driver * driver, uint32_t first_index, mailmessage_list ** result);
	int imap_list_to_list(clist * imap_list, mail_list ** result);
	int imap_section_to_imap_section(mailmime_section * section, int type, mailimap_section ** result);
	int imap_get_msg_att_info(mailimap_msg_att * msg_att, uint32_t * puid, mailimap_envelope ** pimap_envelope, char ** preferences,
	    size_t * pref_size, mailimap_msg_att_dynamic ** patt_dyn, mailimap_body ** pimap_body);
	int imap_add_envelope_fetch_att(mailimap_fetch_type * fetch_type);
	int imap_env_to_fields(mailimap_envelope * env, char * ref_str, size_t ref_size, mailimf_fields ** result);
	int imap_fetch_result_to_envelop_list(clist * fetch_result, mailmessage_list * env_list);
	int imap_body_to_body(mailimap_body * imap_body, mailmime ** result);
	int imap_msg_list_to_imap_set(clist * msg_list, mailimap_set ** result);
	int imap_flags_to_imap_flags(mail_flags * flags, mailimap_flag_list ** result);
	int imap_flags_to_flags(mailimap_msg_att_dynamic * att_dyn, mail_flags ** result);
	int feed_mailstorage_init(mailstorage * storage, const char * feed_url, int feed_cached, const char * feed_cache_directory, const char * feed_flags_directory);
	__gshared mailsession_driver * feed_session_driver;

	struct feed_session_state_data {
	  time_t feed_last_update;
	  newsfeed * feed_session;
	  int feed_error;
	};

	struct feed_mailstorage {
	  char * feed_url;

	  int feed_cached;
	  char * feed_cache_directory;
	  char * feed_flags_directory;
	}

	__gshared mailmessage_driver * feed_message_driver;
	__gshared mailmessage_driver * mbox_cached_message_driver;

	int mbox_mailstorage_init(mailstorage * storage, const char * mb_pathname, int mb_cached,
	    const char * mb_cache_directory, const char * mb_flags_directory);

	enum {
	  MBOXDRIVER_SET_READ_ONLY = 1,
	  MBOXDRIVER_SET_NO_UID
	}

	struct mbox_session_state_data {
	  mailmbox_folder * mbox_folder;
	  int mbox_force_read_only;
	  int mbox_force_no_uid;
	}

	/* cached version */

	enum {
	  /* the mapping of the parameters should be the same as for mbox */
	  MBOXDRIVER_CACHED_SET_READ_ONLY = 1,
	  MBOXDRIVER_CACHED_SET_NO_UID,
	  /* cache specific */
	  MBOXDRIVER_CACHED_SET_CACHE_DIRECTORY,
	  MBOXDRIVER_CACHED_SET_FLAGS_DIRECTORY
	}

	struct mbox_cached_session_state_data {
	  mailsession * mbox_ancestor;
	  char * mbox_quoted_mb;
	  char mbox_cache_directory[PATH_MAX];
	  char mbox_flags_directory[PATH_MAX];
	  mail_flags_store * mbox_flags_store;
	}

	struct mbox_mailstorage {
	  char * mbox_pathname;
	  
	  int mbox_cached;
	  char * mbox_cache_directory;
	  char * mbox_flags_directory;
	}

	__gshared mailsession_driver * mbox_session_driver;
	__gshared mailsession_driver * mbox_cached_session_driver;
	int mboxdriver_mbox_error_to_mail_error(int error);
	int mboxdriver_fetch_msg(mailsession * session, uint32_t indx, char ** result, size_t * result_len);
	int mboxdriver_fetch_size(mailsession * session, uint32_t indx, size_t * result);
	int mboxdriver_get_cached_flags(mail_cache_db * cache_db, MMAPString * mmapstr, mailsession * session,
	    uint32_t num, mail_flags ** result);
	int mboxdriver_write_cached_flags(mail_cache_db * cache_db, MMAPString * mmapstr, char * uid, mail_flags * flags);
	int mbox_get_uid_messages_list(mailmbox_folder * folder, mailsession * session, mailmessage_driver * driver, mailmessage_list ** result);
	int mbox_get_messages_list(mailmbox_folder * folder, mailsession * session, mailmessage_driver * driver, mailmessage_list ** result);
	int mboxdriver_fetch_header(mailsession * session, uint32_t indx, char ** result, size_t * result_len);
	int hotmail_mailstorage_init(mailstorage * storage, char * hotmail_login, char * hotmail_password, int hotmail_cached, char * hotmail_cache_directory, char * hotmail_flags_directory);
	__gshared mailmessage_driver * data_message_driver;
	__gshared  mailmessage * data_message_init(char * data, size_t len);
	void data_message_detach_mime(mailmessage * msg);

	enum {
	  MAIL_THREAD_REFERENCES,            /* this is threading using
	                                        References fields only) */
	  MAIL_THREAD_REFERENCES_NO_SUBJECT, /* this is threading using References
	                                        fields, then subject */
	  MAIL_THREAD_ORDEREDSUBJECT,        /* this is threading using only subject */
	  MAIL_THREAD_NONE                   /* no thread */
	}


	int generic_cache_create_dir(char * dirname);
	int generic_cache_store(char * filename, char * content, size_t length);
	int generic_cache_read(char * filename, char ** result, size_t * result_len);
	int generic_cache_fields_read(mail_cache_db * cache_db, MMAPString * mmapstr, char * keyname, mailimf_fields ** result); 
	int generic_cache_fields_write(mail_cache_db * cache_db, MMAPString * mmapstr, char * keyname, mailimf_fields * fields);
	int generic_cache_flags_read(mail_cache_db * cache_db, MMAPString * mmapstr, char * keyname, mail_flags ** result); 
	int generic_cache_flags_write( mail_cache_db * cache_db, MMAPString * mmapstr, char * keyname, mail_flags * flags); 
	int generic_cache_delete( mail_cache_db * cache_db, char * keyname);
	mail_flags_store * mail_flags_store_new();
	void mail_flags_store_clear( mail_flags_store * flags_store);
	void mail_flags_store_free( mail_flags_store * flags_store);
	int mail_flags_store_set( mail_flags_store * flags_store, mailmessage * msg);
	void mail_flags_store_sort( mail_flags_store * flags_store);
	 mail_flags * mail_flags_store_get( mail_flags_store * flags_store, uint32_t indx);
	int mail_flags_compare( mail_flags * flags1, mail_flags * flags2);

	struct mail_flags_store {
	  carray * fls_tab;
	  chash * fls_hash;
	};


	int mail_serialize_clear(MMAPString * mmapstr, size_t * indx);
	int mail_serialize_write(MMAPString * mmapstr, size_t * indx, char * buf, size_t size);
	int mail_serialize_read(MMAPString * mmapstr, size_t * indx, char * buf, size_t size);
	int mailimf_cache_int_write(MMAPString * mmapstr, size_t * indx, uint32_t value);
	int mailimf_cache_string_write(MMAPString * mmapstr, size_t * indx, char * str, size_t length);
	int mailimf_cache_int_read(MMAPString * mmapstr, size_t * indx, uint32_t * result);
	int mailimf_cache_string_read(MMAPString * mmapstr, size_t * indx, char ** result);
	int mailimf_cache_fields_write(MMAPString * mmapstr, size_t * indx, mailimf_fields * fields);
	int mailimf_cache_fields_read(MMAPString * mmapstr, size_t * indx,  mailimf_fields ** result);
	int mail_build_thread(int type, char * default_from, mailmessage_list * env_list, mailmessage_tree ** result, int function( mailmessage_tree **,  mailmessage_tree **) comp_func);
	int mail_thread_sort( mailmessage_tree * tree, int function( mailmessage_tree **, mailmessage_tree **) comp_func, int sort_sub);
	int mailthread_tree_timecomp( mailmessage_tree ** ptree1,  mailmessage_tree ** ptree2);

	
	struct mailstorage_driver {
	  char * sto_name;
	  int function(mailstorage * storage) sto_connect;
	  int function(mailstorage * storage, char * pathname, mailsession ** result) sto_get_folder_session;
	  void function(mailstorage * storage) sto_uninitialize;
	}

	struct mailstorage {
	  char * sto_id;
	  void * sto_data;
	  mailsession * sto_session;
	  mailstorage_driver * sto_driver;
	  clist * sto_shared_folders; /* list of (struct mailfolder *) */ 
	  void * sto_user_data;
	}

	struct mailfolder {
	  char * fld_pathname;
	  char * fld_virtual_name;
	  
	   mailstorage * fld_storage;

	  mailsession * fld_session;
	  int fld_shared_session;
	  clistiter * fld_pos;

	   mailfolder * fld_parent;
	  uint fld_sibling_index;
	  carray * fld_children; /* array of (struct mailfolder *) */

	  void * fld_user_data;
	}


	enum {
	  CONNECTION_TYPE_PLAIN,        /* when the connection is plain text */
	  CONNECTION_TYPE_STARTTLS,     /* when the connection is first plain,
	                                   then, we want to switch to
	                                   TLS (secure connection) */
	  CONNECTION_TYPE_TRY_STARTTLS, /* the connection is first plain,
	                                   then, we will try to switch to TLS */
	  CONNECTION_TYPE_TLS,          /* the connection is over TLS */
	  CONNECTION_TYPE_COMMAND,      /* the connection is over a shell command */
	  CONNECTION_TYPE_COMMAND_STARTTLS, /* the connection is over a shell
	                                       command and STARTTLS will be used */
	  CONNECTION_TYPE_COMMAND_TRY_STARTTLS, /* the connection is over
	                                           a shell command and STARTTLS will
	                                           be tried */
	  CONNECTION_TYPE_COMMAND_TLS  /* the connection is over a shell
	                                  command in TLS */
	}
	int mailfolder_noop( mailfolder * folder);
	int mailfolder_check( mailfolder * folder);
	int mailfolder_expunge( mailfolder * folder);
	int mailfolder_status( mailfolder * folder, uint32_t * result_messages, uint32_t * result_recent, uint32_t * result_unseen);
	int mailfolder_append_message( mailfolder * folder, char * message, size_t size);
	int mailfolder_append_message_flags( mailfolder * folder, char * message, size_t size,  mail_flags * flags);
	int mailfolder_get_messages_list( mailfolder * folder,  mailmessage_list ** result);
	int mailfolder_get_envelopes_list( mailfolder * folder, mailmessage_list * result);
	int mailfolder_get_message( mailfolder * folder, uint32_t num, mailmessage ** result);
	int mailfolder_get_message_by_uid( mailfolder * folder, const char * uid, mailmessage ** result);

	enum {
	  MAIL_NO_ERROR = 0,
	  MAIL_NO_ERROR_AUTHENTICATED,
	  MAIL_NO_ERROR_NON_AUTHENTICATED,
	  MAIL_ERROR_NOT_IMPLEMENTED,
	  MAIL_ERROR_UNKNOWN,
	  MAIL_ERROR_CONNECT,
	  MAIL_ERROR_BAD_STATE,
	  MAIL_ERROR_FILE,
	  MAIL_ERROR_STREAM,
	  MAIL_ERROR_LOGIN,
	  MAIL_ERROR_CREATE, /* 10 */
	  MAIL_ERROR_DELETE,
	  MAIL_ERROR_LOGOUT,
	  MAIL_ERROR_NOOP,
	  MAIL_ERROR_RENAME,
	  MAIL_ERROR_CHECK,
	  MAIL_ERROR_EXAMINE,
	  MAIL_ERROR_SELECT,
	  MAIL_ERROR_MEMORY,
	  MAIL_ERROR_STATUS,
	  MAIL_ERROR_SUBSCRIBE, /* 20 */
	  MAIL_ERROR_UNSUBSCRIBE,
	  MAIL_ERROR_LIST,
	  MAIL_ERROR_LSUB,
	  MAIL_ERROR_APPEND,
	  MAIL_ERROR_COPY,
	  MAIL_ERROR_FETCH,
	  MAIL_ERROR_STORE,
	  MAIL_ERROR_SEARCH,
	  MAIL_ERROR_DISKSPACE,
	  MAIL_ERROR_MSG_NOT_FOUND,  /* 30 */
	  MAIL_ERROR_PARSE,
	  MAIL_ERROR_INVAL,
	  MAIL_ERROR_PART_NOT_FOUND,
	  MAIL_ERROR_REMOVE,
	  MAIL_ERROR_FOLDER_NOT_FOUND,
	  MAIL_ERROR_MOVE,
	  MAIL_ERROR_STARTTLS,
	  MAIL_ERROR_CACHE_MISS,
	  MAIL_ERROR_NO_TLS,
	  MAIL_ERROR_EXPUNGE, /* 40 */
	  /* misc errors */
	  MAIL_ERROR_MISC,
	  MAIL_ERROR_PROTOCOL,
	  MAIL_ERROR_CAPABILITY,
	  MAIL_ERROR_CLOSE,
	  MAIL_ERROR_FATAL,
	  MAIL_ERROR_READONLY,
	  MAIL_ERROR_NO_APOP,
	  MAIL_ERROR_COMMAND_NOT_SUPPORTED,
	  MAIL_ERROR_NO_PERMISSION,
	  MAIL_ERROR_PROGRAM_ERROR, /* 50 */
	  MAIL_ERROR_SUBJECT_NOT_FOUND,
	  MAIL_ERROR_CHAR_ENCODING_FAILED,
	  MAIL_ERROR_SEND,
	  MAIL_ERROR_COMMAND,
	  MAIL_ERROR_SYSTEM,
	  MAIL_ERROR_UNABLE,
	  MAIL_ERROR_FOLDER,
	  MAIL_ERROR_SSL
	}

	int mail_flags_add_extension(mail_flags * flags, char * ext_flag);
	int mail_flags_remove_extension( mail_flags * flags, char * ext_flag);
	int mail_flags_has_extension( mail_flags * flags, char * ext_flag);

	struct mailmessage_list {
	  carray * msg_tab; /* elements are (mailmessage *) */
	}

	mailmessage_list * mailmessage_list_new(carray * msg_tab);
	void mailmessage_list_free(mailmessage_list * env_list);

	struct mail_list {
	  clist * mb_list; /* elements are (char *) */
	};

	mail_list * mail_list_new(clist * mb_list);
	void mail_list_free(mail_list * resp);


	enum {
	  MAIL_FLAG_NEW       = 1 << 0,
	  MAIL_FLAG_SEEN      = 1 << 1,
	  MAIL_FLAG_FLAGGED   = 1 << 2,
	  MAIL_FLAG_DELETED   = 1 << 3,
	  MAIL_FLAG_ANSWERED  = 1 << 4,
	  MAIL_FLAG_FORWARDED = 1 << 5,
	  MAIL_FLAG_CANCELLED = 1 << 6
	}


	struct mail_flags {
	  uint32_t fl_flags;
	  clist * fl_extension; /* elements are (char *) */
	}

	mail_flags * mail_flags_new(uint32_t fl_flags, clist * fl_ext);
	void mail_flags_free(mail_flags * flags);
	mail_flags * mail_flags_new_empty();
	int32_t mailimf_date_time_comp( mailimf_date_time * date1,  mailimf_date_time * date2);
	
	enum {
	  MAIL_SEARCH_KEY_ALL,        /* all messages correspond */
	  MAIL_SEARCH_KEY_ANSWERED,   /* messages with flag \Answered */
	  MAIL_SEARCH_KEY_BCC,        /* messages which Bcc field contains
	                                 a given string */
	  MAIL_SEARCH_KEY_BEFORE,     /* messages which internal date is earlier
	                                 than the specified date */
	  MAIL_SEARCH_KEY_BODY,       /* message that contains the given string
	                                 (in header and text parts) */
	  MAIL_SEARCH_KEY_CC,         /* messages whose Cc field contains the
	                                 given string */
	  MAIL_SEARCH_KEY_DELETED,    /* messages with the flag \Deleted */
	  MAIL_SEARCH_KEY_FLAGGED,    /* messages with the flag \Flagged */ 
	  MAIL_SEARCH_KEY_FROM,       /* messages whose From field contains the
	                                 given string */
	  MAIL_SEARCH_KEY_NEW,        /* messages with the flag \Recent and not
	                                 the \Seen flag */
	  MAIL_SEARCH_KEY_OLD,        /* messages that do not have the
	                                 \Recent flag set */
	  MAIL_SEARCH_KEY_ON,         /* messages whose internal date is the
	                                 specified date */
	  MAIL_SEARCH_KEY_RECENT,     /* messages with the flag \Recent */
	  MAIL_SEARCH_KEY_SEEN,       /* messages with the flag \Seen */
	  MAIL_SEARCH_KEY_SINCE,      /* messages whose internal date is later
	                                 than specified date */
	  MAIL_SEARCH_KEY_SUBJECT,    /* messages whose Subject field contains the
	                                 given string */
	  MAIL_SEARCH_KEY_TEXT,       /* messages whose text part contains the
	                                 given string */
	  MAIL_SEARCH_KEY_TO,         /* messages whose To field contains the
	                                 given string */
	  MAIL_SEARCH_KEY_UNANSWERED, /* messages with no flag \Answered */
	  MAIL_SEARCH_KEY_UNDELETED,  /* messages with no flag \Deleted */
	  MAIL_SEARCH_KEY_UNFLAGGED,  /* messages with no flag \Flagged */
	  MAIL_SEARCH_KEY_UNSEEN,     /* messages with no flag \Seen */
	  MAIL_SEARCH_KEY_HEADER,     /* messages whose given field 
	                                 contains the given string */
	  MAIL_SEARCH_KEY_LARGER,     /* messages whose size is larger then
	                                 the given size */
	  MAIL_SEARCH_KEY_NOT,        /* not operation of the condition */
	  MAIL_SEARCH_KEY_OR,         /* or operation between two conditions */
	  MAIL_SEARCH_KEY_SMALLER,    /* messages whose size is smaller than
	                                 the given size */
	  MAIL_SEARCH_KEY_MULTIPLE    /* the boolean operator between the
	                                 conditions is AND */
	}

	struct mailsession_driver {
	  char * sess_name;
	  int function(mailsession * session) sess_initialize;
	  void function(mailsession * session) sess_uninitialize;
	  int function(mailsession * session, int id, void * value) sess_parameters;
	  int function(mailsession * session, mailstream * s) sess_connect_stream;
	  int function(mailsession * session, const char * path) sess_connect_path;
	  int function(mailsession * session) sess_starttls;
	  int function(mailsession * session, const char * userid, const char * password) sess_login;
	  int function(mailsession * session) sess_logout;
	  int function(mailsession * session) sess_noop;
	  int function(mailsession * session, const char * mb, const char * name, char ** result) sess_build_folder_name;
	  int function(mailsession * session, const char * mb) sess_create_folder;
	  int function(mailsession * session, const char * mb) sess_delete_folder;
	  int function(mailsession * session, const char * mb, const char * new_name) sess_rename_folder;
	  int function(mailsession * session) sess_check_folder;
	  int function(mailsession * session, const char * mb) sess_examine_folder;
	  int function(mailsession * session, const char * mb) sess_select_folder;
	  int function(mailsession * session) sess_expunge_folder;
	  int function(mailsession * session, const char * mb, uint32_t * result_num, uint32_t * result_recent, uint32_t * result_unseen) sess_status_folder;
	  int function(mailsession * session, const char * mb, uint32_t * result) sess_messages_number;
	  int function(mailsession * session, const char * mb, uint32_t * result) sess_recent_number;
	  int function(mailsession * session, const char * mb, uint32_t * result) sess_unseen_number;
	  int function(mailsession * session, const char * mb, mail_list ** result) sess_list_folders;
	  int function(mailsession * session, const char * mb, mail_list ** result) sess_lsub_folders;
	  int function(mailsession * session, const char * mb) sess_subscribe_folder;
	  int function(mailsession * session, const char * mb) sess_unsubscribe_folder;
	  int function(mailsession * session, const char * message, size_t size) sess_append_message;
	  int function(mailsession * session, const char * message, size_t size, mail_flags * flags) sess_append_message_flags;
	  int function(mailsession * session, uint32_t num, const char * mb) sess_copy_message;
	  int function(mailsession * session, uint32_t num, const char * mb) sess_move_message;
	  int function(mailsession * session, uint32_t num, mailmessage ** result) sess_get_message;
	  int function(mailsession * session, const char * uid, mailmessage ** result) sess_get_message_by_uid;
	  int function(mailsession * session,  mailmessage_list ** result) sess_get_messages_list;
	  int function(mailsession * session,  mailmessage_list * env_list) sess_get_envelopes_list;
	  int function(mailsession * session, uint32_t num) sess_remove_message;
	  int function(mailsession * session, const char * auth_type, const char * server_fqdn, const char * local_ip_port, const char * remote_ip_port, const char * login, const char * auth_name, const char * password, const char * realm) sess_login_sasl;
	}


	struct mailsession {
	  void * sess_data;
	  mailsession_driver * sess_driver;
	}

	struct mailmessage_driver
	{
	    char * msg_name;
	    int function(mailmessage * msg_info) msg_initialize;
	    void function(mailmessage * msg_info) msg_uninitialize;
	    void function(mailmessage * msg_info) msg_flush;
	    void function(mailmessage * msg_info) msg_check;
	    void function(mailmessage * msg_info, char * msg) msg_fetch_result_free;
	    int function(mailmessage * msg_info, char ** result, size_t * result_len) msg_fetch;
		int function(mailmessage * msg_info, char ** result, size_t * result_len) msg_fetch_header;
	    int function(mailmessage * msg_info, char ** result, size_t * result_len) msg_fetch_body;
		int function(mailmessage * msg_info, size_t * result) msg_fetch_size;
	    int function(mailmessage * msg_info, mailmime ** result) msg_get_bodystructure;
	    int function(mailmessage * msg_info, mailmime * mime, char ** result, size_t * result_len) msg_fetch_section;
	    int function(mailmessage * msg_info, mailmime * mime, char ** result, size_t * result_len) msg_fetch_section_header;
	    int function(mailmessage * msg_info, mailmime * mime, char ** result, size_t * result_len) msg_fetch_section_mime;
	    int function(mailmessage * msg_info, mailmime * mime, char ** result, size_t * result_len) msg_fetch_section_body;
		int function(mailmessage * msg_info, mailimf_fields ** result) msg_fetch_envelope;
	  	int function(mailmessage * msg_info, mail_flags ** result) msg_get_flags;
	}

	struct mailmessage {
	  mailsession * msg_session;
	  mailmessage_driver * msg_driver;
	  uint32_t msg_index;
	  char * msg_uid;
	  size_t msg_size;
	  mailimf_fields * msg_fields;
	  mail_flags * msg_flags;
	  int msg_resolved;
	  mailimf_single_fields msg_single_fields;
	  mailmime * msg_mime;
	  int msg_cached;
	  void * msg_data;
	  void * msg_folder;
	  void * msg_user_data;
	}


	struct mailmessage_tree {
	  mailmessage_tree * node_parent;
	  char * node_msgid;
	  time_t node_date;
	  mailmessage * node_msg;
	  carray * node_children; /* array of (struct mailmessage_tree *) */
	  int node_is_reply;
	  char * node_base_subject;
	}

	mailmessage_tree * mailmessage_tree_new(char * node_msgid, time_t node_date, mailmessage * node_msg);
	void mailmessage_tree_free(mailmessage_tree *tree);
	void mailmessage_tree_free_recursive(mailmessage_tree * tree);

	struct generic_message_t {
	  int function(mailmessage * msg_info) msg_prefetch;
	  void function(generic_message_t * msg) * msg_prefetch_free;
	  int msg_fetched;
	  char * msg_message;
	  size_t msg_length;
	  void * msg_data;
	};

	char * maildriver_strerror(int err);
	void *libetpan_malloc(size_t length);
	void libetpan_free(void* data);
	
	int mailstorage_generic_connect(mailsession_driver * driver, char * servername, uint16_t port, char * command, int connection_type, int cache_function_id, char * cache_directory, int flags_function_id, char * flags_directory, mailsession ** result);
	int mailstorage_generic_connect_with_local_address(mailsession_driver * driver, char * servername, uint16_t port, char * local_address, uint16_t local_port, char * command, int connection_type, int cache_function_id, char * cache_directory, int flags_function_id, char * flags_directory, mailsession ** result);
	int mailstorage_generic_auth(mailsession * session, int connect_result, int auth_type, char * login, char * password);
	int mailstorage_generic_auth_sasl(mailsession * session, int connect_result, const char * auth_type, const char * server_fqdn, const char * local_ip_port, const char * remote_ip_port, const char * login, const char * auth_name, const char * password, const char * realm);

	mailstorage * mailstorage_new(const char * sto_id);
	void mailstorage_free(mailstorage * storage);
	int mailstorage_connect(mailstorage * storage);
	void mailstorage_disconnect(mailstorage * storage);
	int mailstorage_noop(mailstorage * storage);
	 mailfolder * mailfolder_new( mailstorage * fld_storage, const char * fld_pathname, const char * fld_virtual_name);
	void mailfolder_free( mailfolder * folder);
	int mailfolder_add_child( mailfolder * parent,  mailfolder * child);
	int mailfolder_detach_parent( mailfolder * folder);
	int mailfolder_connect( mailfolder * folder);
	void mailfolder_disconnect( mailfolder * folder);
	mailsession * mailsession_new(mailsession_driver * sess_driver);
	 void mailsession_free(mailsession * session);
	 int mailsession_parameters(mailsession * session, int id, void * value);
	 int mailsession_connect_stream(mailsession * session, mailstream * s);
	 int mailsession_connect_path(mailsession * session, const char * path);
	 int mailsession_starttls(mailsession * session);
	 int mailsession_login(mailsession * session, const char * userid, const char * password);
	 int mailsession_logout(mailsession * session);
	 int mailsession_noop(mailsession * session);
	 int mailsession_build_folder_name(mailsession * session, const char * mb, const char * name, char ** result);
	 int mailsession_create_folder(mailsession * session, const char * mb);
	 int mailsession_delete_folder(mailsession * session, const char * mb);
	 int mailsession_rename_folder(mailsession * session, const char * mb, const char * new_name);
	int mailsession_check_folder(mailsession * session);
	 int mailsession_examine_folder(mailsession * session, const char * mb);
	 int mailsession_select_folder(mailsession * session, const char * mb);
	 int mailsession_expunge_folder(mailsession * session);
	 int mailsession_status_folder(mailsession * session, const char * mb, uint32_t * result_messages, uint32_t * result_recent, uint32_t * result_unseen);
	 int mailsession_messages_number(mailsession * session, const char * mb, uint32_t * result);
	 int mailsession_recent_number(mailsession * session, const char * mb, uint32_t * result);
	 int mailsession_unseen_number(mailsession * session, const char * mb, uint32_t * result);
	 int mailsession_list_folders(mailsession * session, const char * mb, mail_list ** result);
	 int mailsession_lsub_folders(mailsession * session, const char * mb, mail_list ** result);
	 int mailsession_subscribe_folder(mailsession * session, const char * mb);
	 int mailsession_unsubscribe_folder(mailsession * session, const char * mb);
	int mailsession_append_message(mailsession * session, const char * message, size_t size);
	int mailsession_append_message_flags(mailsession * session, const char * message, size_t size, mail_flags * flags);
	 int mailsession_copy_message(mailsession * session, uint32_t num, const char * mb);
	 int mailsession_move_message(mailsession * session, uint32_t num, const char * mb);
	 int mailsession_get_messages_list(mailsession * session, mailmessage_list ** result);
	 int mailsession_get_envelopes_list(mailsession * session, mailmessage_list * result);
	 int mailsession_remove_message(mailsession * session, uint32_t num);
	 int mailsession_get_message(mailsession * session, uint32_t num, mailmessage ** result);
	int mailsession_get_message_by_uid(mailsession * session, const char * uid, mailmessage ** result);
	 int mailsession_login_sasl(mailsession * session, const char * auth_type, const char * server_fqdn, const char * local_ip_port, const char * remote_ip_port, const char * login, const char * auth_name, const char * password, const char * realm);
	int mailmessage_generic_initialize(mailmessage * msg_info);
	void mailmessage_generic_uninitialize(mailmessage * msg_info);
	void mailmessage_generic_flush(mailmessage * msg_info);
	void mailmessage_generic_fetch_result_free(mailmessage * msg_info, char * msg);
	int mailmessage_generic_fetch(mailmessage * msg_info, char ** result, size_t * result_len);
	int mailmessage_generic_fetch_header(mailmessage * msg_info, char ** result, size_t * result_len);
	int mailmessage_generic_fetch_body(mailmessage * msg_info, char ** result, size_t * result_len);
	int mailmessage_generic_get_bodystructure(mailmessage * msg_info, mailmime ** result);
	int mailmessage_generic_fetch_section(mailmessage * msg_info, mailmime * mime, char ** result, size_t * result_len);
	int mailmessage_generic_fetch_section_header(mailmessage * msg_info, mailmime * mime, char ** result, size_t * result_len);
	int mailmessage_generic_fetch_section_mime(mailmessage * msg_info, mailmime * mime, char ** result, size_t * result_len);
	int mailmessage_generic_fetch_section_body(mailmessage * msg_info, mailmime * mime, char ** result, size_t * result_len);
	int mailmessage_generic_fetch_envelope(mailmessage * msg_info, mailimf_fields ** result);
	int maildriver_generic_get_envelopes_list(mailsession * session, mailmessage_list * env_list);
	int maildriver_env_list_to_msg_list(mailmessage_list * env_list, clist ** result);
	int maildriver_imf_error_to_mail_error(int error);
	char * maildriver_quote_mailbox(const char * mb);
	int maildriver_env_list_to_msg_list_no_flags( mailmessage_list * env_list, clist ** result);
	int maildriver_cache_clean_up(mail_cache_db * cache_db_env, mail_cache_db * cache_db_flags, mailmessage_list * env_list);
	int maildriver_message_cache_clean_up(char * cache_dir, mailmessage_list * env_list, void function(char *) get_uid_from_filename);
	mailmessage * mailmessage_new();
	void mailmessage_free(mailmessage * info);
	int mailmessage_init(mailmessage * msg_info, mailsession * session, mailmessage_driver * driver, uint32_t indx, size_t size);
	int mailmessage_flush(mailmessage * info);
	int mailmessage_check(mailmessage * info);
	int mailmessage_fetch_result_free(mailmessage * msg_info, char * msg);
	int mailmessage_fetch(mailmessage * msg_info, char ** result, size_t * result_len);
	int mailmessage_fetch_header(mailmessage * msg_info, char ** result, size_t * result_len);
	int mailmessage_fetch_body(mailmessage * msg_info, char ** result, size_t * result_len);
	int mailmessage_fetch_size(mailmessage * msg_info, size_t * result);
	int mailmessage_get_bodystructure(mailmessage * msg_info, mailmime ** result);
	int mailmessage_fetch_section(mailmessage * msg_info, mailmime * mime, char ** result, size_t * result_len);
	int mailmessage_fetch_section_header(mailmessage * msg_info, mailmime * mime, char ** result, size_t * result_len);
	int mailmessage_fetch_section_mime(mailmessage * msg_info, mailmime * mime, char ** result, size_t * result_len);
	int mailmessage_fetch_section_body(mailmessage * msg_info, mailmime * mime, char ** result, size_t * result_len);
	int mailmessage_fetch_envelope(mailmessage * msg_info, mailimf_fields ** result);
	int mailmessage_get_flags(mailmessage * msg_info, mail_flags ** result);
	void mailmessage_resolve_single_fields(mailmessage * msg_info);
	newsnntp * newsnntp_new(size_t nntp_progr_rate, progress_function * nntp_progr_fun);
	void newsnntp_free(newsnntp * session);
	void newsnntp_set_logger(newsnntp * session, void function(newsnntp * session, int log_type, const char * str, size_t size, void * context) logger, void * logger_context);
	void newsnntp_set_progress_callback(newsnntp * f, mailprogress_function * progr_fun, void * context);
	void newsnntp_set_timeout(newsnntp * session, time_t timeout);
	time_t newsnntp_get_timeout(newsnntp * session);
	int newsnntp_connect(newsnntp * session, mailstream * s);
	int newsnntp_quit(newsnntp * session);
	int newsnntp_head(newsnntp * session, uint32_t indx, char ** result, size_t * result_len);
	void newsnntp_head_free(char * str);
	int newsnntp_article(newsnntp * session, uint32_t indx, char ** result, size_t * result_len);
	int newsnntp_article_by_message_id(newsnntp * session, char * msg_id, char ** result, size_t * result_len);
	void newsnntp_article_free(char * str);
	int newsnntp_body(newsnntp * session, uint32_t indx, char ** result, size_t * result_len);
	void newsnntp_body_free(char * str);
	int newsnntp_mode_reader(newsnntp * session);
	int newsnntp_date(newsnntp * session, tm * tm);
	int newsnntp_authinfo_username(newsnntp * session, const char * username);
	int newsnntp_authinfo_password(newsnntp * session, const char * password);
	int newsnntp_post(newsnntp * session, const char * message, size_t size);
	int newsnntp_group(newsnntp * session, const char * groupname, newsnntp_group_info ** info);
	void newsnntp_group_free(newsnntp_group_info * info);
	int newsnntp_list(newsnntp * session, clist ** result);
	void newsnntp_list_free(clist * l);
	int newsnntp_list_overview_fmt(newsnntp * session, clist ** result);
	void newsnntp_list_overview_fmt_free(clist * l);
	int newsnntp_list_active(newsnntp * session, const char * wildmat, clist ** result);
	void newsnntp_list_active_free(clist * l);
	int newsnntp_list_active_times(newsnntp * session, clist ** result);
	void newsnntp_list_active_times_free(clist * l);
	int newsnntp_list_distribution(newsnntp * session, clist ** result);
	void newsnntp_list_distribution_free(clist * l);
	int newsnntp_list_distrib_pats(newsnntp * session, clist ** result);
	void newsnntp_list_distrib_pats_free(clist * l);
	int newsnntp_list_newsgroups(newsnntp * session, const char * pattern, clist ** result);
	void newsnntp_list_newsgroups_free(clist * l);
	int newsnntp_list_subscriptions(newsnntp * session, clist ** result);
	void newsnntp_list_subscriptions_free(clist * l);
	int newsnntp_listgroup(newsnntp * session, const char * group_name, clist ** result);
	void newsnntp_listgroup_free(clist * l);
	int newsnntp_xhdr_single(newsnntp * session, const char * header, uint32_t article, clist ** result);
	int newsnntp_xhdr_range(newsnntp * session, const char * header, uint32_t rangeinf, uint32_t rangesup, clist ** result);
	void newsnntp_xhdr_free(clist * l);
	int newsnntp_xover_single(newsnntp * session, uint32_t article, newsnntp_xover_resp_item ** result);
	int newsnntp_xover_range(newsnntp * session, uint32_t rangeinf, uint32_t rangesup, clist ** result); void xover_resp_item_free(newsnntp_xover_resp_item * n);
	void newsnntp_xover_resp_list_free(clist * l);
	int newsnntp_authinfo_generic(newsnntp * session, const char * authentificator, const char * arguments);

	enum {
	  NEWSNNTP_NO_ERROR = 0,
	  NEWSNNTP_WARNING_REQUEST_AUTHORIZATION_USERNAME=1, /* DEPRECATED, use ERROR instead */
	  NEWSNNTP_ERROR_REQUEST_AUTHORIZATION_USERNAME=1,
	  NEWSNNTP_WARNING_REQUEST_AUTHORIZATION_PASSWORD,
	  NEWSNNTP_ERROR_STREAM,
	  NEWSNNTP_ERROR_UNEXPECTED,
	  NEWSNNTP_ERROR_NO_NEWSGROUP_SELECTED,
	  NEWSNNTP_ERROR_NO_ARTICLE_SELECTED,
	  NEWSNNTP_ERROR_INVALID_ARTICLE_NUMBER,
	  NEWSNNTP_ERROR_ARTICLE_NOT_FOUND,
	  NEWSNNTP_ERROR_UNEXPECTED_RESPONSE,
	  NEWSNNTP_ERROR_INVALID_RESPONSE,
	  NEWSNNTP_ERROR_NO_SUCH_NEWS_GROUP,
	  NEWSNNTP_ERROR_POSTING_NOT_ALLOWED,
	  NEWSNNTP_ERROR_POSTING_FAILED,
	  NEWSNNTP_ERROR_PROGRAM_ERROR,
	  NEWSNNTP_ERROR_NO_PERMISSION,
	  NEWSNNTP_ERROR_COMMAND_NOT_UNDERSTOOD,
	  NEWSNNTP_ERROR_COMMAND_NOT_SUPPORTED,
	  NEWSNNTP_ERROR_CONNECTION_REFUSED,
	  NEWSNNTP_ERROR_MEMORY,
	  NEWSNNTP_ERROR_AUTHENTICATION_REJECTED,
	  NEWSNNTP_ERROR_BAD_STATE,
	  NEWSNNTP_ERROR_SSL,
	  NEWSNNTP_ERROR_AUTHENTICATION_OUT_OF_SEQUENCE,
	};

	struct newsnntp
	{
	  mailstream * nntp_stream;

	  int nntp_readonly;

	  size_t nntp_progr_rate;
	  progress_function * nntp_progr_fun;
	  
	  MMAPString * nntp_stream_buffer;
	  MMAPString * nntp_response_buffer;

	  char * nntp_response;

	  time_t nntp_timeout;
	  
	  void function(newsnntp * session, int log_type, const char * str, size_t size, void * context) nntp_logger;
	  void * nntp_logger_context;
	  
	  mailprogress_function * nntp_progress_fun;
	  void * nntp_progress_context;
	};

	struct newsnntp_group_info
	{
	  char * grp_name;
	  uint32_t grp_first;
	  uint32_t grp_last;
	  uint32_t grp_count;
	  char grp_type;
	};

	struct newsnntp_group_time {
	  char * grp_name;
	  time_t grp_date;
	  char * grp_email;
	};

	struct newsnntp_distrib_value_meaning {
	  char * dst_value;
	  char * dst_meaning;
	};

	struct newsnntp_distrib_default_value {
	  uint32_t dst_weight;
	  char * dst_group_pattern;
	  char * dst_value;
	};

	struct newsnntp_group_description {
	  char * grp_name;
	  char * grp_description;
	};

	struct newsnntp_xhdr_resp_item {
	  uint32_t hdr_article;
	  char * hdr_value;
	};

	struct newsnntp_xover_resp_item {
	  uint32_t ovr_article;
	  char * ovr_subject;
	  char * ovr_author;
	  char * ovr_date;
	  char * ovr_message_id;
	  char * ovr_references;
	  size_t ovr_size;
	  uint32_t ovr_line_count;
	  clist * ovr_others;
	}

	int newsnntp_socket_connect(newsnntp * f, const char * server, uint16_t port);
	int newsnntp_ssl_connect(newsnntp * f, const char * server, uint16_t port);
	int newsnntp_ssl_connect_with_callback(newsnntp * f, const char * server, uint16_t port, void function(mailstream_ssl_context * ssl_context, void * data) callback, void * data);
	int mailpop3_ssl_connect(mailpop3 * f, const char * server, uint16_t port);
	int mailpop3_ssl_connect_with_callback(mailpop3 * f, const char * server, uint16_t port, void function(mailstream_ssl_context * ssl_context, void * data) callback, void * data);

	enum POP3_STRING_SIZE=513;

	mailpop3 * mailpop3_new(size_t pop3_progr_rate, progress_function * pop3_progr_fun);
	void mailpop3_free(mailpop3 * f);
	void mailpop3_set_timeout(mailpop3 * f, time_t timeout);
	time_t mailpop3_get_timeout(mailpop3 * f);
	void mailpop3_set_progress_callback(mailpop3 * f, mailprogress_function * progr_fun, void * context);
	int mailpop3_connect(mailpop3 * f, mailstream * s);
	int mailpop3_quit(mailpop3 * f);
	int mailpop3_apop(mailpop3 * f, const char * user, const char * password);
	int mailpop3_user(mailpop3 * f, const char * user);
	int mailpop3_pass(mailpop3 * f, const char * password);
	int mailpop3_list(mailpop3 * f, carray ** result);
	int mailpop3_retr(mailpop3 * f, uint indx, char ** result, size_t * result_len);
	int mailpop3_top(mailpop3 * f, uint indx, uint count, char ** result, size_t * result_len);
	int mailpop3_dele(mailpop3 * f, uint indx);
	int mailpop3_noop(mailpop3 * f);
	int mailpop3_rset(mailpop3 * f);
	void mailpop3_top_free(char * str);
	void mailpop3_retr_free(char * str);
	int mailpop3_get_msg_info(mailpop3 * f, uint indx, mailpop3_msg_info ** result);
	int mailpop3_capa(mailpop3 * f, clist ** result);
	void mailpop3_capa_resp_free(clist * capa_list);
	int mailpop3_stat(mailpop3 * f, mailpop3_stat_response ** result);
	void mailpop3_stat_resp_free(mailpop3_stat_response * stat_result);
	int mailpop3_stls(mailpop3 * f);
	int mailpop3_auth(mailpop3 * f, const char * auth_type, const char * server_fqdn, const char * local_ip_port, const char * remote_ip_port, const char * login, const char * auth_name, const char * password, const char * realm);
	void mailpop3_set_logger(mailpop3 * session, void function(mailpop3 * session, int log_type, const char * str, size_t size, void * context) logger, void * logger_context);

	enum {
	  MAILPOP3_NO_ERROR = 0,
	  MAILPOP3_ERROR_BAD_STATE,
	  MAILPOP3_ERROR_UNAUTHORIZED,
	  MAILPOP3_ERROR_STREAM,
	  MAILPOP3_ERROR_DENIED,
	  MAILPOP3_ERROR_BAD_USER,
	  MAILPOP3_ERROR_BAD_PASSWORD,
	  MAILPOP3_ERROR_CANT_LIST,
	  MAILPOP3_ERROR_NO_SUCH_MESSAGE,
	  MAILPOP3_ERROR_MEMORY,
	  MAILPOP3_ERROR_CONNECTION_REFUSED,
	  MAILPOP3_ERROR_APOP_NOT_SUPPORTED,
	  MAILPOP3_ERROR_CAPA_NOT_SUPPORTED,
	  MAILPOP3_ERROR_STLS_NOT_SUPPORTED,
	  MAILPOP3_ERROR_SSL,
	  MAILPOP3_ERROR_QUIT_FAILED
	};

	struct mailpop3
	{
	  char * pop3_response;               /* response message */
	  char * pop3_timestamp;              /* connection timestamp */
	  
	  /* internals */
	  mailstream * pop3_stream;
	  size_t pop3_progr_rate;
	  progress_function * pop3_progr_fun;

	  MMAPString * pop3_stream_buffer;        /* buffer for lines reading */
	  MMAPString * pop3_response_buffer;      /* buffer for responses */

	  carray * pop3_msg_tab;               /* list of pop3_msg_info structures */
	  int pop3_state;                        /* state */

	  uint pop3_deleted_count;
	  
	  struct pop3_sasl_t {
	    void * sasl_conn;
	    const char * sasl_server_fqdn;
	    const char * sasl_login;
	    const char * sasl_auth_name;
	    const char * sasl_password;
	    const char * sasl_realm;
	    void * sasl_secret;
	  }
	  pop3_sasl_t pop3_sasl;
	  time_t pop3_timeout;
	  mailprogress_function * pop3_progress_fun;
	  void * pop3_progress_context;
	  
	  void function(mailpop3 * session, int log_type, const char * str, size_t size, void * context) pop3_logger;
	  void * pop3_logger_context;
	};

	struct mailpop3_msg_info
	{
	  uint msg_index;
	  uint32_t msg_size;
	  char * msg_uidl;
	  int msg_deleted;
	};


	struct mailpop3_capa_t {
	  char * cap_name;
	  clist * cap_param; /* (char *) */
	}


	struct mailpop3_stat_response  {
	  uint msgs_count;
	  size_t msgs_size;
	}

	
	int mailpop3_socket_connect(mailpop3 * f, const char * server, uint16_t port);
	int mailpop3_socket_starttls(mailpop3 * f);
	int mailpop3_socket_starttls_with_callback(mailpop3 * f, void function(mailstream_ssl_context * ssl_context, void * data)  callback);
	int mailpop3_login_apop(mailpop3 * f, const char * user, const char * password);
	int mailpop3_login(mailpop3 * f, const char * user, const char * password);
	int mailpop3_header(mailpop3 * f, uint32_t indx, char ** result, size_t * result_len);
	void mailpop3_header_free(char * str);
	int mailmime_transfer_encoding_get(mailmime_fields * fields);
	mailmime_disposition * mailmime_disposition_new_filename(int type, char * filename);
	mailmime_fields * mailmime_fields_new_empty();
	int mailmime_fields_add(mailmime_fields * fields, mailmime_field * field);
	mailmime_fields * mailmime_fields_new_with_data(mailmime_mechanism * encoding, char * id, char * description, mailmime_disposition * disposition, mailmime_language * language);
	mailmime_fields * mailmime_fields_new_with_version(mailmime_mechanism * encoding, char * id, char * description,				  mailmime_disposition * disposition,  mailmime_language * language);
	mailmime_content * mailmime_get_content_message();
	mailmime_content * mailmime_get_content_text();
	
	//alias mailmime_content_new_with_str= mailmime_get_content;
	mailmime_data * mailmime_data_new_data(int encoding, int encoded, const char * data, size_t length);
	mailmime_data * mailmime_data_new_file(int encoding, int encoded, char * filename);
	char * mailmime_content_charset_get(mailmime_content * content);
	char * mailmime_content_param_get(mailmime_content * content, char * name);
	int mailmime_parse(const char * message, size_t length, size_t * indx, mailmime ** result);
	int mailmime_get_section(mailmime * mime, mailmime_section * section, mailmime ** result);
	char * mailmime_extract_boundary(mailmime_content * content_type);
	int mailmime_base64_body_parse(const char * message, size_t length, size_t * indx, char ** result, size_t * result_len);
	int mailmime_quoted_printable_body_parse(const char * message, size_t length, size_t * indx, char ** result, size_t * result_len, int in_header);
	int mailmime_binary_body_parse(const char * message, size_t length, size_t * indx, char ** result, size_t * result_len);
	int mailmime_part_parse(const char * message, size_t length, size_t * indx, int encoding, char ** result, size_t * result_len);
	int mailmime_get_section_id(mailmime * mime, mailmime_section ** result);
	int mailmime_disposition_parse(const char * message, size_t length, size_t * indx, mailmime_disposition ** result);
	int mailmime_disposition_type_parse(const char * message, size_t length, size_t * indx, mailmime_disposition_type ** result);
	int mailmime_disposition_guess_type(const char * message, size_t length, size_t indx);
	int mailmime_fields_write(FILE * f, int * col,  mailmime_fields * fields);
	int mailmime_content_write(FILE * f, int * col, mailmime_content * content);
	int mailmime_content_type_write(FILE * f, int * col, mailmime_content * content);
	int mailmime_write(FILE * f, int * col, mailmime * build_info);
	int mailmime_quoted_printable_write(FILE * f, int * col, int istext, const char * text, size_t size);
	int mailmime_base64_write(FILE * f, int * col, const char * text, size_t size);
	int mailmime_data_write(FILE * f, int * col, mailmime_data * data, int istext);
	int mailmime_content_parse(const char * message, size_t length, size_t * indx, mailmime_content ** result);
	int mailmime_description_parse(const char * message, size_t length, size_t * indx, char ** result);
	int mailmime_location_parse(const char * message, size_t length, size_t * indx, char ** result);
	int mailmime_encoding_parse(const char * message, size_t length, size_t * indx, mailmime_mechanism ** result);
	int mailmime_field_parse(mailimf_optional_field * field, mailmime_field ** result);
	int mailmime_id_parse(const char * message, size_t length, size_t * indx, char ** result);
	int mailmime_fields_parse(mailimf_fields * fields, mailmime_fields ** result);
	int mailmime_version_parse(const char * message, size_t length, size_t * indx, uint32_t * result);
	int mailmime_extension_token_parse(const char * message, size_t length, size_t * indx, char ** result);
	int mailmime_parameter_parse(const char * message, size_t length, size_t * indx, mailmime_parameter ** result);
	int mailmime_value_parse(const char * message, size_t length, size_t * indx, char ** result);
	int mailmime_language_parse(const char * message, size_t length, size_t * indx, mailmime_language ** result);
	int mailmime_fields_write_file(FILE * f, int * col, mailmime_fields * fields);
	int	mailmime_content_write_file(FILE * f, int * col, mailmime_content * content);
	int mailmime_content_type_write_file(FILE * f, int * col, mailmime_content * content);
	int mailmime_write_file(FILE * f, int * col, mailmime * build_info);
	int mailmime_quoted_printable_write_file(FILE * f, int * col, int istext, const char * text, size_t size);
	int mailmime_base64_write_file(FILE * f, int * col, const char * text, size_t size);
	int mailmime_data_write_file(FILE * f, int * col, mailmime_data * data, int istext);
	int mailmime_fields_write(FILE * f, int * col, mailmime_fields * fields);
	int mailmime_content_write(FILE * f, int * col, mailmime_content * content);
	int mailmime_content_type_write(FILE * f, int * col, mailmime_content * content);
	int mailmime_write(FILE * f, int * col, mailmime * build_info);
	int mailmime_quoted_printable_write(FILE * f, int * col, int istext, const char * text, size_t size);
	int mailmime_base64_write(FILE * f, int * col, const char * text, size_t size);
	int mailmime_data_write(FILE * f, int * col, mailmime_data * data, int istext);
	int mailmime_fields_write_mem(MMAPString * f, int * col, mailmime_fields * fields);
	int mailmime_content_write_mem(MMAPString * f, int * col, mailmime_content * content);
	int mailmime_content_type_write_mem(MMAPString * f, int * col, mailmime_content * content);
	int mailmime_write_mem(MMAPString * f, int * col, mailmime * build_info);
	int mailmime_quoted_printable_write_mem(MMAPString * f, int * col, int istext, const char * text, size_t size);
	int mailmime_base64_write_mem(MMAPString * f, int * col, const char * text, size_t size);
	int mailmime_data_write_mem(MMAPString * f, int * col,  mailmime_data * data, int istext);

	enum {
	  MAILMIME_COMPOSITE_TYPE_ERROR,
	  MAILMIME_COMPOSITE_TYPE_MESSAGE,
	  MAILMIME_COMPOSITE_TYPE_MULTIPART,
	  MAILMIME_COMPOSITE_TYPE_EXTENSION
	};

	struct mailmime_composite_type {
	  int ct_type;
	  char * ct_token;
	}


	struct mailmime_content {
	  mailmime_type * ct_type;
	  char * ct_subtype;
	  clist * ct_parameters; /* elements are (struct mailmime_parameter *) */
	}


	enum {
	  MAILMIME_DISCRETE_TYPE_ERROR,
	  MAILMIME_DISCRETE_TYPE_TEXT,
	  MAILMIME_DISCRETE_TYPE_IMAGE,
	  MAILMIME_DISCRETE_TYPE_AUDIO,
	  MAILMIME_DISCRETE_TYPE_VIDEO,
	  MAILMIME_DISCRETE_TYPE_APPLICATION,
	  MAILMIME_DISCRETE_TYPE_EXTENSION
	};

	struct mailmime_discrete_type {
	  int dt_type;
	  char * dt_extension;
	}

	enum {
	  MAILMIME_FIELD_NONE,
	  MAILMIME_FIELD_TYPE,
	  MAILMIME_FIELD_TRANSFER_ENCODING,
	  MAILMIME_FIELD_ID,
	  MAILMIME_FIELD_DESCRIPTION,
	  MAILMIME_FIELD_VERSION,
	  MAILMIME_FIELD_DISPOSITION,
	  MAILMIME_FIELD_LANGUAGE,
	  MAILMIME_FIELD_LOCATION
	}

	struct mailmime_field {
	  int fld_type;
	  union fld_data_t {
	    mailmime_content * fld_content;
	    mailmime_mechanism * fld_encoding;
	    char * fld_id;
	    char * fld_description;
	    uint32_t fld_version;
	    mailmime_disposition * fld_disposition;
	    mailmime_language * fld_language;
	    char * fld_location;
	  }
	  fld_data_t fld_data;
	}

	enum {
	  MAILMIME_MECHANISM_ERROR,
	  MAILMIME_MECHANISM_7BIT,
	  MAILMIME_MECHANISM_8BIT,
	  MAILMIME_MECHANISM_BINARY,
	  MAILMIME_MECHANISM_QUOTED_PRINTABLE,
	  MAILMIME_MECHANISM_BASE64,
	  MAILMIME_MECHANISM_TOKEN
	};

	struct mailmime_mechanism {
	  int enc_type;
	  char * enc_token;
	};


	struct mailmime_fields {
	  clist * fld_list; /* list of (struct mailmime_field *) */
	};


	struct mailmime_parameter {
	  char * pa_name;
	  char * pa_value;
	};

	enum {
	  MAILMIME_TYPE_ERROR,
	  MAILMIME_TYPE_DISCRETE_TYPE,
	  MAILMIME_TYPE_COMPOSITE_TYPE
	};

	struct mailmime_type
	{
	  int tp_type;
	  union tp_data_t
	  {
	    mailmime_discrete_type * tp_discrete_type;
	    mailmime_composite_type * tp_composite_type;
	  }
	  tp_data_t tp_data;
	}

	void mailmime_attribute_free(char * attribute);
	mailmime_composite_type * mailmime_composite_type_new(int ct_type, char * ct_token);
	void mailmime_composite_type_free(mailmime_composite_type * ct);
	mailmime_content * mailmime_content_new(mailmime_type * ct_type, char * ct_subtype, clist * ct_parameters);
	void mailmime_content_free(mailmime_content * content);
	void mailmime_description_free(char * description);
	void mailmime_location_free(char * location);
	mailmime_discrete_type * mailmime_discrete_type_new(int dt_type, char * dt_extension);
	void mailmime_discrete_type_free(mailmime_discrete_type * discrete_type);
	void mailmime_encoding_free(mailmime_mechanism * encoding);
	void mailmime_extension_token_free(char * extension);
	void mailmime_id_free(char * id);
	mailmime_mechanism * mailmime_mechanism_new(int enc_type, char * enc_token);
	void mailmime_mechanism_free(mailmime_mechanism * mechanism);
	mailmime_parameter * mailmime_parameter_new(char * pa_name, char * pa_value);
	void mailmime_parameter_free(mailmime_parameter * parameter);
	void mailmime_subtype_free(char * subtype);
	void mailmime_token_free(char * token);
	mailmime_type * mailmime_type_new(int tp_type,  mailmime_discrete_type * tp_discrete_type,  mailmime_composite_type * tp_composite_type);
	void mailmime_type_free(mailmime_type * type);
	void mailmime_value_free(char * value);

	struct mailmime_language {
	  clist * lg_list; /* atom (char *) */
	};

	
	mailmime_language * mailmime_language_new(clist * lg_list);
	void mailmime_language_free( mailmime_language * lang);
	mailmime_field * mailmime_field_new(int fld_type, mailmime_content * fld_content, mailmime_mechanism * fld_encoding, char * fld_id, char * fld_description, uint32_t fld_version, mailmime_disposition * fld_disposition, mailmime_language * fld_language, char * fld_location);
	void mailmime_field_free(mailmime_field * field);
	mailmime_fields * mailmime_fields_new(clist * fld_list);
	void mailmime_fields_free(mailmime_fields * fields);


	struct mailmime_multipart_body {
	  clist * bd_list;
	};

	mailmime_multipart_body * mailmime_multipart_body_new(clist * bd_list);
	void mailmime_multipart_body_free(mailmime_multipart_body * mp_body);


	enum {
	  MAILMIME_DATA_TEXT,
	  MAILMIME_DATA_FILE
	};

	struct mailmime_data {
	  int dt_type;
	  int dt_encoding;
	  int dt_encoded;
	  union dt_data_t
	  {
	    struct dt_text_t
	    {
	      const char * dt_data;
	      size_t dt_length;
	    }
	    dt_text_t dt_text; 
	    char * dt_filename;
	  }
	  dt_data_t dt_data;
	};

	mailmime_data * mailmime_data_new(int dt_type, int dt_encoding, int dt_encoded, const char * dt_data, size_t dt_length, char * dt_filename);
	void mailmime_data_free(mailmime_data * mime_data);


	enum {
	  MAILMIME_NONE,
	  MAILMIME_SINGLE,
	  MAILMIME_MULTIPLE,
	  MAILMIME_MESSAGE
	};

	struct mailmime {
	  /* parent information */
	  int mm_parent_type;
	  mailmime * mm_parent;
	  clistiter * mm_multipart_pos;

	  int mm_type;
	  const char * mm_mime_start;
	  size_t mm_length;
	  
	  mailmime_fields * mm_mime_fields;
	  mailmime_content * mm_content_type;
	  
	  mailmime_data * mm_body;
	  union mm_data_t
	  {
	    /* single part */
	    mailmime_data * mm_single; /* XXX - was body */
	    
	    /* multi-part */
	    struct mm_multipart_t
	    {
	      mailmime_data * mm_preamble;
	      mailmime_data * mm_epilogue;
	      clist * mm_mp_list;
	    }
	    mm_multipart_t mm_multipart;
	    
	    /* message */
	    struct mm_message_t
	    {
	      mailimf_fields * mm_fields;
	      mailmime * mm_msg_mime;
	    }
	    mm_message_t mm_message;
	    
	  }
	  mm_data_t mm_data;
	};

	
	mailmime * mailmime_new(int mm_type, const char * mm_mime_start, size_t mm_length, mailmime_fields * mm_mime_fields, mailmime_content * mm_content_type, mailmime_data * mm_body, mailmime_data * mm_preamble, mailmime_data * mm_epilogue, clist * mm_mp_list, mailimf_fields * mm_fields, mailmime * mm_msg_mime);
	
	void mailmime_free(mailmime * mime);

	struct mailmime_encoded_word {
	  char * wd_charset;
	  char * wd_text;
	};

	
	mailmime_encoded_word * mailmime_encoded_word_new(char * wd_charset, char * wd_text);
	void mailmime_encoded_word_free(mailmime_encoded_word * ew);
	void mailmime_charset_free(char * charset);
	void mailmime_encoded_text_free(char * text);

	struct mailmime_disposition {
	  mailmime_disposition_type * dsp_type;
	  clist * dsp_parms; /* struct mailmime_disposition_parm */
	};


	enum {
	  MAILMIME_DISPOSITION_TYPE_ERROR,
	  MAILMIME_DISPOSITION_TYPE_INLINE,
	  MAILMIME_DISPOSITION_TYPE_ATTACHMENT,
	  MAILMIME_DISPOSITION_TYPE_EXTENSION
	};

	struct mailmime_disposition_type {
	  int dsp_type;
	  char * dsp_extension;
	};


	enum {
	  MAILMIME_DISPOSITION_PARM_FILENAME,
	  MAILMIME_DISPOSITION_PARM_CREATION_DATE,
	  MAILMIME_DISPOSITION_PARM_MODIFICATION_DATE,
	  MAILMIME_DISPOSITION_PARM_READ_DATE,
	  MAILMIME_DISPOSITION_PARM_SIZE,
	  MAILMIME_DISPOSITION_PARM_PARAMETER
	};

	struct mailmime_disposition_parm {
	  int pa_type;
	  union pa_data_t
	  {
	    char * pa_filename;
	    char * pa_creation_date;
	    char * pa_modification_date;
	    char * pa_read_date;
	    size_t pa_size;
	    mailmime_parameter * pa_parameter;
	  }
	  pa_data_t pa_data;
	}

	mailmime_disposition * mailmime_disposition_new(mailmime_disposition_type * dsp_type, clist * dsp_parms);
	void mailmime_disposition_free(mailmime_disposition * dsp);
	mailmime_disposition_type * mailmime_disposition_type_new(int dt_type, char * dt_extension);
	void mailmime_disposition_type_free(mailmime_disposition_type * dsp_type);
	mailmime_disposition_parm * mailmime_disposition_parm_new(int pa_type, char * pa_filename, char * pa_creation_date, char * pa_modification_date,
				      char * pa_read_date, size_t pa_size, mailmime_parameter * pa_parameter);

	void mailmime_disposition_parm_free( mailmime_disposition_parm * dsp_parm);
	void mailmime_filename_parm_free(char * filename);
	void mailmime_creation_date_parm_free(char * date);
	void mailmime_modification_date_parm_free(char * date);
	void mailmime_read_date_parm_free(char * date);
	void mailmime_quoted_date_time_free(char * date);

	struct mailmime_section {
	  clist * sec_list; /* list of (uint32 *) */
	};

	
	mailmime_section * mailmime_section_new(clist * list);
	void mailmime_section_free(mailmime_section * section);
	void mailmime_decoded_part_free(char * part);

	struct mailmime_single_fields {
	   mailmime_content * fld_content;
	  char * fld_content_charset;
	  char * fld_content_boundary;
	  char * fld_content_name;
	  mailmime_mechanism * fld_encoding;
	  char * fld_id;
	  char * fld_description;
	  uint32_t fld_version;
	  mailmime_disposition * fld_disposition;
	  char * fld_disposition_filename;
	  char * fld_disposition_creation_date;
	  char * fld_disposition_modification_date;
	  char * fld_disposition_read_date;
	  size_t fld_disposition_size;
	  mailmime_language * fld_language;
	  char * fld_location;
	};

	int mailmime_encoded_phrase_parse(const char * default_fromcode, const char * message, size_t length,
	    size_t * indx, const char * tocode, char ** result);

	int mailmime_encoded_word_parse(const char * message, size_t length, size_t * indx, mailmime_encoded_word ** result,
	                            int * p_has_fwd);


	int mailmime_fields_write_driver(int function(void *, const char *, size_t) do_write, void * data, int * col, mailmime_fields * fields);
	int mailmime_content_write_driver(int function(void *, const char *, size_t) do_write, void * data, int * col, mailmime_content * content);
	int mailmime_content_type_write_driver(int function(void *, const char *, size_t) do_write, void * data, int * col, mailmime_content * content);
	int mailmime_write_driver(int function(void *, const char *, size_t) do_write, void * data, int * col, mailmime * build_info);
	int mailmime_quoted_printable_write_driver(int function(void *, const char *, size_t) do_write, void * data, int * col, int istext, const char * text, size_t size);
	int mailmime_base64_write_driver(int function(void *, const char *, size_t) do_write, void * data, int * col, const char * text, size_t size);
	int mailmime_data_write_driver(int function(void *, const char *, size_t) do_write, void * data, int * col, mailmime_data * mime_data, int istext);

	enum {
	  MAILMH_NO_ERROR = 0,
	  MAILMH_ERROR_FOLDER,
	  MAILMH_ERROR_MEMORY,
	  MAILMH_ERROR_FILE,
	  MAILMH_ERROR_COULD_NOT_ALLOC_MSG,
	  MAILMH_ERROR_RENAME,
	  MAILMH_ERROR_MSG_NOT_FOUND
	};

	struct mailmh {
	   mailmh_folder * mh_main;
	};

	struct mailmh_msg_info {
	  uint msg_array_index;
	  uint32_t msg_index;
	  size_t msg_size;
	  time_t msg_mtime;
	};

	struct mailmh_folder {
	  char * fl_filename;
	  uint fl_array_index;

	  char * fl_name;
	  time_t fl_mtime;
	  mailmh_folder * fl_parent;
	  uint32_t fl_max_index;

	  carray * fl_msgs_tab;
	  chash * fl_msgs_hash;

	  carray * fl_subfolders_tab;
	  chash * fl_subfolders_hash;
	};

	mailmh * mailmh_new(const char * foldername);
	void mailmh_free(mailmh * f);

	mailmh_msg_info * mailmh_msg_info_new(uint32_t indx, size_t size, time_t mtime);
	void mailmh_msg_info_free( mailmh_msg_info * msg_info);

	mailmh_folder * mailmh_folder_new(mailmh_folder * parent, const char * name);
	void mailmh_folder_free( mailmh_folder * folder);
	int mailmh_folder_add_subfolder( mailmh_folder * parent, const char * name);
	mailmh_folder * mailmh_folder_find(mailmh_folder * root, const char * filename);
	int mailmh_folder_remove_subfolder( mailmh_folder * folder);
	int mailmh_folder_rename_subfolder(mailmh_folder * src_folder, mailmh_folder * dst_folder, const char * new_name);
	int mailmh_folder_get_message_filename(mailmh_folder * folder, uint32_t indx, char ** result);
	int mailmh_folder_get_message_fd( mailmh_folder * folder, uint32_t indx, int flags, int * result);
	int mailmh_folder_get_message_size(mailmh_folder * folder, uint32_t indx, size_t * result);
	int mailmh_folder_add_message_uid( mailmh_folder * folder, const char * message, size_t size, uint32_t * pindex);
	int mailmh_folder_add_message( mailmh_folder * folder, const char * message, size_t size);
	int mailmh_folder_add_message_file_uid( mailmh_folder * folder, int fd, uint32_t * pindex);
	int mailmh_folder_add_message_file( mailmh_folder * folder, int fd);
	int mailmh_folder_remove_message( mailmh_folder * folder, uint32_t indx);
	int mailmh_folder_move_message( mailmh_folder * dest_folder, mailmh_folder * src_folder, uint32_t indx);
	int mailmh_folder_update(mailmh_folder * folder);
	uint mailmh_folder_get_message_number( mailmh_folder * folder);
	int mailmbox_append_message_list( mailmbox_folder * folder, carray * append_tab);
	int mailmbox_append_message( mailmbox_folder * folder, const char * data, size_t len);
	int mailmbox_append_message_uid( mailmbox_folder * folder, const char * data, size_t len, uint * puid);
	int mailmbox_fetch_msg(mailmbox_folder * folder, uint32_t num, char ** result, size_t * result_len);
	int mailmbox_fetch_msg_headers( mailmbox_folder * folder, uint32_t num, char ** result, size_t * result_len);
	void mailmbox_fetch_result_free(char * msg);
	int mailmbox_copy_msg_list( mailmbox_folder * dest_folder,  mailmbox_folder * src_folder, carray * tab);
	int mailmbox_copy_msg( mailmbox_folder * dest_folder, mailmbox_folder * src_folder, uint32_t uid);
	int mailmbox_expunge( mailmbox_folder * folder);
	int mailmbox_delete_msg(mailmbox_folder * folder, uint32_t uid);
	int mailmbox_init(const char * filename, int force_readonly, int force_no_uid, uint32_t default_written_uid, mailmbox_folder ** result_folder);
	void mailmbox_done( mailmbox_folder * folder);
	int mailmbox_write_lock( mailmbox_folder * folder);
	int mailmbox_write_unlock( mailmbox_folder * folder);
	int mailmbox_read_lock( mailmbox_folder * folder);
	int mailmbox_read_unlock( mailmbox_folder * folder);
	int mailmbox_map( mailmbox_folder * folder);
	void mailmbox_unmap( mailmbox_folder * folder);
	void mailmbox_sync( mailmbox_folder * folder);
	int mailmbox_open( mailmbox_folder * folder);
	void mailmbox_close(mailmbox_folder * folder);
	int mailmbox_validate_write_lock( mailmbox_folder * folder);
	int mailmbox_validate_read_lock( mailmbox_folder * folder);
	int mailmbox_fetch_msg_no_lock( mailmbox_folder * folder, uint32_t num, char ** result, size_t * result_len);
	int mailmbox_fetch_msg_headers_no_lock( mailmbox_folder * folder, uint32_t num, char ** result, size_t * result_len);
	int mailmbox_append_message_list_no_lock( mailmbox_folder * folder, carray * append_tab);
	int mailmbox_expunge_no_lock( mailmbox_folder * folder);
	int mailmbox_parse(mailmbox_folder * folder);
	int mailmbox_parse_additionnal( mailmbox_folder * folder, size_t * indx);

	enum {
	  MAILMBOX_NO_ERROR = 0,
	  MAILMBOX_ERROR_PARSE,
	  MAILMBOX_ERROR_INVAL,
	  MAILMBOX_ERROR_FILE_NOT_FOUND,
	  MAILMBOX_ERROR_MEMORY,
	  MAILMBOX_ERROR_TEMPORARY_FILE,
	  MAILMBOX_ERROR_FILE,
	  MAILMBOX_ERROR_MSG_NOT_FOUND,
	  MAILMBOX_ERROR_READONLY
	};


	struct mailmbox_folder {
	  char mb_filename[PATH_MAX];

	  time_t mb_mtime;

	  int mb_fd;
	  int mb_read_only;
	  int mb_no_uid;

	  int mb_changed;
	  uint mb_deleted_count;
	  
	  char * mb_mapping;
	  size_t mb_mapping_size;

	  uint32_t mb_written_uid;
	  uint32_t mb_max_uid;

	  chash * mb_hash;
	  carray * mb_tab;
	};

	mailmbox_folder * mailmbox_folder_new(const char * mb_filename);
	void mailmbox_folder_free(mailmbox_folder * folder);


	struct mailmbox_msg_info {
	  uint msg_index;
	  uint32_t msg_uid;
	  int msg_written_uid;
	  int msg_deleted;

	  size_t msg_start;
	  size_t msg_start_len;

	  size_t msg_headers;
	  size_t msg_headers_len;

	  size_t msg_body;
	  size_t msg_body_len;

	  size_t msg_size;

	  size_t msg_padding;
	};


	int mailmbox_msg_info_update(mailmbox_folder * folder, size_t msg_start, size_t msg_start_len, size_t msg_headers, size_t msg_headers_len, size_t msg_body, size_t msg_body_len, size_t msg_size, size_t msg_padding, uint32_t msg_uid);
	mailmbox_msg_info * mailmbox_msg_info_new(size_t msg_start, size_t msg_start_len, size_t msg_headers, size_t msg_headers_len, size_t msg_body, size_t msg_body_len, size_t msg_size, size_t msg_padding, uint32_t msg_uid);
	void mailmbox_msg_info_free(mailmbox_msg_info * info);
	struct mailmbox_append_info {
	  const char * ai_message;
	  size_t ai_size;
	  uint ai_uid;
	};

	mailmbox_append_info * mailmbox_append_info_new(const char * ai_message, size_t ai_size);

	void mailmbox_append_info_free(mailmbox_append_info * info);
	enum {
	  MAILSMTP_NO_ERROR = 0,
	  MAILSMTP_ERROR_UNEXPECTED_CODE,
	  MAILSMTP_ERROR_SERVICE_NOT_AVAILABLE,
	  MAILSMTP_ERROR_STREAM,
	  MAILSMTP_ERROR_HOSTNAME,
	  MAILSMTP_ERROR_NOT_IMPLEMENTED,
	  MAILSMTP_ERROR_ACTION_NOT_TAKEN,
	  MAILSMTP_ERROR_EXCEED_STORAGE_ALLOCATION,
	  MAILSMTP_ERROR_IN_PROCESSING,
	  MAILSMTP_ERROR_INSUFFICIENT_SYSTEM_STORAGE,
	  MAILSMTP_ERROR_MAILBOX_UNAVAILABLE,
	  MAILSMTP_ERROR_MAILBOX_NAME_NOT_ALLOWED,
	  MAILSMTP_ERROR_BAD_SEQUENCE_OF_COMMAND,
	  MAILSMTP_ERROR_USER_NOT_LOCAL,
	  MAILSMTP_ERROR_TRANSACTION_FAILED,
	  MAILSMTP_ERROR_MEMORY,
	  MAILSMTP_ERROR_AUTH_NOT_SUPPORTED,
	  MAILSMTP_ERROR_AUTH_LOGIN,
	  MAILSMTP_ERROR_AUTH_REQUIRED,
	  MAILSMTP_ERROR_AUTH_TOO_WEAK,
	  MAILSMTP_ERROR_AUTH_TRANSITION_NEEDED,
	  MAILSMTP_ERROR_AUTH_TEMPORARY_FAILTURE,
	  MAILSMTP_ERROR_AUTH_ENCRYPTION_REQUIRED,
	  MAILSMTP_ERROR_STARTTLS_TEMPORARY_FAILURE,
	  MAILSMTP_ERROR_STARTTLS_NOT_SUPPORTED,
	  MAILSMTP_ERROR_CONNECTION_REFUSED,
	  MAILSMTP_ERROR_AUTH_AUTHENTICATION_FAILED,
	  MAILSMTP_ERROR_SSL
	};

	enum {
	  MAILSMTP_AUTH_NOT_CHECKED = 0,
	  MAILSMTP_AUTH_CHECKED = 1,
	  MAILSMTP_AUTH_CRAM_MD5 = 2,
	  MAILSMTP_AUTH_PLAIN = 4,
	  MAILSMTP_AUTH_LOGIN = 8,
	  MAILSMTP_AUTH_DIGEST_MD5 = 16,
	  MAILSMTP_AUTH_GSSAPI = 32,
	  MAILSMTP_AUTH_SRP = 64,
	  MAILSMTP_AUTH_NTLM = 128,
	  MAILSMTP_AUTH_KERBEROS_V4 = 256
	};

	enum {
	  MAILSMTP_ESMTP = 1,
	  MAILSMTP_ESMTP_EXPN = 2,
	  MAILSMTP_ESMTP_8BITMIME = 4,
	  MAILSMTP_ESMTP_SIZE = 8,
	  MAILSMTP_ESMTP_ETRN = 16,
	  MAILSMTP_ESMTP_STARTTLS = 32,
	  MAILSMTP_ESMTP_DSN = 64,
	  MAILSMTP_ESMTP_PIPELINING = 128
	};

	struct mailsmtp {
	  mailstream * stream;

	  size_t progr_rate;
	  progress_function * progr_fun;

	  char * response;

	  MMAPString * line_buffer;
	  MMAPString * response_buffer;

	  int esmtp;		/* contains flags MAILSMTP_ESMTP_* */
	  int auth;             /* contains flags MAILSMTP_AUTH_* */
	  
	  struct smtp_sasl_t
	  {
	    void * sasl_conn;
	    const char * sasl_server_fqdn;
	    const char * sasl_login;
	    const char * sasl_auth_name;
	    const char * sasl_password;
	    const char * sasl_realm;
	    void * sasl_secret;
	  }
	  smtp_sasl_t smtp_sasl;

	  size_t smtp_max_msg_size;

	  mailprogress_function * smtp_progress_fun;
	  void * smtp_progress_context;
	    
		int response_code;
		
	  time_t smtp_timeout;
	  
	  void function(mailsmtp * session, int log_type, const char * str, size_t size, void * context) smtp_logger;
	  void * smtp_logger_context;
	};

	enum MAILSMTP_DSN_NOTIFY_SUCCESS=1;
	enum MAILSMTP_DSN_NOTIFY_FAILURE=2;
	enum MAILSMTP_DSN_NOTIFY_DELAY   =4;
	enum MAILSMTP_DSN_NOTIFY_NEVER   =8;

	struct esmtp_address {
	  char * address;
	  int notify;
	  char * orcpt;
	};
	int mailsmtp_oauth2_authenticate(mailsmtp * session, const char * auth_user, const char * access_token);
	int mailsmtp_oauth2_outlook_authenticate(mailsmtp * session, const char * auth_user, const char * access_token);
	int mailsmtp_init(mailsmtp * session);
	int mailsmtp_init_with_ip(mailsmtp * session, int useip);
	int mailesmtp_send(mailsmtp * session, const char * from, int return_full, const char * envid, clist * addresses, const char * message, size_t size);
	int mailesmtp_send_quit(mailsmtp * session, const char * from, int return_full, const char * envid, clist * addresses, const char * message, size_t size);
	int mailsmtp_send(mailsmtp * session, const char * from, clist * addresses, const char * message, size_t size);
	clist * esmtp_address_list_new();
	int esmtp_address_list_add(clist * list, char * address, int notify, char * orcpt);
	void esmtp_address_list_free(clist * l);
	clist * smtp_address_list_new();
	int smtp_address_list_add(clist * list, char * address);
	void smtp_address_list_free(clist * l);
	int mailsmtp_socket_connect(mailsmtp * session, const char * server, uint16_t port);
	int mailsmtp_socket_starttls(mailsmtp * session);
	int mailsmtp_socket_starttls_with_callback(mailsmtp * session, void function(mailstream_ssl_context * ssl_context, void * data) callback, void * data);
	mailsmtp * mailsmtp_new(size_t progr_rate, progress_function * progr_fun);
	void mailsmtp_free(mailsmtp * session);
	void mailsmtp_set_timeout(mailsmtp * session, time_t timeout);
	time_t mailsmtp_get_timeout(mailsmtp * session);
	int mailsmtp_connect(mailsmtp * session, mailstream * s);
	int mailsmtp_quit(mailsmtp * session);
	int mailsmtp_auth(mailsmtp * session, const char * user, const char * pass);
	int mailsmtp_auth_type(mailsmtp * session, const char * user, const char * pass, int type);
	int mailsmtp_helo(mailsmtp * session);
	int mailsmtp_helo_with_ip(mailsmtp * session, int useip);
	int mailsmtp_mail(mailsmtp * session, const char * from);
	int mailsmtp_rcpt(mailsmtp * session, const char * to);
	int mailsmtp_data(mailsmtp * session);
	int mailsmtp_data_message(mailsmtp * session, const char * message, size_t size);
	int mailsmtp_data_message_quit(mailsmtp * session, const char * message, size_t size);
	int mailesmtp_ehlo(mailsmtp * session);
	int mailesmtp_ehlo_with_ip(mailsmtp * session, int useip);
	int mailesmtp_mail(mailsmtp * session, const char * from, int return_full, const char * envid);
	int mailesmtp_mail_size(mailsmtp * session, const char * from, int return_full, const char * envid, size_t size);
	int mailesmtp_rcpt(mailsmtp * session, const char * to, int notify, const char * orcpt);
	int mailesmtp_starttls(mailsmtp * session);
	const (char *) mailsmtp_strerror(int errnum); int mailesmtp_auth_sasl(mailsmtp * session, const char * auth_type, const char * server_fqdn, const char * local_ip_port, const char * remote_ip_port, const char * login, const char * auth_name, const char * password, const char * realm);
	int mailsmtp_noop(mailsmtp * session);
	int mailsmtp_reset(mailsmtp * session);
	void mailsmtp_set_progress_callback(mailsmtp * session, mailprogress_function * progr_fun, void * context);
	void mailsmtp_set_logger(mailsmtp * session, void function(mailsmtp * session, int log_type, const char * str, size_t size, void * context) logger, void * logger_context);
	int mailsmtp_ssl_connect(mailsmtp * session, const char * server, uint16_t port);
	int mailsmtp_ssl_connect_with_callback(mailsmtp * session, const char * server, uint16_t port, void function(mailstream_ssl_context * ssl_context, void * data) callback, void * data);
	int mailsmtp_send_command(mailsmtp * f, char * command);
	int mailsmtp_read_response(mailsmtp * session);
	void newsfeed_parser_rss20_start(void * data, const char * el, const char ** attr);
	void newsfeed_parser_rss20_end(void * data, const char * el);
	newsfeed * newsfeed_new();
	void newsfeed_free(newsfeed * feed);
	int newsfeed_get_response_code(newsfeed * feed);
	int newsfeed_set_url(newsfeed * feed, const char * url);
	const (char *) newsfeed_get_url(newsfeed * feed);
	int newsfeed_set_title(newsfeed * feed, const char * title);
	const (char *) newsfeed_get_title(newsfeed * feed);
	int newsfeed_set_description(newsfeed * feed, const char * description);
	const (char *) newsfeed_get_description(newsfeed * feed);
	int newsfeed_set_language(newsfeed * feed, const char * language);
	const (char *) newsfeed_get_language(newsfeed * feed);
	int newsfeed_set_author(newsfeed * feed, const char * author);
	const (char *) newsfeed_get_author(newsfeed * feed);
	int newsfeed_set_generator(newsfeed * feed, const char * generator);
	const (char *) newsfeed_get_generator(newsfeed * feed);
	uint newsfeed_item_list_get_count(newsfeed * feed);
	newsfeed_item * newsfeed_get_item(newsfeed * feed, uint n);
	void newsfeed_set_date(newsfeed * feed, time_t date);
	time_t newsfeed_get_date(newsfeed * feed);
	void newsfeed_set_timeout(newsfeed * feed, uint timeout);
	uint newsfeed_get_timeout(newsfeed * feed);
	int newsfeed_add_item(newsfeed * feed, newsfeed_item * item);
	int newsfeed_update(newsfeed * feed, time_t last_update);

	enum {
	  NEWSFEED_NO_ERROR = 0,
	  NEWSFEED_ERROR_CANCELLED,
	  NEWSFEED_ERROR_INTERNAL,
	  NEWSFEED_ERROR_BADURL,
	  NEWSFEED_ERROR_RESOLVE_PROXY,
	  NEWSFEED_ERROR_RESOLVE_HOST,
	  NEWSFEED_ERROR_CONNECT,
	  NEWSFEED_ERROR_STREAM,
	  NEWSFEED_ERROR_PROTOCOL,
	  NEWSFEED_ERROR_PARSE,
	  NEWSFEED_ERROR_ACCESS,
	  NEWSFEED_ERROR_AUTHENTICATION,
	  NEWSFEED_ERROR_FTP,
	  NEWSFEED_ERROR_PARTIAL_FILE,
	  NEWSFEED_ERROR_FETCH,
	  NEWSFEED_ERROR_HTTP,
	  NEWSFEED_ERROR_FILE,
	  NEWSFEED_ERROR_PUT,
	  NEWSFEED_ERROR_MEMORY,
	  NEWSFEED_ERROR_SSL,
	  NEWSFEED_ERROR_LDAP,
	  NEWSFEED_ERROR_UNSUPPORTED_PROTOCOL
	};

	struct newsfeed {
	  char * feed_url;
	  char * feed_title;
	  char * feed_description;
	  char * feed_language;
	  char * feed_author;
	  char * feed_generator;
	  time_t feed_date;
	  carray * feed_item_list;
	  int feed_response_code;
	  
	  uint feed_timeout;
	};

	struct newsfeed_item {
	  char * fi_url;
	  char * fi_title;
	  char * fi_summary;
	  char * fi_text;
	  char * fi_author;
	  char * fi_id;
	  time_t fi_date_published;
	  time_t fi_date_modified;
	  newsfeed * fi_feed; /* owner */
	  newsfeed_item_enclosure * fi_enclosure;
	};

	struct newsfeed_item_enclosure {
	  char * fie_url;
	  char * fie_type;
	  size_t fie_size;
	};


	struct newsfeed_parser_context {
	  uint depth;
	  uint location;
	  MMAPString *str;
	  
	  newsfeed * feed;
	  newsfeed_item * curitem;
	  
	  int error;
	  
	  void * parser;
	}

	time_t newsfeed_rfc822_date_parse(char * text);
	newsfeed_item_enclosure * newsfeed_item_enclosure_new();
	void newsfeed_item_enclosure_free(newsfeed_item_enclosure * enclosure);
	char * newsfeed_item_enclosure_get_url(newsfeed_item_enclosure * enclosure);
	int newsfeed_item_enclosure_set_url(newsfeed_item_enclosure * enclosure, const char * url);
	char * newsfeed_item_enclosure_get_type(newsfeed_item_enclosure * enclosure);
	int newsfeed_item_enclosure_set_type(newsfeed_item_enclosure * enclosure, const char * type);
	size_t newsfeed_item_enclosure_get_size(newsfeed_item_enclosure * enclosure);
	void newsfeed_item_enclosure_set_size(newsfeed_item_enclosure * enclosure, size_t size);
	void newsfeed_parser_set_expat_handlers(newsfeed_parser_context * ctx);
	size_t newsfeed_writefunc(void * ptr, size_t size, size_t nmemb, void * stream);
	const (char *) newsfeed_parser_get_attribute_value(const char ** attr, const char * name);
	void newsfeed_parser_atom03_start(void * data, const char * el, const char ** attr);
	void newsfeed_parser_atom03_end(void * data, const char * el);
	newsfeed_item * newsfeed_item_new(newsfeed * feed);
	void newsfeed_item_free(newsfeed_item * item);
	newsfeed * newsfeed_item_get_feed(newsfeed_item * item);
	const (char *) newsfeed_item_get_url(newsfeed_item * item);
	int newsfeed_item_set_url(newsfeed_item * item, const char * url);
	const (char *) newsfeed_item_get_title( newsfeed_item * item);
	int newsfeed_item_set_title(newsfeed_item * item, const char * title);
	const (char *) newsfeed_item_get_summary( newsfeed_item * item);
	int newsfeed_item_set_summary(newsfeed_item * item, const char * summary);
	const (char *) newsfeed_item_get_text( newsfeed_item * item);
	int newsfeed_item_set_text(newsfeed_item * item, const char * text);
	const (char *) newsfeed_item_get_author( newsfeed_item * item);
	int newsfeed_item_set_author(newsfeed_item * item, const char * author);
	const (char *) newsfeed_item_get_id( newsfeed_item * item);
	int newsfeed_item_set_id(newsfeed_item * item, const char * id);
	time_t newsfeed_item_get_date_published( newsfeed_item * item);
	void newsfeed_item_set_date_published( newsfeed_item * item, time_t date);
	time_t newsfeed_item_get_date_modified( newsfeed_item * item);
	void newsfeed_item_set_date_modified( newsfeed_item * item, time_t date);
	 newsfeed_item_enclosure * newsfeed_item_get_enclosure( newsfeed_item * item);
	void newsfeed_item_set_enclosure( newsfeed_item * item,  newsfeed_item_enclosure * enclosure);
	void newsfeed_parser_rdf_start(void * data, const char * el, const char ** attr);
	void newsfeed_parser_rdf_end(void * data, const char * el);

	enum {
	  FEED_LOC_RDF_NONE,
	  FEED_LOC_RDF_CHANNEL,
	  FEED_LOC_RDF_ITEM
	};
	time_t newsfeed_iso8601_date_parse(char *date);
	void newsfeed_parser_atom10_start(void * data, const char * el, const char ** attr);
	void newsfeed_parser_atom10_end(void * data, const char * el);
	int mailimap_quota_parse(int calling_parser, mailstream * fd, MMAPString * buffer, size_t * indx, mailimap_extension_data ** result, size_t progr_rate, progress_function * progr_fun);
	int mailimap_examine_condstore_optional(mailimap * session, const char * mb, int condstore, uint64_t * p_mod_sequence_value);
	int mailimap_select_condstore_optional(mailimap * session, const char * mb, int condstore, uint64_t * p_mod_sequence_value);
	int mailimap_store_unchangedsince_optional(mailimap * session, mailimap_set * set, int use_unchangedsince, uint64_t mod_sequence_valzer, mailimap_store_att_flags * store_att_flags);
	int mailimap_uid_store_unchangedsince_optional(mailimap * session, mailimap_set * set, int use_unchangedsince, uint64_t mod_sequence_valzer, mailimap_store_att_flags * store_att_flags);
	int mailimap_namespace_extension_parse(int calling_parser, mailstream * fd, MMAPString * buffer, size_t * indx, mailimap_extension_data ** result, size_t progr_rate, progress_function * progr_fun);
	void mailimap_response_print(mailimap_response * resp);
	void mailimap_greeting_print(mailimap_greeting * greeting);
	__gshared mailimap_extension_api mailimap_extension_annotatemore;
	int mailimap_annotatemore_getannotation(mailimap * session, const char * list_mb, mailimap_annotatemore_entry_match_list * entries, mailimap_annotatemore_attrib_match_list * attribs, clist ** result);
	int mailimap_annotatemore_setannotation(mailimap * session, const char * list_mb, mailimap_annotatemore_entry_att_list * en_att, int * result);
	int mailimap_has_annotatemore(mailimap * session);
	int mailimap_compress(mailimap * session);
	int mailimap_has_compress_deflate(mailimap * session);
	__gshared  mailimap_extension_api mailimap_extension_acl;
	int mailimap_acl_setacl(mailimap * session, const char * mailbox, const char * identifier, const char * mod_rights);
	int mailimap_acl_deleteacl(mailimap * session, const char * mailbox, const char * identifier);
	int mailimap_acl_getacl(mailimap * session, const char * mailbox, clist ** result);
	int mailimap_acl_listrights(mailimap * session, const char * mailbox, const char * identifier, mailimap_acl_listrights_data ** result);
	int mailimap_acl_myrights(mailimap * session, const char * mailbox, mailimap_acl_myrights_data ** result);
	int mailimap_has_acl(mailimap * session);
	int mailimap_connect(mailimap * session, mailstream * s);
	int mailimap_append(mailimap * session, const char * mailbox, mailimap_flag_list * flag_list, mailimap_date_time * date_time, const char * literal, size_t literal_size);
	int mailimap_noop(mailimap * session);
	int mailimap_logout(mailimap * session);
	int mailimap_capability(mailimap * session, mailimap_capability_data ** result);
	int mailimap_check(mailimap * session);
	int mailimap_close(mailimap * session);
	int mailimap_expunge(mailimap * session);
	int mailimap_copy(mailimap * session, mailimap_set * set, const char * mb);
	int mailimap_uid_copy(mailimap * session, mailimap_set * set, const char * mb);
	int mailimap_create(mailimap * session, const char * mb);
	int mailimap_delete(mailimap * session, const char * mb);
	int mailimap_examine(mailimap * session, const char * mb);
	int mailimap_fetch(mailimap * session, mailimap_set * set, mailimap_fetch_type * fetch_type, clist ** result);
	int mailimap_uid_fetch(mailimap * session, mailimap_set * set, mailimap_fetch_type * fetch_type, clist ** result);
	void mailimap_fetch_list_free(clist * fetch_list);
	int mailimap_list(mailimap * session, const char * mb, const char * list_mb, clist ** result);
	int mailimap_login(mailimap * session, const char * userid, const char * password);
	int mailimap_authenticate(mailimap * session, const char * auth_type, const char * server_fqdn, const char * local_ip_port, const char * remote_ip_port, const char * login, const char * auth_name, const char * password, const char * realm);
	int mailimap_lsub(mailimap * session, const char * mb, const char * list_mb, clist ** result);
	void mailimap_list_result_free(clist * list);
	int mailimap_rename(mailimap * session, const char * mb, const char * new_name);
	int mailimap_search(mailimap * session, const char * charset, mailimap_search_key * key, clist ** result);
	int mailimap_uid_search(mailimap * session, const char * charset, mailimap_search_key * key, clist ** result);
	int mailimap_search_literalplus(mailimap * session, const char * charset, mailimap_search_key * key, clist ** result);
	int mailimap_uid_search_literalplus(mailimap * session, const char * charset, mailimap_search_key * key, clist ** result);
	void mailimap_search_result_free(clist * search_result);
	int mailimap_select(mailimap * session, const char * mb);
	int mailimap_status(mailimap * session, const char * mb, mailimap_status_att_list * status_att_list, mailimap_mailbox_data_status ** result);
	int mailimap_store(mailimap * session, mailimap_set * set, mailimap_store_att_flags * store_att_flags);
	int mailimap_uid_store(mailimap * session, mailimap_set * set, mailimap_store_att_flags * store_att_flags);
	int mailimap_subscribe(mailimap * session, const char * mb);
	int mailimap_unsubscribe(mailimap * session, const char * mb);
	int mailimap_starttls(mailimap * session);
	mailimap * mailimap_new(size_t imap_progr_rate, progress_function * imap_progr_fun);
	void mailimap_free(mailimap * session);
	int mailimap_send_current_tag(mailimap * session);
	char * mailimap_read_line(mailimap * session);
	int mailimap_parse_response(mailimap * session, mailimap_response ** result);
	void mailimap_set_progress_callback(mailimap * session, mailprogress_function * body_progr_fun, mailprogress_function * items_progr_fun, void * context);
	void mailimap_set_msg_att_handler(mailimap * session, mailimap_msg_att_handler * handler, void * context);
	void mailimap_set_timeout(mailimap * session, time_t timeout);;
	time_t mailimap_get_timeout(mailimap * session);
	void mailimap_set_logger(mailimap * session, void function(mailimap * session, int log_type, const char * str, size_t size, void * context) logger, void * logger_context);

	struct mailimap_quota_quota_resource {
		char * resource_name;
		uint32_t usage;
		uint32_t limit;
	}

	
	mailimap_quota_quota_resource * mailimap_quota_quota_resource_new(char * resource_name, uint32_t usage, uint32_t limit);
	void mailimap_quota_quota_resource_free(mailimap_quota_quota_resource * res);

	struct mailimap_quota_quota_data {
	  char * quotaroot;
	  clist * quota_list;
	  /* list of (struct mailimap_quota_quota_resource *) */
	};

	mailimap_quota_quota_data * mailimap_quota_quota_data_new(char * quotaroot, clist * quota_list);
	void mailimap_quota_quota_data_free(mailimap_quota_quota_data * data);

	struct mailimap_quota_quotaroot_data {
	  char * mailbox;
	  clist * quotaroot_list;
	  /* list of (char *) */
	};

	mailimap_quota_quotaroot_data * mailimap_quota_quotaroot_data_new(char * mailbox, clist * quotaroot_list);
	void mailimap_quota_quotaroot_data_free(mailimap_quota_quotaroot_data * data);

	enum {
	  MAILIMAP_QUOTA_TYPE_QUOTA_DATA,       /* child of mailbox-data */
	  MAILIMAP_QUOTA_TYPE_QUOTAROOT_DATA    /* child of mailbox-data */
	};


	struct mailimap_quota_complete_data {
	  mailimap_quota_quotaroot_data * quotaroot_data;
	  clist * quota_list;
	  /* list of (struct mailimap_quota_quota_data *) */
	};

	mailimap_quota_complete_data * mailimap_quota_complete_data_new(mailimap_quota_quotaroot_data * quotaroot_data, clist * quota_list);
	void mailimap_quota_complete_data_free(mailimap_quota_complete_data * data);
	__gshared mailimap_extension_api mailimap_extension_uidplus;
	int mailimap_uid_expunge(mailimap * session, mailimap_set * set);
	int mailimap_uidplus_copy(mailimap * session, mailimap_set * set, const char * mb, uint32_t * uidvalidity_result, mailimap_set ** source_result, mailimap_set ** dest_result);
	int mailimap_uidplus_uid_copy(mailimap * session, mailimap_set * set, const char * mb, uint32_t * uidvalidity_result, mailimap_set ** source_result, mailimap_set ** dest_result);
	int mailimap_uidplus_append(mailimap * session, const char * mailbox, mailimap_flag_list * flag_list, mailimap_date_time * date_time, const char * literal, size_t literal_size, uint32_t * uidvalidity_result, uint32_t * uid_result);
	int mailimap_uidplus_append_simple(mailimap * session, const char * mailbox, const char * content, size_t size, uint32_t * uidvalidity_result, uint32_t * uid_result);
	int mailimap_has_uidplus(mailimap * session);
	__gshared mailimap_extension_api mailimap_extension_qresync;
	int mailimap_select_qresync(mailimap * session, const char * mb, uint32_t uidvalidity, uint64_t modseq_value, mailimap_set * known_uids, mailimap_set * seq_match_data_sequences, mailimap_set * seq_match_data_uids, clist ** fetch_result, mailimap_qresync_vanished ** p_vanished, uint64_t * p_mod_sequence_value);
	int mailimap_fetch_qresync(mailimap * session, mailimap_set * set, mailimap_fetch_type * fetch_type, uint64_t mod_sequence_value, clist ** fetch_result, mailimap_qresync_vanished ** p_vanished);
	int mailimap_uid_fetch_qresync(mailimap * session, mailimap_set * set, mailimap_fetch_type * fetch_type, uint64_t mod_sequence_value, clist ** fetch_result, mailimap_qresync_vanished ** p_vanished);
	int mailimap_has_qresync(mailimap * session);
	int mailimap_append_send(mailstream * fd, const char * mailbox, mailimap_flag_list * flag_list, mailimap_date_time * date_time, size_t literal_size);
	int mailimap_authenticate_send(mailstream * fd, const char * auth_type);
	int mailimap_authenticate_resp_send(mailstream * fd, const char * base64);
	int mailimap_noop_send(mailstream * fd);
	int mailimap_logout_send(mailstream * fd);
	int mailimap_capability_send(mailstream * fd);
	int mailimap_check_send(mailstream * fd);
	int mailimap_close_send(mailstream * fd);
	int mailimap_expunge_send(mailstream * fd);
	int mailimap_copy_send(mailstream * fd, mailimap_set * set, const char * mb);
	int mailimap_uid_copy_send(mailstream * fd, mailimap_set * set, const char * mb);
	int mailimap_create_send(mailstream * fd, const char * mb);
	int mailimap_delete_send(mailstream * fd, const char * mb);

	int mailimap_examine_send(mailstream * fd, const char * mb, int condstore);
	int mailimap_fetch_send(mailstream * fd, mailimap_set * set, mailimap_fetch_type * fetch_type);
	int mailimap_uid_fetch_send(mailstream * fd,  mailimap_set * set,  mailimap_fetch_type * fetch_type);
	int mailimap_list_send(mailstream * fd, const char * mb, const char * list_mb);
	int mailimap_login_send(mailstream * fd, const char * userid, const char * password);
	int mailimap_lsub_send(mailstream * fd, const char * mb, const char * list_mb);
	int mailimap_rename_send(mailstream * fd, const char * mb, const char * new_name);
	int mailimap_search_send(mailstream * fd, const char * charset,  mailimap_search_key * key);
	int mailimap_uid_search_send(mailstream * fd, const char * charset,  mailimap_search_key * key);
	int mailimap_search_literalplus_send(mailstream * fd, const char * charset, mailimap_search_key * key);
	int mailimap_uid_search_literalplus_send(mailstream * fd, const char * charset, mailimap_search_key * key);
	int mailimap_search_key_send(mailstream * fd, mailimap_search_key * key);
	int mailimap_search_key_literalplus_send(mailstream * fd, mailimap_search_key * key);
	int mailimap_select_send(mailstream * fd, const char * mb, int condstore);
	int mailimap_status_send(mailstream * fd, const char * mb, mailimap_status_att_list * status_att_list);
	int mailimap_store_send(mailstream * fd,  mailimap_set * set, int use_unchangedsince, uint64_t mod_sequence_valzer,  mailimap_store_att_flags * store_att_flags);
	int mailimap_uid_store_send(mailstream * fd, mailimap_set * set, int use_unchangedsince, uint64_t mod_sequence_valzer, mailimap_store_att_flags * store_att_flags);
	int mailimap_subscribe_send(mailstream * fd, const char * mb);
	int mailimap_tag_send(mailstream * fd, const char * tag);
	int mailimap_unsubscribe_send(mailstream * fd, const char * mb);
	int mailimap_crlf_send(mailstream * fd);
	int mailimap_space_send(mailstream * fd);
	int mailimap_literal_send(mailstream * fd, const char * literal, size_t progr_rate, progress_function * progr_fun);
	int mailimap_literal_count_send(mailstream * fd, size_t count);
	int mailimap_literal_data_send(mailstream * fd, const char * literal, size_t len, size_t progr_rate, progress_function * progr_fun);
	int mailimap_literal_data_send_with_context(mailstream * fd, const char * literal, size_t len, mailprogress_function * progr_fun, void * context);
	int mailimap_starttls_send(mailstream * fd);
	int mailimap_token_send(mailstream * fd, const char * atom);
	int mailimap_quoted_send(mailstream * fd, const char * quoted);
	alias mailimap_struct_sender=int function(mailstream * fd, void * data);
	int mailimap_struct_spaced_list_send(mailstream * fd, clist * list, mailimap_struct_sender * sender);
	int mailimap_list_mailbox_send(mailstream * fd, const char * pattern);
	int mailimap_char_send(mailstream * fd, char ch);
	int mailimap_mailbox_send(mailstream * fd, const char * mb);
	int mailimap_astring_send(mailstream * fd, const char * astring);
	int mailimap_set_send(mailstream * fd,  mailimap_set * set);
 	int mailimap_oparenth_send(mailstream * fd);
	int mailimap_cparenth_send(mailstream * fd);
	int mailimap_mod_sequence_value_send(mailstream * fd, uint64_t modseq); 
	int mailimap_uint64_send(mailstream * fd, uint64_t number);
	int mailimap_number_send(mailstream * fd, uint32_t number);
	int mailimap_id_parse(int calling_parser, mailstream * fd, MMAPString * buffer, size_t * indx, mailimap_extension_data ** result, size_t progr_rate, progress_function * progr_fun);
	int mailimap_acl_acl_data_parse(mailstream * fd, MMAPString *buffer, size_t * indx, mailimap_acl_acl_data ** result, size_t progr_rate, progress_function * progr_fun);
	int mailimap_acl_listrights_data_parse(mailstream * fd, MMAPString *buffer, size_t * indx, mailimap_acl_listrights_data ** result, size_t progr_rate, progress_function * progr_fun);
	int mailimap_acl_myrights_data_parse(mailstream * fd, MMAPString *buffer, size_t * indx, mailimap_acl_myrights_data ** result, size_t progr_rate, progress_function * progr_fun);
	int mailimap_acl_identifier_rights_parse(mailstream * fd, MMAPString *buffer, size_t * indx, mailimap_acl_identifier_rights ** result, size_t progr_rate, progress_function * progr_fun);
	int mailimap_acl_identifier_parse(mailstream * fd, MMAPString *buffer, size_t * indx, char ** result, size_t progr_rate, progress_function * progr_fun);
	int mailimap_acl_rights_parse(mailstream * fd, MMAPString *buffer, size_t * indx, char ** result, size_t progr_rate, progress_function * progr_fun);
	int mailimap_acl_parse(int calling_parser, mailstream * fd, MMAPString * buffer, size_t * indx, mailimap_extension_data ** result, size_t progr_rate, progress_function * progr_fun);
	__gshared mailimap_extension_api mailimap_extension_xgmthrid;
	__gshared mailimap_fetch_att * mailimap_fetch_att_new_xgmthrid();
	__gshared mailimap_extension_api mailimap_extension_sort;
	int mailimap_sort(mailimap * session, const char * charset,  mailimap_sort_key * key,  mailimap_search_key * searchkey, clist ** result);
	int mailimap_uid_sort(mailimap * session, const char * charset,  mailimap_sort_key * key,  mailimap_search_key * searchkey, clist ** result);
	void mailimap_sort_result_free(clist * search_result);
	int mailimap_char_parse(mailstream * fd, MMAPString * buffer, size_t * indx, char token);
	int mailimap_space_parse(mailstream * fd, MMAPString * buffer, size_t * indx);
	int mailimap_token_case_insensitive_parse(mailstream * fd, MMAPString * buffer, size_t * indx, const char * token);
	int mailimap_status_att_get_token_value(mailstream * fd, MMAPString * buffer, size_t * indx);
	const (char *) mailimap_status_att_get_token_str(int indx);
	int mailimap_month_get_token_value(mailstream * fd, MMAPString * buffer, size_t * indx);
	const (char *) mailimap_month_get_token_str(int indx);
	int mailimap_flag_get_token_value(mailstream * fd, MMAPString * buffer, size_t * indx);
	const (char *) mailimap_flag_get_token_str(int indx);
	int mailimap_encoding_get_token_value(mailstream * fd, MMAPString * buffer, size_t * indx);
	int mailimap_mbx_list_sflag_get_token_value(mailstream * fd, MMAPString * buffer, size_t * indx);
	int mailimap_media_basic_get_token_value(mailstream * fd, MMAPString * buffer, size_t * indx);
	int mailimap_resp_cond_state_get_token_value(mailstream * fd, MMAPString * buffer, size_t * indx);
	int mailimap_resp_text_code_1_get_token_value(mailstream * fd, MMAPString * buffer, size_t * indx);
	int mailimap_resp_text_code_2_get_token_value(mailstream * fd, MMAPString * buffer, size_t * indx);
	int mailimap_section_msgtext_get_token_value(mailstream * fd, MMAPString * buffer, size_t * indx);

	  
	  enum {
	    MAILIMAP_SORT_KEY_ARRIVAL,
	    MAILIMAP_SORT_KEY_CC,
	    MAILIMAP_SORT_KEY_DATE,
	    MAILIMAP_SORT_KEY_FROM,
	    MAILIMAP_SORT_KEY_SIZE,
	    MAILIMAP_SORT_KEY_SUBJECT,
	    MAILIMAP_SORT_KEY_TO,
	    MAILIMAP_SORT_KEY_MULTIPLE
	  };
	  
	  struct mailimap_sort_key {
	    int sortk_type;
	    int sortk_is_reverse;
	    clist * sortk_multiple; /* list of (struct mailimap_sort_key *) */
	  };
	  
 	mailimap_sort_key * mailimap_sort_key_new(int sortk_type, int is_reverse, clist * sortk_multiple);
 	void mailimap_sort_key_free( mailimap_sort_key * key);
	mailimap_sort_key * mailimap_sort_key_new_arrival(int is_reverse);
	mailimap_sort_key * mailimap_sort_key_new_cc(int is_reverse);
	mailimap_sort_key * mailimap_sort_key_new_date(int is_reverse);
	mailimap_sort_key * mailimap_sort_key_new_from(int is_reverse);
	mailimap_sort_key * mailimap_sort_key_new_size(int is_reverse);
	mailimap_sort_key * mailimap_sort_key_new_subject(int is_reverse);
	mailimap_sort_key * mailimap_sort_key_new_to(int is_reverse);
	mailimap_sort_key * mailimap_sort_key_new_multiple(clist * keys);
	mailimap_sort_key * mailimap_sort_key_new_multiple_empty();
	int mailimap_sort_key_multiple_add( mailimap_sort_key * keys,  mailimap_sort_key * key_item);
	  
	  struct mailimap_msg_att_xgmlabels {
	    clist * att_labels; /* != NULL */
	  };
	  
  
	__gshared mailimap_extension_api mailimap_extension_xgmlabels;
	__gshared mailimap_fetch_att * mailimap_fetch_att_new_xgmlabels();
	int mailimap_has_xgmlabels(mailimap * session);
	__gshared mailimap_msg_att_xgmlabels * mailimap_msg_att_xgmlabels_new(clist * att_labels);
	__gshared mailimap_msg_att_xgmlabels * mailimap_msg_att_xgmlabels_new_empty();
	int mailimap_msg_att_xgmlabels_add(mailimap_msg_att_xgmlabels * att, char * label);
	void mailimap_msg_att_xgmlabels_free(mailimap_msg_att_xgmlabels * att);
	int mailimap_store_xgmlabels(mailimap * session, mailimap_set * set, int fl_sign, int fl_silent,  mailimap_msg_att_xgmlabels * labels);
	int mailimap_uid_store_xgmlabels(mailimap * session,  mailimap_set * set, int fl_sign, int fl_silent, mailimap_msg_att_xgmlabels * labels);
	__gshared mailimap_extension_api mailimap_extension_xlist;
	int mailimap_xlist(mailimap * session, const char * mb, const char * list_mb, clist ** result);
	int mailimap_has_xlist(mailimap * session);
	int mailimap_oauth2_authenticate(mailimap * session, const char * auth_user, const char * access_token);
	int mailimap_has_xoauth2(mailimap * session);
	int mailimap_socket_connect_voip(mailimap * f, const char * server, uint16_t port, int voip_enabled);
	int mailimap_socket_connect(mailimap * f, const char * server, uint16_t port);
	int mailimap_socket_starttls(mailimap * f);
	int mailimap_socket_starttls_with_callback(mailimap * f, void function(mailstream_ssl_context * ssl_context, void * data) callback, void * data);
	__gshared  mailimap_extension_api mailimap_extension_id;
	int mailimap_has_id(mailimap * session);
	int mailimap_id(mailimap * session,  mailimap_id_params_list * client_identification, mailimap_id_params_list ** result);
	int mailimap_id_basic(mailimap * session, const char * name, const char * _version, char ** p_server_name, char ** p_server_version);
	int mailimap_annotatemore_getannotation_send(mailstream * fd, const char * list_mb, mailimap_annotatemore_entry_match_list * entries, mailimap_annotatemore_attrib_match_list * attribs);
	int mailimap_annotatemore_setannotation_send(mailstream * fd, const char * list_mb, mailimap_annotatemore_entry_att_list * en_att);

	struct mailimap_id_params_list {
	  clist * /* struct mailimap_id_param */ idpa_list;
	};

	
	mailimap_id_params_list * mailimap_id_params_list_new(clist * items);
	void mailimap_id_params_list_free(mailimap_id_params_list * list);

	struct mailimap_id_param {
	  char * idpa_name;
	  char * idpa_value;
	};

	
	mailimap_id_param * mailimap_id_param_new(char * name, char * value);
 	void mailimap_id_param_free(mailimap_id_param * param);
 	mailimap_id_params_list * mailimap_id_params_list_new_empty();
 	int mailimap_id_params_list_add_name_value(mailimap_id_params_list * list, char * name, char * value);
 	int mailimap_fetch_rfc822(mailimap * session, uint32_t msgid, char ** result);
 	int mailimap_fetch_rfc822_header(mailimap * session, uint32_t msgid, char ** result);
 	int mailimap_fetch_envelope(mailimap * session, uint32_t first, uint32_t last, clist ** result);
 	int mailimap_append_simple(mailimap * session, const char * mailbox, const char * content, size_t size);
 	int mailimap_login_simple(mailimap * session, const char * userid, const char * password);
	int mailimap_uidplus_parse(int calling_parser, mailstream * fd, MMAPString * buffer, size_t * indx, mailimap_extension_data ** result, size_t progr_rate, progress_function * progr_fun);
 	__gshared mailimap_extension_api mailimap_extension_namespace;
	int mailimap_namespace(mailimap * session, mailimap_namespace_data ** result); 
	int mailimap_has_namespace(mailimap * session);
	int mailimap_acl_setacl_send(mailstream * fd, const char * mailbox, const char * identifier, const char * mod_rights);
	int mailimap_acl_deleteacl_send(mailstream * fd, const char * mailbox, const char * identifier);
	int mailimap_acl_getacl_send(mailstream * fd, const char * mailbox);
	int mailimap_acl_listrights_send(mailstream * fd, const char * mailbox, const char * identifier);
	int mailimap_acl_myrights_send(mailstream * fd, const char * mailbox);
	__gshared mailimap_extension_api mailimap_extension_condstore;
	int mailimap_store_unchangedsince(mailimap * session, mailimap_set * set, uint64_t mod_sequence_valzer, mailimap_store_att_flags * store_att_flags);
	int mailimap_uid_store_unchangedsince(mailimap * session, mailimap_set * set, uint64_t mod_sequence_valzer, mailimap_store_att_flags * store_att_flags);
	int mailimap_fetch_changedsince(mailimap * session, mailimap_set * set, mailimap_fetch_type * fetch_type, uint64_t mod_sequence_value, clist ** result);
	int mailimap_uid_fetch_changedsince(mailimap * session, mailimap_set * set, mailimap_fetch_type * fetch_type, uint64_t mod_sequence_value, clist ** result);
	mailimap_fetch_att * mailimap_fetch_att_new_modseq();
 	int mailimap_search_modseq(mailimap * session, const char * charset,  mailimap_search_key * key, clist ** result, uint64_t * p_mod_sequence_value);
	int mailimap_uid_search_modseq(mailimap * session, const char * charset, mailimap_search_key * key, clist ** result, uint64_t * p_mod_sequence_value);
	int mailimap_search_literalplus_modseq(mailimap * session, const char * charset, mailimap_search_key * key, clist ** result, uint64_t * p_mod_sequence_value);
	int mailimap_uid_search_literalplus_modseq(mailimap * session, const char * charset, mailimap_search_key * key, clist ** result, uint64_t * p_mod_sequence_value);
	int mailimap_select_condstore(mailimap * session, const char * mb, uint64_t * p_mod_sequence_value);
 	int mailimap_examine_condstore(mailimap * session, const char * mb, uint64_t * p_mod_sequence_value);
	int mailimap_has_condstore(mailimap * session);
	
	__gshared mailimap_extension_api mailimap_extension_enable;
	int mailimap_enable(mailimap * session, mailimap_capability_data * capabilities, mailimap_capability_data ** result);
	int mailimap_has_enable(mailimap * session);

	enum {
	  MAILIMAP_ANNOTATEMORE_TYPE_ANNOTATE_DATA,          /* child of response-data   */
	  MAILIMAP_ANNOTATEMORE_TYPE_RESP_TEXT_CODE          /* child of resp-text-code  */
	};

	enum {
	  MAILIMAP_ANNOTATEMORE_RESP_TEXT_CODE_UNSPECIFIED, /* unspecified response   */
	  MAILIMAP_ANNOTATEMORE_RESP_TEXT_CODE_TOOBIG,      /* annotation too big     */
	  MAILIMAP_ANNOTATEMORE_RESP_TEXT_CODE_TOOMANY      /* too many annotations   */
	};

	void mailimap_annotatemore_attrib_free(char * attrib);
	void mailimap_annotatemore_value_free(char * value);
	void mailimap_annotatemore_entry_free(char * entry);

	struct mailimap_annotatemore_att_value  {
	  char * attrib;
	  char * value;
	};

	
	mailimap_annotatemore_att_value * mailimap_annotatemore_att_value_new(char * attrib, char * value);
 	void mailimap_annotatemore_att_value_free(mailimap_annotatemore_att_value * att_value);

	struct mailimap_annotatemore_entry_att {
	  char * entry;
	  clist * att_value_list;
	  /* list of (struct mailimap_annotatemore_att_value *) */
	};

	mailimap_annotatemore_entry_att * mailimap_annotatemore_entry_att_new(char * entry, clist * list);
	void mailimap_annotatemore_entry_att_free(mailimap_annotatemore_entry_att * en_att);
	mailimap_annotatemore_entry_att * mailimap_annotatemore_entry_att_new_empty(char * entry);
	int mailimap_annotatemore_entry_att_add(mailimap_annotatemore_entry_att * en_att, mailimap_annotatemore_att_value * at_value);

	enum {
	  MAILIMAP_ANNOTATEMORE_ENTRY_LIST_TYPE_ERROR,          /* error condition */
	  MAILIMAP_ANNOTATEMORE_ENTRY_LIST_TYPE_ENTRY_ATT_LIST, /* entry-att-list */
	  MAILIMAP_ANNOTATEMORE_ENTRY_LIST_TYPE_ENTRY_LIST      /* entry-list */
	};

	struct mailimap_annotatemore_entry_list {int en_list_type; clist * en_list_data; /* either a list of (struct annotatemore_entry_att *) or a list of (char *) */ };
	mailimap_annotatemore_entry_list * mailimap_annotatemore_entry_list_new(int type, clist * en_att_list, clist * en_list);
	void mailimap_annotatemore_entry_list_free(mailimap_annotatemore_entry_list * en_list);

	struct mailimap_annotatemore_annotate_data {
	  char * mailbox;
	  mailimap_annotatemore_entry_list * entry_list;
	};

	mailimap_annotatemore_annotate_data * mailimap_annotatemore_annotate_data_new(char * mb, mailimap_annotatemore_entry_list * en_list);
	void mailimap_annotatemore_annotate_data_free(mailimap_annotatemore_annotate_data * an_data);

	struct mailimap_annotatemore_entry_match_list {
	  clist * entry_match_list; /* list of (char *) */
	};
	
	mailimap_annotatemore_entry_match_list * mailimap_annotatemore_entry_match_list_new(clist * en_list);
 	void mailimap_annotatemore_entry_match_list_free(mailimap_annotatemore_entry_match_list * en_list);

	struct mailimap_annotatemore_attrib_match_list {
	  clist * attrib_match_list; /* list of (char *) */
	};

	
	mailimap_annotatemore_attrib_match_list * mailimap_annotatemore_attrib_match_list_new(clist * at_list);
	void mailimap_annotatemore_attrib_match_list_free(mailimap_annotatemore_attrib_match_list * at_list);
	mailimap_annotatemore_entry_match_list * mailimap_annotatemore_entry_match_list_new_empty(); int mailimap_annotatemore_entry_match_list_add(mailimap_annotatemore_entry_match_list * en_list, char * entry);
	mailimap_annotatemore_attrib_match_list * mailimap_annotatemore_attrib_match_list_new_empty();
	int mailimap_annotatemore_attrib_match_list_add(mailimap_annotatemore_attrib_match_list * at_list, char * attrib);

	struct mailimap_annotatemore_entry_att_list {
	  clist * entry_att_list; /* list of (mailimap_annotatemore_entry_att *) */
	};

	
	mailimap_annotatemore_entry_att_list * mailimap_annotatemore_entry_att_list_new(clist * en_list);
	void mailimap_annotatemore_entry_att_list_free(mailimap_annotatemore_entry_att_list * en_list);
	mailimap_annotatemore_entry_att_list * mailimap_annotatemore_entry_att_list_new_empty(); int mailimap_annotatemore_entry_att_list_add(mailimap_annotatemore_entry_att_list * en_list, mailimap_annotatemore_entry_att * en_att);
	void mailimap_annotatemore_free(mailimap_extension_data * ext_data);
	int mailimap_idle(mailimap * session);
	int mailimap_idle_done(mailimap * session);
	int mailimap_idle_get_fd(mailimap * session);
	void mailimap_idle_set_delay(mailimap * session, long delay);
	long mailimap_idle_get_done_delay(mailimap * session);
	int mailimap_has_idle(mailimap * session);
	int mailimap_greeting_parse(mailstream * fd, MMAPString * buffer, size_t * indx, mailimap_greeting ** result, size_t progr_rate, progress_function * progr_fun);
	int mailimap_response_parse(mailstream * fd, MMAPString * buffer, size_t * indx, mailimap_response ** result, size_t progr_rate, progress_function * progr_fun);
	int mailimap_response_parse_with_context(mailstream * fd, MMAPString * buffer, size_t * indx, mailimap_response ** result, mailprogress_function * body_progr_fun, mailprogress_function * items_progr_fun, void * context, mailimap_msg_att_handler * msg_att_handler, void * msg_att_context);
	int mailimap_continue_req_parse(mailstream * fd, MMAPString * buffer, size_t * indx, mailimap_continue_req ** result, size_t progr_rate, progress_function * progr_fun);
	int mailimap_response_data_parse(mailstream * fd, MMAPString * buffer, size_t * indx, mailimap_response_data ** result, size_t progr_rate, progress_function * progr_fun);

	alias mailimap_struct_parser=void function(mailstream * fd, MMAPString * buffer, size_t * indx, void * result, size_t progr_rate, progress_function * progr_fun);
	alias mailimap_struct_destructor=void function(void * result);

	int mailimap_mailbox_parse(mailstream * fd, MMAPString * buffer, size_t * indx, char ** result, size_t progr_rate, progress_function * progr_fun); 
	int mailimap_mailbox_list_parse(mailstream * fd, MMAPString * buffer, size_t * indx, mailimap_mailbox_list ** result, size_t progr_rate, progress_function * progr_fun);
 	int mailimap_nstring_parse(mailstream * fd, MMAPString * buffer, size_t * indx, char ** result, size_t * result_len, size_t progr_rate, progress_function * progr_fun);
 	int mailimap_string_parse(mailstream * fd, MMAPString * buffer, size_t * indx, char ** result, size_t * result_len, size_t progr_rate, progress_function * progr_fun);
 	int mailimap_struct_spaced_list_parse(mailstream * fd, MMAPString * buffer, size_t * indx, clist ** result, mailimap_struct_parser * parser, mailimap_struct_destructor * destructor, size_t progr_rate, progress_function * progr_fun);
 	int mailimap_oparenth_parse(mailstream * fd, MMAPString * buffer, size_t * indx); int mailimap_cparenth_parse(mailstream * fd, MMAPString * buffer, size_t * indx);
 	int mailimap_atom_parse(mailstream * fd, MMAPString * buffer, size_t * indx, char ** result, size_t progr_rate, progress_function * progr_fun);
	int mailimap_astring_parse(mailstream * fd, MMAPString * buffer, size_t * indx, char ** result, size_t progr_rate, progress_function * progr_fun);
 	int mailimap_number_parse(mailstream * fd, MMAPString * buffer, size_t * indx, uint32_t * result);
	int mailimap_nz_number_parse(mailstream * fd, MMAPString * buffer, size_t * indx, uint32_t * result);
 	int mailimap_struct_list_parse(mailstream * fd, MMAPString * buffer, size_t * indx, clist ** result, char symbol, mailimap_struct_parser * parser, mailimap_struct_destructor * destructor, size_t progr_rate, progress_function * progr_fun);
 	int mailimap_uniqueid_parse(mailstream * fd, MMAPString * buffer, size_t * indx, uint32_t * result);
 	int mailimap_colon_parse(mailstream * fd, MMAPString * buffer, size_t * indx);
 	int mailimap_dquote_parse(mailstream * fd, MMAPString * buffer, size_t * indx);
 	int mailimap_quoted_char_parse(mailstream * fd, MMAPString * buffer, size_t * indx, char * result);
 	int mailimap_nil_parse(mailstream * fd, MMAPString * buffer, size_t * indx);
 	int mailimap_struct_multiple_parse(mailstream * fd, MMAPString * buffer, size_t * indx, clist ** result, mailimap_struct_parser * parser, mailimap_struct_destructor * destructor, size_t progr_rate, progress_function * progr_fun);
 	int mailimap_capability_data_parse(mailstream * fd, MMAPString * buffer, size_t * indx, mailimap_capability_data ** result, size_t progr_rate, progress_function * progr_fun);
	int mailimap_capability_list_parse(mailstream * fd, MMAPString * buffer, size_t * indx, clist ** result, size_t progr_rate, progress_function * progr_fun);
	int mailimap_status_att_parse(mailstream * fd, MMAPString * buffer, size_t * indx, int * result);
	int mailimap_nz_number_alloc_parse(mailstream * fd, MMAPString * buffer, size_t * indx, uint32_t ** result, size_t progr_rate, progress_function * progr_fun);
	int mailimap_mod_sequence_value_parse(mailstream * fd, MMAPString * buffer, size_t * indx, uint64_t * result);
	int mailimap_uint64_parse(mailstream * fd, MMAPString * buffer, size_t * indx, uint64_t * result);
	int mailimap_set_parse(mailstream * fd, MMAPString * buffer, size_t * indx, mailimap_set ** result);
		int mailimap_hack_date_time_parse(char * str, mailimap_date_time ** result, size_t progr_rate, progress_function * progr_fun);
	int mailimap_id_send(mailstream * fd, mailimap_id_params_list * client_identification);

	enum {
	  MAILIMAP_ACL_TYPE_ACL_DATA,                   /* child of mailbox-data  */
	  MAILIMAP_ACL_TYPE_LISTRIGHTS_DATA,            /* child of mailbox-data  */
	  MAILIMAP_ACL_TYPE_MYRIGHTS_DATA               /* child of mailbox-data  */
	};

	void mailimap_acl_identifier_free(char * identifier);

	void mailimap_acl_rights_free(char * rights);

	struct mailimap_acl_identifier_rights {
	  char * identifer;
	  char * rights;
	};

	mailimap_acl_identifier_rights * mailimap_acl_identifier_rights_new(char * identifier, char * rights);
	void mailimap_acl_identifier_rights_free( mailimap_acl_identifier_rights * id_rights);

	struct mailimap_acl_acl_data {
	  char * mailbox;
	  clist * idrights_list;
	  /* list of (struct mailimap_acl_identifier_rights *) */
	};

	mailimap_acl_acl_data * mailimap_acl_acl_data_new(char * mailbox, clist * idrights_list);
 	void mailimap_acl_acl_data_free(mailimap_acl_acl_data * acl_data);

	struct mailimap_acl_listrights_data {
	  char * mailbox;
	  char * identifier;
	  clist * rights_list; /* list of (char *) */
	};

	mailimap_acl_listrights_data * mailimap_acl_listrights_data_new(char * mailbox, char * identifier, clist * rights_list);

	
	void mailimap_acl_listrights_data_free(mailimap_acl_listrights_data * listrights_data);

	struct mailimap_acl_myrights_data {
	  char * mailbox;
	  char * rights;
	};

	mailimap_acl_myrights_data * mailimap_acl_myrights_data_new(char * mailbox, char * rights);

	
	void mailimap_acl_myrights_data_free(mailimap_acl_myrights_data * myrights_data);

	void mailimap_acl_free(mailimap_extension_data * ext_data);

	enum {
	  MAILIMAP_UIDPLUS_RESP_CODE_APND,
	  MAILIMAP_UIDPLUS_RESP_CODE_COPY,
	  MAILIMAP_UIDPLUS_RESP_CODE_UIDNOTSTICKY
	};

	struct mailimap_uidplus_resp_code_apnd {
	  uint32_t uid_uidvalidity;
	  mailimap_set * uid_set;
	};

	struct mailimap_uidplus_resp_code_copy {
	  uint32_t uid_uidvalidity;
	  mailimap_set * uid_source_set;
	  mailimap_set * uid_dest_set;
	};

	
	mailimap_uidplus_resp_code_apnd * mailimap_uidplus_resp_code_apnd_new(uint32_t uid_uidvalidity, mailimap_set * uid_set);
	void mailimap_uidplus_resp_code_apnd_free(mailimap_uidplus_resp_code_apnd * resp_code_apnd);
	mailimap_uidplus_resp_code_copy *mailimap_uidplus_resp_code_copy_new(uint32_t uid_uidvalidity, mailimap_set * uid_source_set, mailimap_set * uid_dest_set);
	void mailimap_uidplus_resp_code_copy_free(mailimap_uidplus_resp_code_copy * resp_code_copy);
	void mailimap_uidplus_free(mailimap_extension_data * ext_data);


	enum {
	  MAILIMAP_EXTENSION_ANNOTATEMORE,  /* the annotatemore-draft */
	  MAILIMAP_EXTENSION_ACL,           /* the acl capability */
	  MAILIMAP_EXTENSION_UIDPLUS,       /* UIDPLUS */
	  MAILIMAP_EXTENSION_QUOTA,         /* quota */
	  MAILIMAP_EXTENSION_NAMESPACE,     /* namespace */
	  MAILIMAP_EXTENSION_XLIST,         /* XLIST (Gmail and Zimbra have this) */
	  MAILIMAP_EXTENSION_XGMLABELS,     /* X-GM-LABELS (Gmail) */
	  MAILIMAP_EXTENSION_XGMMSGID,      /* X-GM-MSGID (Gmail) */
	  MAILIMAP_EXTENSION_XGMTHRID,      /* X-GM-THRID (Gmail) */
	  MAILIMAP_EXTENSION_ID,            /* ID */
	  MAILIMAP_EXTENSION_ENABLE,        /* ENABLE */
	  MAILIMAP_EXTENSION_CONDSTORE,     /* CONDSTORE */
	  MAILIMAP_EXTENSION_QRESYNC,       /* QRESYNC */
	  MAILIMAP_EXTENSION_SORT           /* SORT */
	};


	enum {
	  MAILIMAP_EXTENDED_PARSER_RESPONSE_DATA,
	  MAILIMAP_EXTENDED_PARSER_RESP_TEXT_CODE,
	  MAILIMAP_EXTENDED_PARSER_MAILBOX_DATA,
	  MAILIMAP_EXTENDED_PARSER_FETCH_DATA,
	  MAILIMAP_EXTENDED_PARSER_STATUS_ATT
	};

	struct mailimap_extension_api {
	  char * ext_name;
	  int ext_id; /* use -1 if this is an extension outside libetpan */

	  int function(int calling_parser, mailstream * fd,
	            MMAPString * buffer, size_t * indx,
	            mailimap_extension_data ** result,
	            size_t progr_rate,
	            progress_function * progr_fun) ext_parser;

	  void function(mailimap_extension_data * ext_data) ext_free;
	};
	struct mailimap_extension_data {
	  mailimap_extension_api * ext_extension;
	  int ext_type;
	  void * ext_data;
	};

	enum {
	  MAILIMAP_QRESYNC_TYPE_VANISHED,
	  MAILIMAP_QRESYNC_TYPE_RESP_TEXT_CODE
	};

	struct mailimap_qresync_vanished {
	  int qr_earlier;
	  mailimap_set * qr_known_uids;
	};

	enum {
	  MAILIMAP_QRESYNC_RESPTEXTCODE_CLOSED
	};

	struct mailimap_qresync_resptextcode {
	  int qr_type;
	};

mailimap_qresync_vanished * mailimap_qresync_vanished_new(int qr_earlier, mailimap_set * qr_known_uids);
	void mailimap_qresync_vanished_free(mailimap_qresync_vanished * vanished);
	mailimap_qresync_resptextcode * mailimap_qresync_resptextcode_new(int qr_type);
	void mailimap_qresync_resptextcode_free(mailimap_qresync_resptextcode * resptextcode);
	
	int mailimap_quota_getquota_send(mailstream * fd, const char * quotaroot);
	int mailimap_quota_getquotaroot_send(mailstream * fd, const char * list_mb);

	mailimap_set_item * mailimap_set_item_new_single(uint32_t indx);
	mailimap_set * mailimap_set_new_single_item(mailimap_set_item * item);
	mailimap_set * mailimap_set_new_interval(uint32_t first, uint32_t last);
	mailimap_set * mailimap_set_new_single(uint32_t indx);
	mailimap_set * mailimap_set_new_empty();
	int mailimap_set_add( mailimap_set * set,  mailimap_set_item * set_item);
	int mailimap_set_add_interval( mailimap_set * set, uint32_t first, uint32_t last);
	int mailimap_set_add_single( mailimap_set * set, uint32_t indx);
	mailimap_section * mailimap_section_new_header();
	mailimap_section * mailimap_section_new_header_fields( mailimap_header_list * header_list);
	mailimap_section * mailimap_section_new_header_fields_not( mailimap_header_list * header_list);
	mailimap_section * mailimap_section_new_text();
	mailimap_section * mailimap_section_new_part( mailimap_section_part * part);
	mailimap_section * mailimap_section_new_part_mime( mailimap_section_part * part);
	mailimap_section * mailimap_section_new_part_header(mailimap_section_part * part);
	mailimap_section * mailimap_section_new_part_header_fields(mailimap_section_part * part, mailimap_header_list * header_list);
	mailimap_section * mailimap_section_new_part_header_fields_not(mailimap_section_part * part, mailimap_header_list * header_list);
	mailimap_section * mailimap_section_new_part_text(mailimap_section_part * part);
	mailimap_fetch_att * mailimap_fetch_att_new_envelope();
	mailimap_fetch_att * mailimap_fetch_att_new_flags();
	mailimap_fetch_att * mailimap_fetch_att_new_internaldate();
	mailimap_fetch_att * mailimap_fetch_att_new_rfc822();
	mailimap_fetch_att * mailimap_fetch_att_new_rfc822_header();
	mailimap_fetch_att * mailimap_fetch_att_new_rfc822_size();
	mailimap_fetch_att * mailimap_fetch_att_new_rfc822_text();
	mailimap_fetch_att * mailimap_fetch_att_new_body();
	mailimap_fetch_att * mailimap_fetch_att_new_bodystructure();
	mailimap_fetch_att * mailimap_fetch_att_new_uid();
	mailimap_fetch_att * mailimap_fetch_att_new_body_section(mailimap_section * section);
	mailimap_fetch_att * mailimap_fetch_att_new_body_peek_section(mailimap_section * section);
	mailimap_fetch_att * mailimap_fetch_att_new_body_section_partial(mailimap_section * section, uint32_t offset, uint32_t size);
	mailimap_fetch_att * mailimap_fetch_att_new_body_peek_section_partial(mailimap_section * section, uint32_t offset, uint32_t size);
	mailimap_fetch_att * mailimap_fetch_att_new_extension(char * ext_keyword);
	mailimap_fetch_type * mailimap_fetch_type_new_all();
	mailimap_fetch_type * mailimap_fetch_type_new_full();
	mailimap_fetch_type * mailimap_fetch_type_new_fast();
	mailimap_fetch_type * mailimap_fetch_type_new_fetch_att(mailimap_fetch_att * fetch_att);
	mailimap_fetch_type * mailimap_fetch_type_new_fetch_att_list(clist * fetch_att_list);
	mailimap_fetch_type * mailimap_fetch_type_new_fetch_att_list_empty();
	int mailimap_fetch_type_new_fetch_att_list_add( mailimap_fetch_type * fetch_type,  mailimap_fetch_att * fetch_att);
	mailimap_store_att_flags * mailimap_store_att_flags_new_set_flags(mailimap_flag_list * flags);
	mailimap_store_att_flags * mailimap_store_att_flags_new_set_flags_silent(mailimap_flag_list * flags);
	mailimap_store_att_flags * mailimap_store_att_flags_new_add_flags(mailimap_flag_list * flags);
	mailimap_store_att_flags * mailimap_store_att_flags_new_add_flags_silent(mailimap_flag_list * flags);
	mailimap_store_att_flags * mailimap_store_att_flags_new_remove_flags(mailimap_flag_list * flags);
	mailimap_store_att_flags * mailimap_store_att_flags_new_remove_flags_silent(mailimap_flag_list * flags);
	mailimap_search_key * mailimap_search_key_new_all();
	mailimap_search_key * mailimap_search_key_new_bcc(char * sk_bcc);
	mailimap_search_key * mailimap_search_key_new_before(mailimap_date * sk_before);
	mailimap_search_key * mailimap_search_key_new_body(char * sk_body);
	mailimap_search_key * mailimap_search_key_new_cc(char * sk_cc);
	mailimap_search_key * mailimap_search_key_new_from(char * sk_from);
	mailimap_search_key * mailimap_search_key_new_keyword(char * sk_keyword);
	mailimap_search_key * mailimap_search_key_new_on(mailimap_date * sk_on);
	mailimap_search_key * mailimap_search_key_new_since(mailimap_date * sk_since);
	mailimap_search_key * mailimap_search_key_new_subject(char * sk_subject);
	mailimap_search_key * mailimap_search_key_new_text(char * sk_text);
	mailimap_search_key * mailimap_search_key_new_to(char * sk_to);
	mailimap_search_key * mailimap_search_key_new_unkeyword(char * sk_unkeyword);
	mailimap_search_key * mailimap_search_key_new_header(char * sk_header_name, char * sk_header_value);
	mailimap_search_key * mailimap_search_key_new_larger(uint32_t sk_larger);
	mailimap_search_key * mailimap_search_key_new_not(mailimap_search_key * sk_not);
	mailimap_search_key *mailimap_search_key_new_or( mailimap_search_key * sk_or1, mailimap_search_key * sk_or2);
	mailimap_search_key * mailimap_search_key_new_sentbefore(mailimap_date * sk_sentbefore);
	mailimap_search_key * mailimap_search_key_new_senton( mailimap_date * sk_senton);
	mailimap_search_key * mailimap_search_key_new_sentsince(mailimap_date * sk_sentsince);
	mailimap_search_key * mailimap_search_key_new_smaller(uint32_t sk_smaller);
	mailimap_search_key * mailimap_search_key_new_uid( mailimap_set * sk_uid);
	mailimap_search_key * mailimap_search_key_new_set(mailimap_set * sk_set);
	mailimap_search_key * mailimap_search_key_new_multiple(clist * sk_multiple);
	mailimap_search_key * mailimap_search_key_new_multiple_empty();
	int mailimap_search_key_multiple_add(mailimap_search_key * keys,  mailimap_search_key * key_item);
	mailimap_flag_list * mailimap_flag_list_new_empty();
	int mailimap_flag_list_add(mailimap_flag_list * flag_list, mailimap_flag * f);
	mailimap_flag * mailimap_flag_new_answered();
	mailimap_flag * mailimap_flag_new_flagged();
	mailimap_flag * mailimap_flag_new_deleted();
	mailimap_flag * mailimap_flag_new_seen();
	mailimap_flag * mailimap_flag_new_draft();
	mailimap_flag * mailimap_flag_new_flag_keyword(char * flag_keyword);
	mailimap_flag * mailimap_flag_new_flag_extension(char * flag_extension);
	mailimap_status_att_list * mailimap_status_att_list_new_empty();
	int mailimap_status_att_list_add(mailimap_status_att_list * sa_list, int status_att);
	int mailimap_get_section_part_from_body(mailimap_body * root_part, mailimap_body * part, mailimap_section_part ** result);
	int mailimap_extension_register(mailimap_extension_api * extension);
	void mailimap_extension_unregister_all();
	int mailimap_extension_data_parse(int calling_parser, mailstream * fd, MMAPString * buffer, size_t * indx, mailimap_extension_data ** result, size_t progr_rate, progress_function * progr_fun);
	mailimap_extension_data * mailimap_extension_data_new(mailimap_extension_api * extension, int type, void * data);
	int mailimap_has_extension(mailimap * session, char * extension_name);
	int mailimap_has_authentication(mailimap * session, char * authentication_name);


	int mailimap_namespace_send(mailstream * fd);
	__gshared mailimap_extension_api mailimap_extension_xgmmsgid;
	mailimap_fetch_att * mailimap_fetch_att_new_xgmmsgid();
	
	enum {
	  MAILIMAP_CONDSTORE_TYPE_FETCH_DATA,
	  MAILIMAP_CONDSTORE_TYPE_RESP_TEXT_CODE,
	  MAILIMAP_CONDSTORE_TYPE_SEARCH_DATA,
	  MAILIMAP_CONDSTORE_TYPE_STATUS_INFO
	};

	struct mailimap_condstore_fetch_mod_resp {
	  uint64_t cs_modseq_value;
	};

	enum {
	  MAILIMAP_CONDSTORE_RESPTEXTCODE_HIGHESTMODSEQ,
	  MAILIMAP_CONDSTORE_RESPTEXTCODE_NOMODSEQ,
	  MAILIMAP_CONDSTORE_RESPTEXTCODE_MODIFIED
	};

	struct mailimap_condstore_resptextcode {
	  int cs_type;
	  union cs_data_t
	  {
	    uint64_t cs_modseq_value;
	    mailimap_set * cs_modified_set;
	  }
	  cs_data_t cs_data;
	};

	struct mailimap_condstore_search {
	  clist * cs_search_result; /* uint32_t */
	  uint64_t cs_modseq_value;
	};

	struct mailimap_condstore_status_info {
	  uint64_t cs_highestmodseq_value;
	};

	
	mailimap_condstore_fetch_mod_resp * mailimap_condstore_fetch_mod_resp_new(uint64_t cs_modseq_value);
	void mailimap_condstore_fetch_mod_resp_free(mailimap_condstore_fetch_mod_resp * fetch_data);
	mailimap_condstore_resptextcode * mailimap_condstore_resptextcode_new(int cs_type, uint64_t cs_modseq_value, mailimap_set * cs_modified_set);
	void mailimap_condstore_resptextcode_free(mailimap_condstore_resptextcode * resptextcode);
	mailimap_condstore_search * mailimap_condstore_search_new(clist * cs_search_result, uint64_t cs_modseq_value);
	void mailimap_condstore_search_free(mailimap_condstore_search * search_data);
	mailimap_condstore_status_info * mailimap_condstore_status_info_new(uint64_t cs_highestmodseq_value);
	void mailimap_condstore_status_info_free( mailimap_condstore_status_info * status_info);
	int mailimap_annotatemore_annotate_data_parse(mailstream * fd, MMAPString *buffer, size_t * indx,  mailimap_annotatemore_annotate_data ** result, size_t progr_rate, progress_function * progr_fun);
	int mailimap_annotatemore_entry_list_parse(mailstream * fd, MMAPString *buffer, size_t * indx,  mailimap_annotatemore_entry_list ** result, size_t progr_rate, progress_function * progr_fun);
	int mailimap_annotatemore_entry_att_parse(mailstream * fd, MMAPString *buffer, size_t * indx,  mailimap_annotatemore_entry_att ** result, size_t progr_rate, progress_function * progr_fun);
	int mailimap_annotatemore_att_value_parse(mailstream * fd, MMAPString *buffer, size_t * indx,  mailimap_annotatemore_att_value ** result, size_t progr_rate, progress_function * progr_fun);
	int mailimap_annotatemore_attrib_parse(mailstream * fd, MMAPString *buffer, size_t * indx, char ** result, size_t progr_rate, progress_function * progr_fun);
	int mailimap_annotatemore_value_parse(mailstream * fd, MMAPString *buffer, size_t * indx, char ** result, size_t progr_rate, progress_function * progr_fun);
	int mailimap_annotatemore_entry_parse(mailstream * fd, MMAPString *buffer, size_t * indx, char ** result, size_t progr_rate, progress_function * progr_fun);
	int mailimap_annotatemore_text_code_annotatemore_parse(mailstream * fd, MMAPString *buffer, size_t * indx, int * result, size_t progr_rate, progress_function * progr_fun);
	int mailimap_annotatemore_parse(int calling_parser, mailstream * fd, MMAPString * buffer, size_t * indx, mailimap_extension_data ** result, size_t progr_rate, progress_function * progr_fun);

	struct mailimap_address {
	  char * ad_personal_name; /* can be NULL */
	  char * ad_source_route;  /* can be NULL */
	  char * ad_mailbox_name;  /* can be NULL */
	  char * ad_host_name;     /* can be NULL */
	};

	mailimap_address * mailimap_address_new(char * ad_personal_name, char * ad_source_route, char * ad_mailbox_name, char * ad_host_name);
	void mailimap_address_free( mailimap_address * addr);
	
	enum {
	  MAILIMAP_BODY_ERROR,
	  MAILIMAP_BODY_1PART, /* single part */
	  MAILIMAP_BODY_MPART  /* multi-part */
	};
	
	struct mailimap_body
	{
	  int bd_type;
	  /* can be MAILIMAP_BODY_1PART or MAILIMAP_BODY_MPART */
	  union bd_data_t
	  {
	    mailimap_body_type_1part * bd_body_1part; /* can be NULL */
	    mailimap_body_type_mpart * bd_body_mpart; /* can be NULL */
	  }
	  bd_data_t bd_data;
	}

	mailimap_body * mailimap_body_new(int bd_type, mailimap_body_type_1part * bd_body_1part, mailimap_body_type_mpart * bd_body_mpart);
	void mailimap_body_free(mailimap_body * xbody);

	enum {
	  MAILIMAP_BODY_EXTENSION_ERROR,
	  MAILIMAP_BODY_EXTENSION_NSTRING, /* string */
	  MAILIMAP_BODY_EXTENSION_NUMBER,  /* number */
	  MAILIMAP_BODY_EXTENSION_LIST     /* list of
	                                      (struct mailimap_body_extension *) */
	}


	struct mailimap_body_extension {
	  int ext_type;
	  /*
	    can be MAILIMAP_BODY_EXTENSION_NSTRING, MAILIMAP_BODY_EXTENSION_NUMBER
	    or MAILIMAP_BODY_EXTENSION_LIST
	  */
	  union ext_data_t
	  {
	    char * ext_nstring;    /* can be NULL */
	    uint32_t ext_number;
	    clist * ext_body_extension_list;
	    /* list of (struct mailimap_body_extension *) */
	    /* can be NULL */
	  }
	  ext_data_t ext_data;
	};

	
	mailimap_body_extension * mailimap_body_extension_new(int ext_type, char * ext_nstring, uint32_t ext_number, clist * ext_body_extension_list);
	void mailimap_body_extension_free(mailimap_body_extension * be);

	struct mailimap_body_ext_1part
	{
	  char * bd_md5;   /* can be NULL */
	  mailimap_body_fld_dsp * bd_disposition; /* can be NULL */
	  mailimap_body_fld_lang * bd_language;   /* can be NULL */
	  char * bd_loc; /* can be NULL */
	  clist * bd_extension_list; /* list of (struct mailimap_body_extension *) */
	                               /* can be NULL */
	}

	
	mailimap_body_ext_1part * mailimap_body_ext_1part_new(char * bd_md5,  mailimap_body_fld_dsp * bd_disposition,  mailimap_body_fld_lang * bd_language, char * bd_loc, clist * bd_extension_list);
	void mailimap_body_ext_1part_free( mailimap_body_ext_1part * body_ext_1part);

	struct mailimap_body_ext_mpart {
	  mailimap_body_fld_param * bd_parameter; /* can be NULL */
	  mailimap_body_fld_dsp * bd_disposition; /* can be NULL */
	  mailimap_body_fld_lang * bd_language;   /* can be NULL */
	  char * bd_loc; /* can be NULL */
	  clist * bd_extension_list; /* list of (struct mailimap_body_extension *) */
	                               /* can be NULL */
	};

	
	mailimap_body_ext_mpart * mailimap_body_ext_mpart_new(mailimap_body_fld_param * bd_parameter, mailimap_body_fld_dsp * bd_disposition, mailimap_body_fld_lang * bd_language, char * bd_loc, clist * bd_extension_list);
	void mailimap_body_ext_mpart_free(mailimap_body_ext_mpart * body_ext_mpart);

	struct mailimap_body_fields {
	  mailimap_body_fld_param * bd_parameter; /* can be NULL */
	  char * bd_id;                                  /* can be NULL */
	  char * bd_description;                         /* can be NULL */
	  mailimap_body_fld_enc * bd_encoding;    /* != NULL */
	  uint32_t bd_size;
	};

	mailimap_body_fields * mailimap_body_fields_new(mailimap_body_fld_param * bd_parameter, char * bd_id, char * bd_description, mailimap_body_fld_enc * bd_encoding, uint32_t bd_size);
	void mailimap_body_fields_free(mailimap_body_fields * body_fields);


	struct mailimap_body_fld_dsp {
	  char * dsp_type;                     /* != NULL */
	  mailimap_body_fld_param * dsp_attributes; /* can be NULL */
	};

	
	mailimap_body_fld_dsp * mailimap_body_fld_dsp_new(char * dsp_type,  mailimap_body_fld_param * dsp_attributes);
	void mailimap_body_fld_dsp_free( mailimap_body_fld_dsp * bfd);

	enum {
	  MAILIMAP_BODY_FLD_ENC_7BIT,             /* 7bit */
	  MAILIMAP_BODY_FLD_ENC_8BIT,             /* 8bit */
	  MAILIMAP_BODY_FLD_ENC_BINARY,           /* binary */
	  MAILIMAP_BODY_FLD_ENC_BASE64,           /* base64 */
	  MAILIMAP_BODY_FLD_ENC_QUOTED_PRINTABLE, /* quoted-printable */
	  MAILIMAP_BODY_FLD_ENC_OTHER             /* other */
	};

	struct mailimap_body_fld_enc {
	  int enc_type;
	  char * enc_value; /* can be NULL */
	};

	
	mailimap_body_fld_enc * mailimap_body_fld_enc_new(int enc_type, char * enc_value);
	void mailimap_body_fld_enc_free(mailimap_body_fld_enc * bfe);


	/* this is the type of Content-Language header field value */

	enum {
	  MAILIMAP_BODY_FLD_LANG_ERROR,  /* error parse */
	  MAILIMAP_BODY_FLD_LANG_SINGLE, /* single value */
	  MAILIMAP_BODY_FLD_LANG_LIST    /* list of values */
	}


	struct mailimap_body_fld_lang {
	  int lg_type;
	  union lg_data_t 
	  {
	    char * lg_single; /* can be NULL */
	    clist * lg_list; /* list of string (char *), can be NULL */
	  }
	  lg_data_t lg_data;
	};

	mailimap_body_fld_lang * mailimap_body_fld_lang_new(int lg_type, char * lg_single, clist * lg_list);
	void mailimap_body_fld_lang_free(mailimap_body_fld_lang * fld_lang);
	
	struct mailimap_single_body_fld_param {
	  char * pa_name;  /* != NULL */
	  char * pa_value; /* != NULL */
	};

	
	mailimap_single_body_fld_param * mailimap_single_body_fld_param_new(char * pa_name, char * pa_value);
	void mailimap_single_body_fld_param_free(mailimap_single_body_fld_param * p);
	

	struct mailimap_body_fld_param {
	  clist * pa_list; /* list of (struct mailimap_single_body_fld_param *) */
	                /* != NULL */
	};

	mailimap_body_fld_param * mailimap_body_fld_param_new(clist * pa_list);
	void mailimap_body_fld_param_free( mailimap_body_fld_param * fld_param);
	
	enum {
	  MAILIMAP_BODY_TYPE_1PART_ERROR, /* parse error */
	  MAILIMAP_BODY_TYPE_1PART_BASIC, /* others then multipart/xxx */
	  MAILIMAP_BODY_TYPE_1PART_MSG,   /* message/rfc2822 */
	  MAILIMAP_BODY_TYPE_1PART_TEXT   /* text/xxx */
	};


	struct mailimap_body_type_1part {
	  int bd_type;
	  union bd_data_t
	  {
	    mailimap_body_type_basic * bd_type_basic; /* can be NULL */
	    mailimap_body_type_msg * bd_type_msg;     /* can be NULL */
	    mailimap_body_type_text * bd_type_text;   /* can be NULL */
	  }
	  bd_data_t bd_data;
	  mailimap_body_ext_1part * bd_ext_1part;   /* can be NULL */
	}
	
	mailimap_body_type_1part * mailimap_body_type_1part_new(int bd_type,  mailimap_body_type_basic * bd_type_basic,  mailimap_body_type_msg * bd_type_msg,
	mailimap_body_type_text * bd_type_text,  mailimap_body_ext_1part * bd_ext_1part);
	void mailimap_body_type_1part_free( mailimap_body_type_1part * bt1p);
	

	struct mailimap_body_type_basic {
	   mailimap_media_basic * bd_media_basic; /* != NULL */
	   mailimap_body_fields * bd_fields; /* != NULL */
	};

	mailimap_body_type_basic * mailimap_body_type_basic_new( mailimap_media_basic * bd_media_basic,  mailimap_body_fields * bd_fields);
	void mailimap_body_type_basic_free( mailimap_body_type_basic * body_type_basic);
	
	struct mailimap_body_type_mpart {
	  clist * bd_list; /* list of (struct mailimap_body *) */
	                     /* != NULL */
	  char * bd_media_subtype; /* != NULL */
	   mailimap_body_ext_mpart * bd_ext_mpart; /* can be NULL */
	};

	
	mailimap_body_type_mpart * mailimap_body_type_mpart_new(clist * bd_list, char * bd_media_subtype,  mailimap_body_ext_mpart * bd_ext_mpart);
	void mailimap_body_type_mpart_free( mailimap_body_type_mpart * body_type_mpart);
	

	struct mailimap_body_type_msg {
	  mailimap_body_fields * bd_fields; /* != NULL */
	  mailimap_envelope * bd_envelope;       /* != NULL */
	  mailimap_body * bd_body;               /* != NULL */
	  uint32_t bd_lines;
	};

	
	mailimap_body_type_msg * mailimap_body_type_msg_new( mailimap_body_fields * bd_fields,  mailimap_envelope * bd_envelope, mailimap_body * bd_body, uint32_t bd_lines);
	void mailimap_body_type_msg_free( mailimap_body_type_msg * body_type_msg);
	

	struct mailimap_body_type_text {
	  char * bd_media_text;                         /* != NULL */
	  mailimap_body_fields * bd_fields; /* != NULL */
	  uint32_t bd_lines;
	};

	
	mailimap_body_type_text * mailimap_body_type_text_new(char * bd_media_text, mailimap_body_fields * bd_fields, uint32_t bd_lines);
	void mailimap_body_type_text_free( mailimap_body_type_text * body_type_text);
	
	enum {
	  MAILIMAP_CAPABILITY_AUTH_TYPE, /* when the capability is an
	                                      authentication type */
	  MAILIMAP_CAPABILITY_NAME       /* other type of capability */
	};

	struct mailimap_capability_t {
	  int cap_type;
	  union cap_data_t
	  {
	    char * cap_auth_type; /* can be NULL */
	    char * cap_name;      /* can be NULL */
	  }
	  cap_data_t cap_data;
	}

	mailimap_capability_t * mailimap_capability_new(int cap_type, char * cap_auth_type, char * cap_name);
	void mailimap_capability_free(mailimap_capability_t * c);
	

	struct mailimap_capability_data {
	  clist * cap_list; /* list of (struct mailimap_capability *), != NULL */
	};

	
	mailimap_capability_data * mailimap_capability_data_new(clist * cap_list);
	void mailimap_capability_data_free(mailimap_capability_data * cap_data);
	

	enum {
	  MAILIMAP_CONTINUE_REQ_ERROR,  /* on parse error */ 
	  MAILIMAP_CONTINUE_REQ_TEXT,   /* when data is a text response */
	  MAILIMAP_CONTINUE_REQ_BASE64  /* when data is a base64 response */
	}


	struct mailimap_continue_req
	{
	  int cr_type;
	  union cr_data_t
	  {
	    mailimap_resp_text * cr_text; /* can be NULL */
	    char * cr_base64;                    /* can be NULL */
	  }
	  cr_data_t cr_data;
	}

	mailimap_continue_req * mailimap_continue_req_new(int cr_type, mailimap_resp_text * cr_text, char * cr_base64);
	void mailimap_continue_req_free( mailimap_continue_req * cont_req);

	struct mailimap_date_time {
	  int dt_day;
	  int dt_month;
	  int dt_year;
	  int dt_hour;
	  int dt_min;
	  int dt_sec;
	  int dt_zone;
	};

	mailimap_date_time * mailimap_date_time_new(int dt_day, int dt_month, int dt_year, int dt_hour, int dt_min, int dt_sec, int dt_zone);
	void mailimap_date_time_free( mailimap_date_time * date_time);

	struct mailimap_envelope {
	  char * env_date;                             /* can be NULL */
	  char * env_subject;                          /* can be NULL */
	  mailimap_env_from * env_from;         /* can be NULL */
	  mailimap_env_sender * env_sender;     /* can be NULL */
	  mailimap_env_reply_to * env_reply_to; /* can be NULL */
	  mailimap_env_to * env_to;             /* can be NULL */
	  mailimap_env_cc * env_cc;             /* can be NULL */
	  mailimap_env_bcc * env_bcc;           /* can be NULL */
	  char * env_in_reply_to;                      /* can be NULL */
	  char * env_message_id;                       /* can be NULL */
	};

	
	mailimap_envelope * mailimap_envelope_new(char * env_date, char * env_subject, mailimap_env_from * env_from, mailimap_env_sender * env_sender, mailimap_env_reply_to * env_reply_to, mailimap_env_to * env_to, mailimap_env_cc* env_cc, mailimap_env_bcc * env_bcc, char * env_in_reply_to, char * env_message_id);
	void mailimap_envelope_free( mailimap_envelope * env);


	struct mailimap_env_bcc {
	  clist * bcc_list; /* list of (struct mailimap_address *), can be NULL */
	};
	
	mailimap_env_bcc * mailimap_env_bcc_new(clist * bcc_list);

	
	void mailimap_env_bcc_free( mailimap_env_bcc * env_bcc);

	struct mailimap_env_cc {
	  clist * cc_list; /* list of (struct mailimap_address *), can be NULL */
	};

	
	 mailimap_env_cc * mailimap_env_cc_new(clist * cc_list);

	
	void mailimap_env_cc_free( mailimap_env_cc * env_cc);

	struct mailimap_env_from {
	  clist * frm_list; /* list of (struct mailimap_address *) */
	                /* can be NULL */
	};

	
	mailimap_env_from * mailimap_env_from_new(clist * frm_list);
	void mailimap_env_from_free( mailimap_env_from * env_from);

	struct mailimap_env_reply_to {
	  clist * rt_list; /* list of (struct mailimap_address *), can be NULL */
	};

	
	mailimap_env_reply_to * mailimap_env_reply_to_new(clist * rt_list);
	void mailimap_env_reply_to_free( mailimap_env_reply_to * env_reply_to);


	struct mailimap_env_sender {
	  clist * snd_list; /* list of (struct mailimap_address *), can be NULL */
	};

	
	mailimap_env_sender * mailimap_env_sender_new(clist * snd_list);
	void mailimap_env_sender_free(mailimap_env_sender * env_sender);

	struct mailimap_env_to {
	  clist * to_list; /* list of (struct mailimap_address *), can be NULL */
	};

	
	mailimap_env_to * mailimap_env_to_new(clist * to_list);
	void mailimap_env_to_free(mailimap_env_to * env_to);


	/* this is the type of flag */

	enum {
	  MAILIMAP_FLAG_ANSWERED,  /* \Answered flag */
	  MAILIMAP_FLAG_FLAGGED,   /* \Flagged flag */
	  MAILIMAP_FLAG_DELETED,   /* \Deleted flag */
	  MAILIMAP_FLAG_SEEN,      /* \Seen flag */
	  MAILIMAP_FLAG_DRAFT,     /* \Draft flag */
	  MAILIMAP_FLAG_KEYWORD,   /* keyword flag */
	  MAILIMAP_FLAG_EXTENSION  /* \extension flag */
	};

	struct mailimap_flag {
	  int fl_type;
	  union fl_data_t
	  {
	    char * fl_keyword;   /* can be NULL */
	    char * fl_extension; /* can be NULL */
	  }
	  fl_data_t fl_data;
	};

	
	mailimap_flag * mailimap_flag_new(int fl_type, char * fl_keyword, char * fl_extension);
	void mailimap_flag_free( mailimap_flag * f);




	/* this is the type of flag */

	enum {
	  MAILIMAP_FLAG_FETCH_ERROR,  /* on parse error */
	  MAILIMAP_FLAG_FETCH_RECENT, /* \Recent flag */
	  MAILIMAP_FLAG_FETCH_OTHER   /* other type of flag */
	};

	
	struct mailimap_flag_fetch {
	  int fl_type;
	  mailimap_flag * fl_flag; /* can be NULL */
	};

	
	mailimap_flag_fetch * mailimap_flag_fetch_new(int fl_type, mailimap_flag * fl_flag);
	void mailimap_flag_fetch_free( mailimap_flag_fetch * flag_fetch);

	enum {
	  MAILIMAP_FLAG_PERM_ERROR, /* on parse error */
	  MAILIMAP_FLAG_PERM_FLAG,  /* to specify that usual flags can be changed */
	  MAILIMAP_FLAG_PERM_ALL    /* to specify that new flags can be created */
	};

	struct mailimap_flag_perm {
	  int fl_type;
	  mailimap_flag * fl_flag; /* can be NULL */
	};

	
	mailimap_flag_perm * mailimap_flag_perm_new(int fl_type, mailimap_flag * fl_flag);
	void mailimap_flag_perm_free(mailimap_flag_perm * flag_perm);


	struct mailimap_flag_list {
	  clist * fl_list; /* list of (struct mailimap_flag *), != NULL */
	};

	
	mailimap_flag_list * mailimap_flag_list_new(clist * fl_list);
	void mailimap_flag_list_free( mailimap_flag_list * flag_list);

	enum {
	  MAILIMAP_GREETING_RESP_COND_ERROR, /* on parse error */
	  MAILIMAP_GREETING_RESP_COND_AUTH,  /* when connection is accepted */
	  MAILIMAP_GREETING_RESP_COND_BYE    /* when connection is refused */
	};


	struct mailimap_greeting {
	  int gr_type;
	  union gr_data_t
	  {
	     mailimap_resp_cond_auth * gr_auth; /* can be NULL */
	     mailimap_resp_cond_bye * gr_bye;   /* can be NULL */
	  }
	  gr_data_t gr_data;
	};

	
	mailimap_greeting * mailimap_greeting_new(int gr_type,  mailimap_resp_cond_auth * gr_auth, mailimap_resp_cond_bye * gr_bye);
	void mailimap_greeting_free(mailimap_greeting * greeting);

	struct mailimap_header_list {
	  clist * hdr_list; /* list of astring (char *), != NULL */
	};

	
	mailimap_header_list * mailimap_header_list_new(clist * hdr_list);
	void mailimap_header_list_free(mailimap_header_list * header_list);

	
	enum {
	  MAILIMAP_STATUS_ATT_MESSAGES,      /* when requesting the number of
	                                        messages */
	  MAILIMAP_STATUS_ATT_RECENT,        /* when requesting the number of
	                                        recent messages */
	  MAILIMAP_STATUS_ATT_UIDNEXT,       /* when requesting the next unique
	                                        identifier */
	  MAILIMAP_STATUS_ATT_UIDVALIDITY,   /* when requesting the validity of
	                                        message unique identifiers*/
	  MAILIMAP_STATUS_ATT_UNSEEN,        /* when requesting the number of
	                                        unseen messages */
	  MAILIMAP_STATUS_ATT_HIGHESTMODSEQ, /* when requesting the highest
	                                        mod-sequence value of all messages in
	                                        the mailbox */
	  MAILIMAP_STATUS_ATT_EXTENSION
	}


	struct mailimap_status_info {
	  int st_att;
	  uint32_t st_value;
	  mailimap_extension_data * st_ext_data; /* can be NULL */
	};

	 mailimap_status_info * mailimap_status_info_new(int st_att, uint32_t st_value, mailimap_extension_data * st_ext_data);

	
	void mailimap_status_info_free( mailimap_status_info * info);
	struct mailimap_mailbox_data_status {
	  char * st_mailbox;
	  clist * st_info_list; /* list of (struct mailimap_status_info *) */
	                            /* can be NULL */
	};

	
	mailimap_mailbox_data_status * mailimap_mailbox_data_status_new(char * st_mailbox, clist * st_info_list);
	void mailimap_mailbox_data_status_free(mailimap_mailbox_data_status * info);


	enum {
	  MAILIMAP_MAILBOX_DATA_ERROR,  /* on parse error */
	  MAILIMAP_MAILBOX_DATA_FLAGS,  /* flag that are applicable to the mailbox */
	  MAILIMAP_MAILBOX_DATA_LIST,   /* this is a mailbox in the list of mailboxes
	                                   returned on LIST command*/
	  MAILIMAP_MAILBOX_DATA_LSUB,   /* this is a mailbox in the list of
	                                   subscribed mailboxes returned on LSUB
	                                   command */
	  MAILIMAP_MAILBOX_DATA_SEARCH, /* this is a list of messages numbers or
	                                   unique identifiers returned
	                                   on a SEARCH command*/
	  MAILIMAP_MAILBOX_DATA_STATUS, /* this is the list of information returned
	                                   on a STATUS command */
	  MAILIMAP_MAILBOX_DATA_EXISTS, /* this is the number of messages in the
	                                   mailbox */
	  MAILIMAP_MAILBOX_DATA_RECENT, /* this is the number of recent messages
	                                   in the mailbox */
	  MAILIMAP_MAILBOX_DATA_EXTENSION_DATA  /* this mailbox-data stores data
	                                           returned by an extension */
	};


	struct mailimap_mailbox_data {
	  int mbd_type;
	  union mbd_data_t
	  {
	    mailimap_flag_list * mbd_flags;   /* can be NULL */
	    mailimap_mailbox_list * mbd_list; /* can be NULL */
	    mailimap_mailbox_list * mbd_lsub; /* can be NULL */
	    clist * mbd_search;  /* list of nz-number (uint32_t *), can be NULL */
	    mailimap_mailbox_data_status *  mbd_status; /* can be NULL */
	    uint32_t mbd_exists;
	    uint32_t mbd_recent;
	    mailimap_extension_data * mbd_extension; /* can be NULL */
	  }
	  mbd_data_t mbd_data;
	}

	
	mailimap_mailbox_data * mailimap_mailbox_data_new(int mbd_type,  mailimap_flag_list * mbd_flags, mailimap_mailbox_list * mbd_list, mailimap_mailbox_list * mbd_lsub, clist * mbd_search, mailimap_mailbox_data_status * mbd_status, uint32_t mbd_exists, uint32_t mbd_recent, mailimap_extension_data * mbd_extension);
	void mailimap_mailbox_data_free(mailimap_mailbox_data * mb_data);

	enum {
	  MAILIMAP_MBX_LIST_FLAGS_SFLAG,    /* mailbox single flag - a flag in
	                                       {\NoSelect, \Marked, \Unmarked} */
	  MAILIMAP_MBX_LIST_FLAGS_NO_SFLAG  /* mailbox other flag -  mailbox flag
	                                       other than \NoSelect \Marked and
	                                       \Unmarked) */
	};

	/* this is a single flag type */

	enum {
	  MAILIMAP_MBX_LIST_SFLAG_ERROR,
	  MAILIMAP_MBX_LIST_SFLAG_MARKED,
	  MAILIMAP_MBX_LIST_SFLAG_NOSELECT,
	  MAILIMAP_MBX_LIST_SFLAG_UNMARKED
	};

	struct mailimap_mbx_list_flags {
	  int mbf_type;
	  clist * mbf_oflags; /* list of
	                         (struct mailimap_mbx_list_oflag *), != NULL */
	  int mbf_sflag;
	};

	
	mailimap_mbx_list_flags * mailimap_mbx_list_flags_new(int mbf_type, clist * mbf_oflags, int mbf_sflag);

 	void mailimap_mbx_list_flags_free( mailimap_mbx_list_flags * mbx_list_flags);

	enum {
	  MAILIMAP_MBX_LIST_OFLAG_ERROR,       /* on parse error */
	  MAILIMAP_MBX_LIST_OFLAG_NOINFERIORS, /* \NoInferior flag */
	  MAILIMAP_MBX_LIST_OFLAG_FLAG_EXT     /* other flag */
	};
	struct mailimap_mbx_list_oflag {
	  int of_type;
	  char * of_flag_ext; /* can be NULL */
	};

	
	mailimap_mbx_list_oflag * mailimap_mbx_list_oflag_new(int of_type, char * of_flag_ext);
	void mailimap_mbx_list_oflag_free(mailimap_mbx_list_oflag * oflag);

	struct mailimap_mailbox_list {
		mailimap_mbx_list_flags * mb_flag; /* can be NULL */
	  char mb_delimiter;
	  char * mb_name; /* != NULL */
	};

	
	mailimap_mailbox_list * mailimap_mailbox_list_new( mailimap_mbx_list_flags * mbx_flags, char mb_delimiter, char * mb_name);
	void mailimap_mailbox_list_free(mailimap_mailbox_list * mb_list);

	enum {
	  MAILIMAP_MEDIA_BASIC_APPLICATION, /* application/xxx */
	  MAILIMAP_MEDIA_BASIC_AUDIO,       /* audio/xxx */
	  MAILIMAP_MEDIA_BASIC_IMAGE,       /* image/xxx */
	  MAILIMAP_MEDIA_BASIC_MESSAGE,     /* message/xxx */
	  MAILIMAP_MEDIA_BASIC_VIDEO,       /* video/xxx */
	  MAILIMAP_MEDIA_BASIC_OTHER        /* for all other cases */
	};

	struct mailimap_media_basic {
	  int med_type;
	  char * med_basic_type; /* can be NULL */
	  char * med_subtype;    /* != NULL */
	};

	
	mailimap_media_basic * mailimap_media_basic_new(int med_type, char * med_basic_type, char * med_subtype);
	void mailimap_media_basic_free( mailimap_media_basic * media_basic);

	enum {
	  MAILIMAP_MESSAGE_DATA_ERROR,
	  MAILIMAP_MESSAGE_DATA_EXPUNGE,
	  MAILIMAP_MESSAGE_DATA_FETCH
	};

	
	struct mailimap_message_data {
	  uint32_t mdt_number;
	  int mdt_type;
	  mailimap_msg_att * mdt_msg_att; /* can be NULL */
	                                     /* if type = EXPUNGE, can be NULL */
	};

	
	mailimap_message_data * mailimap_message_data_new(uint32_t mdt_number, int mdt_type,  mailimap_msg_att * mdt_msg_att);
 	void mailimap_message_data_free( mailimap_message_data * msg_data);


	enum {
	  MAILIMAP_MSG_ATT_ITEM_ERROR,   /* on parse error */
	  MAILIMAP_MSG_ATT_ITEM_DYNAMIC, /* dynamic message attributes (flags) */
	  MAILIMAP_MSG_ATT_ITEM_STATIC,  /* static messages attributes
	                                    (message content) */
	  MAILIMAP_MSG_ATT_ITEM_EXTENSION /* extension data */
	};


	struct mailimap_msg_att_item {
	  int att_type;
	  union att_data_t 
	  {
	    mailimap_msg_att_dynamic * att_dyn;   /* can be NULL */
	    mailimap_msg_att_static * att_static; /* can be NULL */
	    mailimap_extension_data * att_extension_data; /* can be NULL */
	  }
	  att_data_t att_data;
	};

	
	mailimap_msg_att_item * mailimap_msg_att_item_new(int att_type,  mailimap_msg_att_dynamic * att_dyn,  mailimap_msg_att_static * att_static,  mailimap_extension_data * att_extension_data);
	void mailimap_msg_att_item_free( mailimap_msg_att_item * item);

	struct mailimap_msg_att {
	  clist * att_list; /* list of (struct mailimap_msg_att_item *) */
	                /* != NULL */
	  uint32_t att_number; /* extra field to store the message number,
			     used for mailimap */
	};

	
	mailimap_msg_att * mailimap_msg_att_new(clist * att_list);
	void mailimap_msg_att_free( mailimap_msg_att * msg_att);
	struct mailimap_msg_att_dynamic {
	  clist * att_list; /* list of (struct mailimap_flag_fetch *) */
	  /* can be NULL */
	};

	
	mailimap_msg_att_dynamic * mailimap_msg_att_dynamic_new(clist * att_list);
	void mailimap_msg_att_dynamic_free( mailimap_msg_att_dynamic * msg_att_dyn);

	struct mailimap_msg_att_body_section {
	  mailimap_section * sec_section; /* != NULL */
	  uint32_t sec_origin_octet;
	  char * sec_body_part; /* can be NULL */
	  size_t sec_length;
	};

	
	mailimap_msg_att_body_section * mailimap_msg_att_body_section_new(mailimap_section * section, uint32_t sec_origin_octet, char * sec_body_part, size_t sec_length);
	void mailimap_msg_att_body_section_free( mailimap_msg_att_body_section * msg_att_body_section);

	enum {
	  MAILIMAP_MSG_ATT_ERROR,         /* on parse error */
	  MAILIMAP_MSG_ATT_ENVELOPE,      /* this is the fields that can be
	                                    parsed by the server */
	  MAILIMAP_MSG_ATT_INTERNALDATE,  /* this is the message date kept
	                                     by the server */
	  MAILIMAP_MSG_ATT_RFC822,        /* this is the message content
	                                     (header and body) */
	  MAILIMAP_MSG_ATT_RFC822_HEADER, /* this is the message header */
	  MAILIMAP_MSG_ATT_RFC822_TEXT,   /* this is the message text part */
	  MAILIMAP_MSG_ATT_RFC822_SIZE,   /* this is the size of the message content */
	  MAILIMAP_MSG_ATT_BODY,          /* this is the MIME description of
	                                     the message */
	  MAILIMAP_MSG_ATT_BODYSTRUCTURE, /* this is the MIME description of the
	                                     message with additional information */
	  MAILIMAP_MSG_ATT_BODY_SECTION,  /* this is a MIME part content */
	  MAILIMAP_MSG_ATT_UID            /* this is the message unique identifier */
	};


	struct mailimap_msg_att_static {
	  int att_type;
	  union att_data_t
	  {
	    mailimap_envelope * att_env;            /* can be NULL */
	    mailimap_date_time * att_internal_date; /* can be NULL */
	    struct att_rfc822_t
	    {
	      char * att_content; /* can be NULL */
	      size_t att_length;
	    }
	    att_rfc822_t att_rfc822;        
	    struct att_rfc822_header_t
	    {
	      char * att_content; /* can be NULL */
	      size_t att_length;
	    }
	    att_rfc822_header_t att_rfc822_header;
	    struct att_rfc822_text_t
	    {
	      char * att_content; /* can be NULL */
	      size_t att_length;
	    }
	    att_rfc822_text_t att_rfc822_text;
	    uint32_t att_rfc822_size;
	    mailimap_body * att_bodystructure; /* can be NULL */
	    mailimap_body * att_body;          /* can be NULL */
	    mailimap_msg_att_body_section * att_body_section; /* can be NULL */
	    uint32_t att_uid;
	  }
	  att_data_t att_data;
	}

	
	mailimap_msg_att_static * mailimap_msg_att_static_new(int att_type, mailimap_envelope * att_env, mailimap_date_time * att_internal_date, char * att_rfc822, char * att_rfc822_header, char * att_rfc822_text, size_t att_length, uint32_t att_rfc822_size, mailimap_body * att_bodystructure,  mailimap_body * att_body,  mailimap_msg_att_body_section * att_body_section, uint32_t att_uid);
	void mailimap_msg_att_static_free(mailimap_msg_att_static * item);

	enum {
	  MAILIMAP_RESP_ERROR,     /* on parse error */
	  MAILIMAP_RESP_CONT_REQ,  /* continuation request */
	  MAILIMAP_RESP_RESP_DATA  /* response data */
	};


	struct mailimap_cont_req_or_resp_data {
	  int rsp_type;
	  union rsp_data_t {
	    mailimap_continue_req * rsp_cont_req;   /* can be NULL */
	    mailimap_response_data * rsp_resp_data; /* can be NULL */
	  }
	  rsp_data_t rsp_data;
	};

	
	mailimap_cont_req_or_resp_data * mailimap_cont_req_or_resp_data_new(int rsp_type, mailimap_continue_req * rsp_cont_req, mailimap_response_data * rsp_resp_data);
	void mailimap_cont_req_or_resp_data_free(mailimap_cont_req_or_resp_data * cont_req_or_resp_data);

	struct mailimap_response {
	  clist * rsp_cont_req_or_resp_data_list;
	   mailimap_response_done * rsp_resp_done; /* != NULL */
	};

	
	mailimap_response * mailimap_response_new(clist * rsp_cont_req_or_resp_data_list,  mailimap_response_done * rsp_resp_done);
	void mailimap_response_free( mailimap_response * resp);

	enum {
	  MAILIMAP_RESP_DATA_TYPE_ERROR,           /* on parse error */
	  MAILIMAP_RESP_DATA_TYPE_COND_STATE,      /* condition state response */
	  MAILIMAP_RESP_DATA_TYPE_COND_BYE,        /* BYE response (server is about
	                                              to close the connection) */
	  MAILIMAP_RESP_DATA_TYPE_MAILBOX_DATA,    /* response related to a mailbox */
	  MAILIMAP_RESP_DATA_TYPE_MESSAGE_DATA,    /* response related to a message */
	  MAILIMAP_RESP_DATA_TYPE_CAPABILITY_DATA, /* capability information */
	  MAILIMAP_RESP_DATA_TYPE_EXTENSION_DATA   /* data parsed by extension */
	};

	struct mailimap_response_data {
	  int rsp_type;
	  union rsp_data_t
	  {
	     mailimap_resp_cond_state * rsp_cond_state;      /* can be NULL */
	     mailimap_resp_cond_bye * rsp_bye;               /* can be NULL */
	     mailimap_mailbox_data * rsp_mailbox_data;       /* can be NULL */
	     mailimap_message_data * rsp_message_data;       /* can be NULL */
	     mailimap_capability_data * rsp_capability_data; /* can be NULL */
	     mailimap_extension_data * rsp_extension_data;   /* can be NULL */
	  }
	  rsp_data_t rsp_data;
	};

	
	mailimap_response_data * mailimap_response_data_new(int rsp_type, mailimap_resp_cond_state * rsp_cond_state, mailimap_resp_cond_bye * rsp_bye, mailimap_mailbox_data * rsp_mailbox_data, mailimap_message_data * rsp_message_data, mailimap_capability_data * rsp_capability_data, mailimap_extension_data * rsp_extension_data);
	void mailimap_response_data_free( mailimap_response_data * resp_data);

	enum {
	  MAILIMAP_RESP_DONE_TYPE_ERROR,  /* on parse error */
	  MAILIMAP_RESP_DONE_TYPE_TAGGED, /* tagged response */
	  MAILIMAP_RESP_DONE_TYPE_FATAL   /* fatal error response */
	};
	struct mailimap_response_done {
	  int rsp_type;
	  union rsp_data_t
	  {
	     mailimap_response_tagged * rsp_tagged; /* can be NULL */
	     mailimap_response_fatal * rsp_fatal;   /* can be NULL */
	  }
	  rsp_data_t rsp_data;
	};

	
	 mailimap_response_done * mailimap_response_done_new(int rsp_type, mailimap_response_tagged * rsp_tagged, mailimap_response_fatal * rsp_fatal);
	void mailimap_response_done_free(mailimap_response_done * resp_done);
	struct mailimap_response_fatal {
	  mailimap_resp_cond_bye * rsp_bye; /* != NULL */
	};

	
	mailimap_response_fatal * mailimap_response_fatal_new( mailimap_resp_cond_bye * rsp_bye);
	void mailimap_response_fatal_free(mailimap_response_fatal * resp_fatal);
	struct mailimap_response_tagged {
	  char * rsp_tag; /* != NULL */
	  mailimap_resp_cond_state * rsp_cond_state; /* != NULL */
	};
	mailimap_response_tagged *
	mailimap_response_tagged_new(char * rsp_tag, mailimap_resp_cond_state * rsp_cond_state);
	void mailimap_response_tagged_free( mailimap_response_tagged * tagged);


	/* this is the type of an authentication condition response */

	enum {
	  MAILIMAP_RESP_COND_AUTH_ERROR,   /* on parse error */
	  MAILIMAP_RESP_COND_AUTH_OK,      /* authentication is needed */
	  MAILIMAP_RESP_COND_AUTH_PREAUTH  /* authentication is not needed */
	};


	struct mailimap_resp_cond_auth {
	  int rsp_type;
	  mailimap_resp_text * rsp_text; /* != NULL */
	};

	
	mailimap_resp_cond_auth * mailimap_resp_cond_auth_new(int rsp_type, mailimap_resp_text * rsp_text);
	void mailimap_resp_cond_auth_free(mailimap_resp_cond_auth * cond_auth);

	struct mailimap_resp_cond_bye {
	  mailimap_resp_text * rsp_text; /* != NULL */
	};

 	mailimap_resp_cond_bye * mailimap_resp_cond_bye_new(mailimap_resp_text * rsp_text);
	void mailimap_resp_cond_bye_free(mailimap_resp_cond_bye * cond_bye);

	enum {
	  MAILIMAP_RESP_COND_STATE_OK,
	  MAILIMAP_RESP_COND_STATE_NO,
	  MAILIMAP_RESP_COND_STATE_BAD
	};

	struct mailimap_resp_cond_state {
	  int rsp_type;
	  mailimap_resp_text * rsp_text; /* can be NULL */
	};
	
	mailimap_resp_cond_state * mailimap_resp_cond_state_new(int rsp_type,  mailimap_resp_text * rsp_text);
	void mailimap_resp_cond_state_free(mailimap_resp_cond_state * cond_state);
	struct mailimap_resp_text {
	  mailimap_resp_text_code * rsp_code; /* can be NULL */
	  char * rsp_text; /* can be NULL */
	};
	
	mailimap_resp_text * mailimap_resp_text_new(mailimap_resp_text_code * resp_code, char * rsp_text);
	void mailimap_resp_text_free(mailimap_resp_text * resp_text);

	enum {
	  MAILIMAP_RESP_TEXT_CODE_ALERT,           /* ALERT response */
	  MAILIMAP_RESP_TEXT_CODE_BADCHARSET,      /* BADCHARSET response */
	  MAILIMAP_RESP_TEXT_CODE_CAPABILITY_DATA, /* CAPABILITY response */
	  MAILIMAP_RESP_TEXT_CODE_PARSE,           /* PARSE response */
	  MAILIMAP_RESP_TEXT_CODE_PERMANENTFLAGS,  /* PERMANENTFLAGS response */
	  MAILIMAP_RESP_TEXT_CODE_READ_ONLY,       /* READONLY response */
	  MAILIMAP_RESP_TEXT_CODE_READ_WRITE,      /* READWRITE response */
	  MAILIMAP_RESP_TEXT_CODE_TRY_CREATE,      /* TRYCREATE response */
	  MAILIMAP_RESP_TEXT_CODE_UIDNEXT,         /* UIDNEXT response */
	  MAILIMAP_RESP_TEXT_CODE_UIDVALIDITY,     /* UIDVALIDITY response */
	  MAILIMAP_RESP_TEXT_CODE_UNSEEN,          /* UNSEEN response */
	  MAILIMAP_RESP_TEXT_CODE_OTHER,           /* other type of response */
	  MAILIMAP_RESP_TEXT_CODE_EXTENSION        /* extension response */
	};


	struct mailimap_resp_text_code {
	  int rc_type;
	  union rc_data_t 
	  {
	    clist * rc_badcharset; /* list of astring (char *) */
	    /* can be NULL */
	     mailimap_capability_data * rc_cap_data; /* != NULL */
	    clist * rc_perm_flags; /* list of (struct mailimap_flag_perm *) */
	    /* can be NULL */
	    uint32_t rc_uidnext;
	    uint32_t rc_uidvalidity;
	    uint32_t rc_first_unseen;
	    struct rc_atom_t
	    {
	      char * atom_name;  /* can be NULL */
	      char * atom_value; /* can be NULL */
	    }
	    rc_atom_t rc_atom;
	     mailimap_extension_data * rc_ext_data; /* can be NULL */
	  }
	  rc_data_t rc_data;
	};

	
	mailimap_resp_text_code * mailimap_resp_text_code_new(int rc_type, clist * rc_badcharset, mailimap_capability_data * rc_cap_data, clist * rc_perm_flags, uint32_t rc_uidnext, uint32_t rc_uidvalidity, uint32_t rc_first_unseen, char * rc_atom, char * rc_atom_value, mailimap_extension_data * rc_ext_data);
	
	void mailimap_resp_text_code_free( mailimap_resp_text_code * resp_text_code);


	/*
	  mailimap_section is a MIME part section identifier

	  section_spec is the MIME section identifier
	*/

	struct mailimap_section {
	  mailimap_section_spec * sec_spec; /* can be NULL */
	};

	
	mailimap_section * mailimap_section_new( mailimap_section_spec * sec_spec);
	void mailimap_section_free( mailimap_section * section);

	/* this is the type of the message/rfc822 part description */

	enum {
	  MAILIMAP_SECTION_MSGTEXT_HEADER,            /* header fields part of the
	                                                 message */
	  MAILIMAP_SECTION_MSGTEXT_HEADER_FIELDS,     /* given header fields of the
	                                                 message */
	  MAILIMAP_SECTION_MSGTEXT_HEADER_FIELDS_NOT, /* header fields of the
	                                                 message except the given */
	  MAILIMAP_SECTION_MSGTEXT_TEXT               /* text part  */
	};


	struct mailimap_section_msgtext {
	  int sec_type;
	   mailimap_header_list * sec_header_list; /* can be NULL */
	};

	
	mailimap_section_msgtext * mailimap_section_msgtext_new(int sec_type, mailimap_header_list * sec_header_list);
	void mailimap_section_msgtext_free(mailimap_section_msgtext * msgtext);



	/*
	  mailimap_section_part is the MIME part location in a message
	  
	  - section_id is a list of number index of the sub-part in the mail structure,
	    each element should be allocated with malloc()

	*/

	struct mailimap_section_part {
	  clist * sec_id; /* list of nz-number (uint32_t *) */
	                      /* != NULL */
	};

	
	mailimap_section_part * mailimap_section_part_new(clist * sec_id);

	
	void mailimap_section_part_free( mailimap_section_part * section_part);



	/* this is the type of section specification */

	enum {
	  MAILIMAP_SECTION_SPEC_SECTION_MSGTEXT, /* if requesting data of the root
	                                            MIME message/rfc822 part */
	  MAILIMAP_SECTION_SPEC_SECTION_PART     /* location of the MIME part
	                                            in the message */
	};

	struct mailimap_section_spec {
	  int sec_type;
	  union sec_data_t
	  {
	    mailimap_section_msgtext * sec_msgtext; /* can be NULL */
	    mailimap_section_part * sec_part;       /* can be NULL */
	  }
	  sec_data_t sec_data;
	  mailimap_section_text * sec_text;       /* can be NULL */
	};

	
	mailimap_section_spec * mailimap_section_spec_new(int sec_type, mailimap_section_msgtext * sec_msgtext, mailimap_section_part * sec_part, mailimap_section_text * sec_text);
	void mailimap_section_spec_free( mailimap_section_spec * section_spec);



	/* this is the type of body part location for a given MIME part */

	enum {
	  MAILIMAP_SECTION_TEXT_ERROR,           /* on parse error **/
	  MAILIMAP_SECTION_TEXT_SECTION_MSGTEXT, /* if the MIME type is
	                                            message/rfc822, headers or text
	                                            can be requested */
	  MAILIMAP_SECTION_TEXT_MIME             /* for all MIME types,
	                                            MIME headers can be requested */
	};

	struct mailimap_section_text {
	  int sec_type;
	  mailimap_section_msgtext * sec_msgtext; /* can be NULL */
	};

	
	mailimap_section_text * mailimap_section_text_new(int sec_type, mailimap_section_msgtext * sec_msgtext);
	void mailimap_section_text_free( mailimap_section_text * section_text);

	struct mailimap_set_item {
	  uint32_t set_first;
	  uint32_t set_last;
	};

	
	mailimap_set_item *mailimap_set_item_new(uint32_t set_first, uint32_t set_last);
	void mailimap_set_item_free(mailimap_set_item * set_item);



	/*
	  set is a list of message sets

	  - list is a list of message sets
	*/

	struct mailimap_set {
	  clist * set_list; /* list of (struct mailimap_set_item *) */
	};

	
	mailimap_set * mailimap_set_new(clist * list);
	void mailimap_set_free(mailimap_set * set);
	struct mailimap_date {
	  int dt_day;
	  int dt_month;
	  int dt_year;
	};

	
	mailimap_date * mailimap_date_new(int dt_day, int dt_month, int dt_year);

	
	void mailimap_date_free(mailimap_date * date);
	enum {
	  MAILIMAP_FETCH_ATT_ENVELOPE,          /* to fetch the headers parsed by
	                                           the IMAP server */
	  MAILIMAP_FETCH_ATT_FLAGS,             /* to fetch the flags */
	  MAILIMAP_FETCH_ATT_INTERNALDATE,      /* to fetch the date of the message
	                                           kept by the server */
	  MAILIMAP_FETCH_ATT_RFC822,            /* to fetch the entire message */
	  MAILIMAP_FETCH_ATT_RFC822_HEADER,     /* to fetch the headers */
	  MAILIMAP_FETCH_ATT_RFC822_SIZE,       /* to fetch the size */
	  MAILIMAP_FETCH_ATT_RFC822_TEXT,       /* to fetch the text part */
	  MAILIMAP_FETCH_ATT_BODY,              /* to fetch the MIME structure */
	  MAILIMAP_FETCH_ATT_BODYSTRUCTURE,     /* to fetch the MIME structure with
	                                           additional information */
	  MAILIMAP_FETCH_ATT_UID,               /* to fetch the unique identifier */
	  MAILIMAP_FETCH_ATT_BODY_SECTION,      /* to fetch a given part */
	  MAILIMAP_FETCH_ATT_BODY_PEEK_SECTION, /* to fetch a given part without
	                                           marking the message as read */
	  MAILIMAP_FETCH_ATT_EXTENSION
	}

	struct mailimap_fetch_att {
	  int att_type;
	  mailimap_section * att_section;
	  uint32_t att_offset;
	  uint32_t att_size;
	  char * att_extension; /* can be NULL */
	};

	
	mailimap_fetch_att * mailimap_fetch_att_new(int att_type, mailimap_section * att_section, uint32_t att_offset, uint32_t att_size, char * att_extension);
	void mailimap_fetch_att_free(mailimap_fetch_att * fetch_att);


	/* this is the type of a FETCH operation */

	enum {
	  MAILIMAP_FETCH_TYPE_ALL,            /* equivalent to (FLAGS INTERNALDATE
	                                         RFC822.SIZE ENVELOPE) */
	  MAILIMAP_FETCH_TYPE_FULL,           /* equivalent to (FLAGS INTERNALDATE
	                                         RFC822.SIZE ENVELOPE BODY) */
	  MAILIMAP_FETCH_TYPE_FAST,           /* equivalent to (FLAGS INTERNALDATE
	                                         RFC822.SIZE) */
	  MAILIMAP_FETCH_TYPE_FETCH_ATT,      /* when there is only of fetch
	                                         attribute */
	  MAILIMAP_FETCH_TYPE_FETCH_ATT_LIST  /* when there is a list of fetch
	                                         attributes */
	};


	struct mailimap_fetch_type {
	  int ft_type;
	  union ft_data_t
	  {
	    mailimap_fetch_att * ft_fetch_att;
	    clist * ft_fetch_att_list; /* list of (struct mailimap_fetch_att *) */
	  }
	  ft_data_t ft_data;
	};

	
	mailimap_fetch_type * mailimap_fetch_type_new(int ft_type, mailimap_fetch_att * ft_fetch_att, clist * ft_fetch_att_list);
	void mailimap_fetch_type_free(mailimap_fetch_type * fetch_type);


	struct mailimap_store_att_flags {
	  int fl_sign;
	  int fl_silent;
	  mailimap_flag_list * fl_flag_list;
	};

	
	mailimap_store_att_flags * mailimap_store_att_flags_new(int fl_sign, int fl_silent, mailimap_flag_list * fl_flag_list);
	void mailimap_store_att_flags_free(mailimap_store_att_flags * store_att_flags);



	/* this is the condition of the SEARCH operation */

	enum {
	  MAILIMAP_SEARCH_KEY_ALL,        /* all messages */
	  MAILIMAP_SEARCH_KEY_ANSWERED,   /* messages with the flag \Answered */
	  MAILIMAP_SEARCH_KEY_BCC,        /* messages whose Bcc field contains the
	                                     given string */
	  MAILIMAP_SEARCH_KEY_BEFORE,     /* messages whose internal date is earlier
	                                     than the specified date */
	  MAILIMAP_SEARCH_KEY_BODY,       /* message that contains the given string
	                                     (in header and text parts) */
	  MAILIMAP_SEARCH_KEY_CC,         /* messages whose Cc field contains the
	                                     given string */
	  MAILIMAP_SEARCH_KEY_DELETED,    /* messages with the flag \Deleted */
	  MAILIMAP_SEARCH_KEY_FLAGGED,    /* messages with the flag \Flagged */ 
	  MAILIMAP_SEARCH_KEY_FROM,       /* messages whose From field contains the
	                                     given string */
	  MAILIMAP_SEARCH_KEY_KEYWORD,    /* messages with the flag keyword set */
	  MAILIMAP_SEARCH_KEY_NEW,        /* messages with the flag \Recent and not
	                                     the \Seen flag */
	  MAILIMAP_SEARCH_KEY_OLD,        /* messages that do not have the
	                                     \Recent flag set */
	  MAILIMAP_SEARCH_KEY_ON,         /* messages whose internal date is the
	                                     specified date */
	  MAILIMAP_SEARCH_KEY_RECENT,     /* messages with the flag \Recent */
	  MAILIMAP_SEARCH_KEY_SEEN,       /* messages with the flag \Seen */
	  MAILIMAP_SEARCH_KEY_SINCE,      /* messages whose internal date is later
	                                     than specified date */
	  MAILIMAP_SEARCH_KEY_SUBJECT,    /* messages whose Subject field contains the
	                                     given string */
	  MAILIMAP_SEARCH_KEY_TEXT,       /* messages whose text part contains the
	                                     given string */
	  MAILIMAP_SEARCH_KEY_TO,         /* messages whose To field contains the
	                                     given string */
	  MAILIMAP_SEARCH_KEY_UNANSWERED, /* messages with no flag \Answered */
	  MAILIMAP_SEARCH_KEY_UNDELETED,  /* messages with no flag \Deleted */
	  MAILIMAP_SEARCH_KEY_UNFLAGGED,  /* messages with no flag \Flagged */
	  MAILIMAP_SEARCH_KEY_UNKEYWORD,  /* messages with no flag keyword */ 
	  MAILIMAP_SEARCH_KEY_UNSEEN,     /* messages with no flag \Seen */
	  MAILIMAP_SEARCH_KEY_DRAFT,      /* messages with no flag \Draft */
	  MAILIMAP_SEARCH_KEY_HEADER,     /* messages whose given field 
	                                     contains the given string */
	  MAILIMAP_SEARCH_KEY_LARGER,     /* messages whose size is larger then
	                                     the given size */
	  MAILIMAP_SEARCH_KEY_NOT,        /* not operation of the condition */
	  MAILIMAP_SEARCH_KEY_OR,         /* or operation between two conditions */
	  MAILIMAP_SEARCH_KEY_SENTBEFORE, /* messages whose date given in Date header
	                                     is earlier than the specified date */
	  MAILIMAP_SEARCH_KEY_SENTON,     /* messages whose date given in Date header
	                                     is the specified date */
	  MAILIMAP_SEARCH_KEY_SENTSINCE,  /* messages whose date given in Date header
	                                     is later than specified date */
	  MAILIMAP_SEARCH_KEY_SMALLER,    /* messages whose size is smaller than
	                                     the given size */
	  MAILIMAP_SEARCH_KEY_UID,        /* messages whose unique identifiers are
	                                     in the given range */
	  MAILIMAP_SEARCH_KEY_UNDRAFT,    /* messages with no flag \Draft */
	  MAILIMAP_SEARCH_KEY_SET,        /* messages whose number (or unique
	                                     identifiers in case of UID SEARCH) are
	                                     in the given range */
	  MAILIMAP_SEARCH_KEY_MULTIPLE,   /* the boolean operator between the
	                                     conditions is AND */
	  MAILIMAP_SEARCH_KEY_MODSEQ,     /* mod sequence */
	  MAILIMAP_SEARCH_KEY_XGMTHRID,   /* Gmail thread id */
	  MAILIMAP_SEARCH_KEY_XGMMSGID,   /* Gmail Message id */
	  MAILIMAP_SEARCH_KEY_XGMRAW      /* Gmail RAW expression */
	};
	enum {
		MAILIMAP_SEARCH_KEY_MODSEQ_ENTRY_TYPE_REQ_PRIV,
		MAILIMAP_SEARCH_KEY_MODSEQ_ENTRY_TYPE_REQ_SHARED,
		MAILIMAP_SEARCH_KEY_MODSEQ_ENTRY_TYPE_REQ_ALL,
	};

	struct mailimap_search_key {
	  int sk_type;
	  union sk_data_t
	  {
	    char * sk_bcc;
	    mailimap_date * sk_before;
	    char * sk_body;
	    char * sk_cc;
	    char * sk_from;
	    char * sk_keyword;
	    mailimap_date * sk_on;
	    mailimap_date * sk_since;
	    char * sk_subject;
	    char * sk_text;
	    char * sk_to;
	    char * sk_unkeyword;
	    struct sk_header_t
	    {
	      char * sk_header_name;
	      char * sk_header_value;
	    }
	    sk_header_t sk_header;
	    uint32_t sk_larger;
	    mailimap_search_key * sk_not;
	    struct sk_or_t
	    {
	       mailimap_search_key * sk_or1;
	       mailimap_search_key * sk_or2;
	    }
	    sk_or_t sk_or;
	    mailimap_date * sk_sentbefore;
	    mailimap_date * sk_senton;
	    mailimap_date * sk_sentsince;
	    uint32_t sk_smaller;
	    mailimap_set * sk_uid;
	    mailimap_set * sk_set;
	    uint64_t sk_xgmthrid;
	    uint64_t sk_xgmmsgid;
	    char * sk_xgmraw;
	    clist * sk_multiple; /* list of (struct mailimap_search_key *) */
	    struct sk_modseq_t
	    {
	      mailimap_flag * sk_entry_name;
	      int sk_entry_type_req;
	      uint64_t sk_modseq_valzer;
	    }
	    sk_modseq_t sk_modseq;
	  }
	  sk_data_t sk_data;
	};

	
	mailimap_search_key *
	mailimap_search_key_new(int sk_type,
	    char * sk_bcc, mailimap_date * sk_before, char * sk_body,
	    char * sk_cc, char * sk_from, char * sk_keyword,
	    mailimap_date * sk_on,  mailimap_date * sk_since,
	    char * sk_subject, char * sk_text, char * sk_to,
	    char * sk_unkeyword, char * sk_header_name,
	    char * sk_header_value, uint32_t sk_larger,
	    mailimap_search_key * sk_not,
	    mailimap_search_key * sk_or1,
	    mailimap_search_key * sk_or2,
	    mailimap_date * sk_sentbefore,
	    mailimap_date * sk_senton,
	    mailimap_date * sk_sentsince,
	    uint32_t sk_smaller, mailimap_set * sk_uid,
	    mailimap_set * sk_set, clist * sk_multiple);
	  
	/*
	  this function creates a condition structure to match messages with
	  the given gmail thread id
	*/

	
	mailimap_search_key * mailimap_search_key_new_xgmthrid(uint64_t sk_xgmthrid);
	mailimap_search_key * mailimap_search_key_new_xgmmsgid(uint64_t sk_xgmmsgid);
	mailimap_search_key * mailimap_search_key_new_xgmraw(char * sk_xgmraw);
	void mailimap_search_key_free( mailimap_search_key * key);

	struct mailimap_status_att_list {
	  clist * att_list; /* list of (uint32_t *) */
	};

	mailimap_status_att_list * mailimap_status_att_list_new(clist * att_list);
	void mailimap_status_att_list_free(mailimap_status_att_list * status_att_list);

	uint32_t * mailimap_number_alloc_new(uint32_t number);
	void mailimap_number_alloc_free(uint32_t * pnumber);
	void mailimap_addr_host_free(char * addr_host);
	void mailimap_addr_mailbox_free(char * addr_mailbox);
	void mailimap_addr_adl_free(char * addr_adl);
	void mailimap_addr_name_free(char * addr_name);
	void mailimap_astring_free(char * astring);
	void mailimap_atom_free(char * atom);
	void mailimap_auth_type_free(char * auth_type);
	void mailimap_base64_free(char * base64);
	void mailimap_body_fld_desc_free(char * body_fld_desc);
	void mailimap_body_fld_id_free(char * body_fld_id);
	void mailimap_body_fld_md5_free(char * body_fld_md5);
	void mailimap_body_fld_loc_free(char * body_fld_loc);
	void mailimap_env_date_free(char * date);
	void mailimap_env_in_reply_to_free(char * in_reply_to);
	void mailimap_env_message_id_free(char * message_id);
	void mailimap_env_subject_free(char * subject);
	void mailimap_flag_extension_free(char * flag_extension);
	void mailimap_flag_keyword_free(char * flag_keyword);
	void mailimap_header_fld_name_free(char * header_fld_name);
	void mailimap_literal_free(char * literal);
	void mailimap_mailbox_free(char * mailbox);
	void mailimap_mailbox_data_search_free(clist * data_search);
	void mailimap_media_subtype_free(char * media_subtype);
	void mailimap_media_text_free(char * media_text);
	void mailimap_msg_att_envelope_free(mailimap_envelope * env);
	void mailimap_msg_att_internaldate_free(mailimap_date_time * date_time);
	void mailimap_msg_att_rfc822_free(char * str);
	void mailimap_msg_att_rfc822_header_free(char * str);
	void mailimap_msg_att_rfc822_text_free(char * str);
	void mailimap_msg_att_body_free(mailimap_body * _body);
	void mailimap_msg_att_bodystructure_free(mailimap_body * _body);
	void mailimap_nstring_free(char * str);
	void mailimap_string_free(char * str);
	void mailimap_tag_free(char * tag);
	void mailimap_text_free(char * text);

	enum {
	  MAILIMAP_STATE_DISCONNECTED,
	  MAILIMAP_STATE_NON_AUTHENTICATED,
	  MAILIMAP_STATE_AUTHENTICATED,
	  MAILIMAP_STATE_SELECTED,
	  MAILIMAP_STATE_LOGOUT
	};

	//typedef void
	alias mailimap_msg_att_handler=void function( mailimap_msg_att * msg_att, void * context);


	struct mailimap {
	  char * imap_response;
	  
	  /* internals */
	  mailstream * imap_stream;

	  size_t imap_progr_rate;
	  progress_function * imap_progr_fun;

	  MMAPString * imap_stream_buffer;
	  MMAPString * imap_response_buffer;

	  int imap_state;
	  int imap_tag;

	  mailimap_connection_info * imap_connection_info;
	  mailimap_selection_info * imap_selection_info;
	  mailimap_response_info * imap_response_info;
	  
	  struct imap_sasl_t
	  {
	    void * sasl_conn;
	    const char * sasl_server_fqdn;
	    const char * sasl_login;
	    const char * sasl_auth_name;
	    const char * sasl_password;
	    const char * sasl_realm;
	    void * sasl_secret;
	  }
	  imap_sasl_t imap_sasl;
	  
	  time_t imap_idle_timestamp;
	  time_t imap_idle_maxdelay;

	  mailprogress_function * imap_body_progress_fun;
	  mailprogress_function * imap_items_progress_fun;
	  void * imap_progress_context;
	  mailimap_msg_att_handler * imap_msg_att_handler;
	  void * imap_msg_att_handler_context;

	  time_t imap_timeout;
	  
	  void function(mailimap * session, int log_type, const char * str, size_t size, void * context) imap_logger;
	  void * imap_logger_context;
	};


	struct mailimap_connection_info {
	  mailimap_capability_data * imap_capability;
	};

	mailimap_connection_info * mailimap_connection_info_new();
	void mailimap_connection_info_free( mailimap_connection_info * conn_info);
	

	/* this is the type of mailbox access */

	enum {
	  MAILIMAP_MAILBOX_READONLY,
	  MAILIMAP_MAILBOX_READWRITE
	};

	struct mailimap_selection_info {
	  clist * sel_perm_flags; /* list of (struct flag_perm *) */
	  int sel_perm;
	  uint32_t sel_uidnext;
	  uint32_t sel_uidvalidity;
	  uint32_t sel_first_unseen;
	  mailimap_flag_list * sel_flags;
	  uint32_t sel_exists;
	  uint32_t sel_recent;
	  uint32_t sel_unseen;
	  /* bitmap argh */
	  //uint8_t  sel_has_exists:1;
	  //uint8_t  sel_has_recent:1;
	  union bitmap_t
	  {
	  	uint8_t sel_has_exists_recent;
	  	uint8_t sel_has_recent;
	  }
	  bitmap_t sel_has;
	};

	mailimap_selection_info * mailimap_selection_info_new();
	void mailimap_selection_info_free(mailimap_selection_info * sel_info);

	struct mailimap_response_info {
	  char * rsp_alert;
	  char * rsp_parse;
	  clist * rsp_badcharset; /* list of (char *) */
	  int rsp_trycreate;
	  clist * rsp_mailbox_list; /* list of (struct mailimap_mailbox_list *) */
	  clist * rsp_mailbox_lsub; /* list of (struct mailimap_mailbox_list *) */
	  clist * rsp_search_result; /* list of (uint32_t *) */
	  mailimap_mailbox_data_status * rsp_status;
	  clist * rsp_expunged; /* list of (uint32_t 32 *) */
	  clist * rsp_fetch_list; /* list of (struct mailimap_msg_att *) */
	  clist * rsp_extension_list; /* list of (struct mailimap_extension_data *) */
	  char * rsp_atom;
	  char * rsp_value;
	};

	
	mailimap_response_info * mailimap_response_info_new();
	void mailimap_response_info_free( mailimap_response_info * resp_info);


	/* these are the possible returned error codes */

	enum {
	  MAILIMAP_NO_ERROR = 0,
	  MAILIMAP_NO_ERROR_AUTHENTICATED = 1,
	  MAILIMAP_NO_ERROR_NON_AUTHENTICATED = 2,
	  MAILIMAP_ERROR_BAD_STATE,
	  MAILIMAP_ERROR_STREAM,
	  MAILIMAP_ERROR_PARSE,
	  MAILIMAP_ERROR_CONNECTION_REFUSED,
	  MAILIMAP_ERROR_MEMORY,
	  MAILIMAP_ERROR_FATAL,
	  MAILIMAP_ERROR_PROTOCOL,
	  MAILIMAP_ERROR_DONT_ACCEPT_CONNECTION,
	  MAILIMAP_ERROR_APPEND,
	  MAILIMAP_ERROR_NOOP,
	  MAILIMAP_ERROR_LOGOUT,
	  MAILIMAP_ERROR_CAPABILITY,
	  MAILIMAP_ERROR_CHECK,
	  MAILIMAP_ERROR_CLOSE,
	  MAILIMAP_ERROR_EXPUNGE,
	  MAILIMAP_ERROR_COPY,
	  MAILIMAP_ERROR_UID_COPY,
	  MAILIMAP_ERROR_CREATE,
	  MAILIMAP_ERROR_DELETE,
	  MAILIMAP_ERROR_EXAMINE,
	  MAILIMAP_ERROR_FETCH,
	  MAILIMAP_ERROR_UID_FETCH,
	  MAILIMAP_ERROR_LIST,
	  MAILIMAP_ERROR_LOGIN,
	  MAILIMAP_ERROR_LSUB,
	  MAILIMAP_ERROR_RENAME,
	  MAILIMAP_ERROR_SEARCH,
	  MAILIMAP_ERROR_UID_SEARCH,
	  MAILIMAP_ERROR_SELECT,
	  MAILIMAP_ERROR_STATUS,
	  MAILIMAP_ERROR_STORE,
	  MAILIMAP_ERROR_UID_STORE,
	  MAILIMAP_ERROR_SUBSCRIBE,
	  MAILIMAP_ERROR_UNSUBSCRIBE,
	  MAILIMAP_ERROR_STARTTLS,
	  MAILIMAP_ERROR_INVAL,
	  MAILIMAP_ERROR_EXTENSION,
	  MAILIMAP_ERROR_SASL,
	  MAILIMAP_ERROR_SSL,
	  MAILIMAP_ERROR_NEEDS_MORE_DATA
	};


	int mailimap_uid_expunge_send(mailstream * fd, mailimap_set * set);

	int mailimap_fetch_qresync_vanished(mailimap * session,
	                                    mailimap_set * set,
	                                     mailimap_fetch_type * fetch_type, uint64_t mod_sequence_value, int vanished,
	                                    clist ** fetch_result,  mailimap_qresync_vanished ** p_vanished);

	int mailimap_uid_fetch_qresync_vanished(mailimap * session,  mailimap_set * set, mailimap_fetch_type * fetch_type, uint64_t mod_sequence_value, int vanished, clist ** fetch_result, mailimap_qresync_vanished ** p_vanished);

	enum {
	  MAILIMAP_NAMESPACE_TYPE_NAMESPACE
	};

	struct mailimap_namespace_response_extension {
	  char * ns_name; /* != NULL */
	  clist * ns_values; /* != NULL, list of char * */
	};

	
	mailimap_namespace_response_extension * mailimap_namespace_response_extension_new(char * name, clist * values);

	
	void mailimap_namespace_response_extension_free( mailimap_namespace_response_extension * ext);

	struct mailimap_namespace_info {
	  char * ns_prefix; /* != NULL */
	  char ns_delimiter;
	  clist * ns_extensions; /* can be NULL, list of mailimap_namespace_response_extension */
	};

	mailimap_namespace_info * mailimap_namespace_info_new(char * prefix, char delimiter, clist * extensions);
	void mailimap_namespace_info_free(mailimap_namespace_info * info);

	struct mailimap_namespace_item {
	  clist * ns_data_list; /* != NULL, list of mailimap_namespace_info */
	};

	mailimap_namespace_item * mailimap_namespace_item_new(clist * data_list);
	void mailimap_namespace_item_free(mailimap_namespace_item * item);

	struct mailimap_namespace_data {
	  mailimap_namespace_item * ns_personal; /* can be NULL */
	  mailimap_namespace_item * ns_other; /* can be NULL */
	  mailimap_namespace_item * ns_shared; /* can be NULL */
	};

	mailimap_namespace_data * mailimap_namespace_data_new( mailimap_namespace_item * personal, mailimap_namespace_item * other,  mailimap_namespace_item * _shared);

	void mailimap_namespace_data_free(mailimap_namespace_data * ns);
	__gshared mailimap_extension_api mailimap_extension_quota;
	void mailimap_quota_free(mailimap_extension_data * ext_data);
	int mailimap_quota_getquotaroot(mailimap * session, const char * list_mb, mailimap_quota_complete_data ** result);
	int mailimap_ssl_connect(mailimap * f, const char * server, uint16_t port);
	int mailimap_ssl_connect_voip(mailimap * f, const char * server, uint16_t port, int voip_enabled);
	int mailimap_ssl_connect_with_callback(mailimap * f, const char * server, uint16_t port, void function(mailstream_ssl_context * ssl_context, void * data) callback, void * data);
	int mailimap_ssl_connect_voip_with_callback(mailimap * f, const char * server, uint16_t port, int voip_enabled, void function(mailstream_ssl_context * ssl_context, void * data) callback, void * data);


	enum {
	  MAILDIR_NO_ERROR = 0,
	  MAILDIR_ERROR_CREATE,
	  MAILDIR_ERROR_DIRECTORY,
	  MAILDIR_ERROR_MEMORY,
	  MAILDIR_ERROR_FILE,
	  MAILDIR_ERROR_NOT_FOUND,
	  MAILDIR_ERROR_FOLDER
	};

	enum MAILDIR_FLAG_NEW      =(1 << 0);
	enum MAILDIR_FLAG_SEEN     =(1 << 1);
	enum MAILDIR_FLAG_REPLIED  =(1 << 2);
	enum MAILDIR_FLAG_FLAGGED  =(1 << 3);
	enum MAILDIR_FLAG_TRASHED  =(1 << 4);

	struct maildir_msg {
	  char * msg_uid;
	  char * msg_filename;
	  int msg_flags;
	};

	enum HOST_NAME_MAX=255;

	struct maildir {
	  pid_t mdir_pid;
	  char[HOST_NAME_MAX] mdir_hostname;
	  char[PATH_MAX] mdir_path;
	  uint32_t mdir_counter;
	  time_t mdir_mtime_new;
	  time_t mdir_mtime_cur;
	  carray * mdir_msg_list;
	  chash * mdir_msg_hash;
	};


	maildir * maildir_new(const char * path);
	void maildir_free(maildir * md);
	int maildir_update( maildir * md);
	int maildir_message_add_uid( maildir * md, const char * message, size_t size, char * uid, size_t max_uid_len);
	int maildir_message_add( maildir * md, const char * message, size_t size);
	int maildir_message_add_file_uid( maildir * md, int fd, char * uid, size_t max_uid_len);
	int maildir_message_add_file( maildir * md, int fd);
	char * maildir_message_get( maildir * md, const char * uid);
	int maildir_message_remove( maildir * md, const char * uid);
	int maildir_message_change_flags( maildir * md, const char * uid, int new_flags);
	int mailimf_string_write_mem(MMAPString * f, int * col, const char * str, size_t length);
	int mailimf_fields_write_mem(MMAPString * f, int * col,  mailimf_fields * fields);
	int mailimf_envelope_fields_write_mem(MMAPString * f, int * col,  mailimf_fields * fields);
	int mailimf_field_write_mem(MMAPString * f, int * col, mailimf_field * field);
	int mailimf_quoted_string_write_mem(MMAPString * f, int * col, const char * string, size_t len);
	int mailimf_address_list_write_mem(MMAPString * f, int * col,  mailimf_address_list * addr_list);
	int mailimf_mailbox_list_write_mem(MMAPString * f, int * col,  mailimf_mailbox_list * mb_list);
	int mailimf_header_string_write_mem(MMAPString * f, int * col, const char * str, size_t length);
	int mailimf_string_write(FILE * f, int * col, const char * str, size_t length);
	int mailimf_fields_write(FILE * f, int * col, mailimf_fields * fields);
	int mailimf_envelope_fields_write(FILE * f, int * col,  mailimf_fields * fields);
	int mailimf_field_write(FILE * f, int * col,  mailimf_field * field);
	int mailimf_quoted_string_write(FILE * f, int * col, const char * string, size_t len);
	int mailimf_address_list_write(FILE * f, int * col,  mailimf_address_list * addr_list);
	int mailimf_mailbox_list_write(FILE * f, int * col,  mailimf_mailbox_list * mb_list);
	int mailimf_header_string_write(FILE * f, int * col, const char * str, size_t length);
	int mailimf_string_write_file(FILE * f, int * col, const char * str, size_t length);
	int mailimf_fields_write_file(FILE * f, int * col,  mailimf_fields * fields);
	int mailimf_envelope_fields_write_file(FILE * f, int * col,  mailimf_fields * fields);
	int mailimf_field_write_file(FILE * f, int * col, mailimf_field * field);
	int mailimf_quoted_string_write_file(FILE * f, int * col, const char * string, size_t len);
	int mailimf_address_list_write_file(FILE * f, int * col,  mailimf_address_list * addr_list);
	int mailimf_mailbox_list_write_file(FILE * f, int * col,  mailimf_mailbox_list * mb_list);
	int mailimf_header_string_write_file(FILE * f, int * col, const char * str, size_t length);
	int mailimf_message_parse(const char * message, size_t length, size_t * indx, mailimf_message ** result);
	int mailimf_body_parse(const char * message, size_t length, size_t * indx, mailimf_body ** result);
	int mailimf_fields_parse(const char * message, size_t length, size_t * indx,  mailimf_fields ** result);
	int mailimf_mailbox_list_parse(const char * message, size_t length, size_t * indx,  mailimf_mailbox_list ** result);
	int mailimf_address_list_parse(const char * message, size_t length, size_t * indx, mailimf_address_list ** result);
	int mailimf_address_parse(const char * message, size_t length, size_t * indx, mailimf_address ** result);
	int mailimf_mailbox_parse(const char * message, size_t length, size_t * indx, mailimf_mailbox ** result);
	int mailimf_date_time_parse(const char * message, size_t length, size_t * indx,  mailimf_date_time ** result);
	int mailimf_envelope_fields_parse(const char * message, size_t length, size_t * indx, mailimf_fields ** result);
	int mailimf_ignore_field_parse(const char * message, size_t length, size_t * indx);
	int mailimf_envelope_and_optional_fields_parse(const char * message, size_t length, size_t * indx,  mailimf_fields ** result);
	int mailimf_optional_fields_parse(const char * message, size_t length, size_t * indx, mailimf_fields ** result);
	int mailimf_fws_parse(const char * message, size_t length, size_t * indx);
	int mailimf_cfws_parse(const char * message, size_t length, size_t * indx);
	int mailimf_char_parse(const char * message, size_t length, size_t * indx, char token);
	int mailimf_unstrict_char_parse(const char * message, size_t length, size_t * indx, char token);
	int mailimf_crlf_parse(const char * message, size_t length, size_t * indx);
	int mailimf_custom_string_parse(const char * message, size_t length, size_t * indx, char ** result, int function(char)is_custom_char);
	int mailimf_token_case_insensitive_len_parse(const char * message, size_t length, size_t * indx, char * token, size_t token_length);

	auto mailimf_token_case_insensitive_parse(T)(T message, T length,T indx, Ttoken)
	{
		return mailimf_token_case_insensitive_len_parse(message, length, indx, token, strlen(token));
	}

	int mailimf_quoted_string_parse(const char * message, size_t length, size_t * indx, char ** result);
	int mailimf_number_parse(const char * message, size_t length, size_t * indx, uint32_t * result);
	int mailimf_msg_id_parse(const char * message, size_t length, size_t * indx, char ** result);
	int mailimf_msg_id_list_parse(const char * message, size_t length, size_t * indx, clist ** result);
	int mailimf_word_parse(const char * message, size_t length, size_t * indx, char ** result);
	int mailimf_atom_parse(const char * message, size_t length, size_t * indx, char ** result);
	int mailimf_fws_atom_parse(const char * message, size_t length, size_t * indx, char ** result);
	int mailimf_fws_word_parse(const char * message, size_t length, size_t * indx, char ** result);
	int mailimf_fws_quoted_string_parse(const char * message, size_t length, size_t * indx, char ** result);
	int mailimf_references_parse(const char * message, size_t length, size_t * indx,  mailimf_references ** result);
	struct mailimf_date_time {
	  int dt_day;
	  int dt_month;
	  int dt_year;
	  int dt_hour;
	  int dt_min;
	  int dt_sec;
	  int dt_zone;
	}

	 mailimf_date_time * mailimf_date_time_new(int dt_day, int dt_month, int dt_year, int dt_hour, int dt_min, int dt_sec, int dt_zone);
	void mailimf_date_time_free(mailimf_date_time * date_time);

	enum {
	  MAILIMF_ADDRESS_ERROR,   /* on parse error */
	  MAILIMF_ADDRESS_MAILBOX, /* if this is a mailbox (mailbox@domain) */
	  MAILIMF_ADDRESS_GROUP    /* if this is a group
	                              (group_name: address1@domain1,
	                                  address2@domain2; ) */
	}

	struct mailimf_address {
	  int ad_type;
	  union ad_data_t
	  {
	     mailimf_mailbox * ad_mailbox; /* can be NULL */
	     mailimf_group * ad_group;     /* can be NULL */
	  }
	  ad_data_t ad_data;
	}

	mailimf_address * mailimf_address_new(int ad_type,  mailimf_mailbox * ad_mailbox,  mailimf_group * ad_group);
	void mailimf_address_free(mailimf_address * address);
	struct mailimf_mailbox {
	  char * mb_display_name; /* can be NULL */
	  char * mb_addr_spec;    /* != NULL */
	}

	mailimf_mailbox * mailimf_mailbox_new(char * mb_display_name, char * mb_addr_spec);
	void mailimf_mailbox_free( mailimf_mailbox * mailbox);


	struct mailimf_group {
	  char * grp_display_name; /* != NULL */
	   mailimf_mailbox_list * grp_mb_list; /* can be NULL */
	};

	mailimf_group * mailimf_group_new(char * grp_display_name,  mailimf_mailbox_list * grp_mb_list);
	void mailimf_group_free(mailimf_group * group);

	struct mailimf_mailbox_list {
	  clist * mb_list; /* list of (struct mailimf_mailbox *), != NULL */
	};

	mailimf_mailbox_list * mailimf_mailbox_list_new(clist * mb_list);
	void mailimf_mailbox_list_free( mailimf_mailbox_list * mb_list);

	struct mailimf_address_list {
	  clist * ad_list; /* list of (struct mailimf_address *), != NULL */
	};

	mailimf_address_list * mailimf_address_list_new(clist * ad_list);
	void mailimf_address_list_free(mailimf_address_list * addr_list);

	struct mailimf_body {
	  const char * bd_text; /* != NULL */
	  size_t bd_size;
	}

	mailimf_body * mailimf_body_new(const char * bd_text, size_t bd_size);
	void mailimf_body_free(mailimf_body * _body);

	struct mailimf_message {
	  mailimf_fields * msg_fields; /* != NULL */
	  mailimf_body * msg_body;     /* != NULL */
	};

	mailimf_message * mailimf_message_new( mailimf_fields * msg_fields, mailimf_body * msg_body);
	void mailimf_message_free(mailimf_message * message);

	struct mailimf_fields {
	  clist * fld_list; /* list of (struct mailimf_field *), != NULL */
	};

	 mailimf_fields * mailimf_fields_new(clist * fld_list);
	void mailimf_fields_free( mailimf_fields * fields);

	/* this is a type of field */

	enum {
	  MAILIMF_FIELD_NONE,           /* on parse error */
	  MAILIMF_FIELD_RETURN_PATH,    /* Return-Path */
	  MAILIMF_FIELD_RESENT_DATE,    /* Resent-Date */
	  MAILIMF_FIELD_RESENT_FROM,    /* Resent-From */
	  MAILIMF_FIELD_RESENT_SENDER,  /* Resent-Sender */
	  MAILIMF_FIELD_RESENT_TO,      /* Resent-To */
	  MAILIMF_FIELD_RESENT_CC,      /* Resent-Cc */
	  MAILIMF_FIELD_RESENT_BCC,     /* Resent-Bcc */
	  MAILIMF_FIELD_RESENT_MSG_ID,  /* Resent-Message-ID */
	  MAILIMF_FIELD_ORIG_DATE,      /* Date */
	  MAILIMF_FIELD_FROM,           /* From */
	  MAILIMF_FIELD_SENDER,         /* Sender */
	  MAILIMF_FIELD_REPLY_TO,       /* Reply-To */
	  MAILIMF_FIELD_TO,             /* To */
	  MAILIMF_FIELD_CC,             /* Cc */
	  MAILIMF_FIELD_BCC,            /* Bcc */
	  MAILIMF_FIELD_MESSAGE_ID,     /* Message-ID */
	  MAILIMF_FIELD_IN_REPLY_TO,    /* In-Reply-To */
	  MAILIMF_FIELD_REFERENCES,     /* References */
	  MAILIMF_FIELD_SUBJECT,        /* Subject */
	  MAILIMF_FIELD_COMMENTS,       /* Comments */
	  MAILIMF_FIELD_KEYWORDS,       /* Keywords */
	  MAILIMF_FIELD_OPTIONAL_FIELD  /* other field */
	};


	enum LIBETPAN_MAILIMF_FIELD_UNION=1;

	struct mailimf_field {
	  int fld_type;
	  union fld_data_t {
	     mailimf_return * fld_return_path;              /* can be NULL */
	     mailimf_orig_date * fld_resent_date;    /* can be NULL */
	     mailimf_from * fld_resent_from;         /* can be NULL */
	     mailimf_sender * fld_resent_sender;     /* can be NULL */
	     mailimf_to * fld_resent_to;             /* can be NULL */
	     mailimf_cc * fld_resent_cc;             /* can be NULL */
	     mailimf_bcc * fld_resent_bcc;           /* can be NULL */
	     mailimf_message_id * fld_resent_msg_id; /* can be NULL */
	     mailimf_orig_date * fld_orig_date;             /* can be NULL */
	     mailimf_from * fld_from;                       /* can be NULL */
	     mailimf_sender * fld_sender;                   /* can be NULL */
	     mailimf_reply_to * fld_reply_to;               /* can be NULL */
	     mailimf_to * fld_to;                           /* can be NULL */
	     mailimf_cc * fld_cc;                           /* can be NULL */
	     mailimf_bcc * fld_bcc;                         /* can be NULL */
	     mailimf_message_id * fld_message_id;           /* can be NULL */
	     mailimf_in_reply_to * fld_in_reply_to;         /* can be NULL */
	     mailimf_references * fld_references;           /* can be NULL */
	     mailimf_subject * fld_subject;                 /* can be NULL */
	     mailimf_comments * fld_comments;               /* can be NULL */
	     mailimf_keywords * fld_keywords;               /* can be NULL */
	     mailimf_optional_field * fld_optional_field;   /* can be NULL */
	  }
	  fld_data_t fld_data;
	};

	 mailimf_field * mailimf_field_new(int fld_type,
	    mailimf_return * fld_return_path,
	    mailimf_orig_date * fld_resent_date,
	    mailimf_from * fld_resent_from,
	    mailimf_sender * fld_resent_sender,
	    mailimf_to * fld_resent_to,
	    mailimf_cc * fld_resent_cc,
	    mailimf_bcc * fld_resent_bcc,
	    mailimf_message_id * fld_resent_msg_id,
	    mailimf_orig_date * fld_orig_date,
	    mailimf_from * fld_from,
	    mailimf_sender * fld_sender,
	    mailimf_reply_to * fld_reply_to,
	    mailimf_to * fld_to,
	    mailimf_cc * fld_cc,
	    mailimf_bcc * fld_bcc,
	    mailimf_message_id * fld_message_id,
	    mailimf_in_reply_to * fld_in_reply_to,
	    mailimf_references * fld_references,
	    mailimf_subject * fld_subject,
	    mailimf_comments * fld_comments,
	    mailimf_keywords * fld_keywords,
	    mailimf_optional_field * fld_optional_field);

	void mailimf_field_free(mailimf_field * field);

	struct mailimf_orig_date {
	  mailimf_date_time * dt_date_time; /* != NULL */
	};

	mailimf_orig_date * mailimf_orig_date_new( mailimf_date_time * dt_date_time);
	void mailimf_orig_date_free( mailimf_orig_date * orig_date);

	struct mailimf_from {
	 	mailimf_mailbox_list * frm_mb_list; /* != NULL */
	};

	mailimf_from * mailimf_from_new( mailimf_mailbox_list * frm_mb_list);
	void mailimf_from_free(mailimf_from * from);


	struct mailimf_sender {
	   mailimf_mailbox * snd_mb; /* != NULL */
	};

	mailimf_sender * mailimf_sender_new( mailimf_mailbox * snd_mb);
	void mailimf_sender_free( mailimf_sender * sender);

	struct mailimf_reply_to {
	   mailimf_address_list * rt_addr_list; /* != NULL */
	};

	
	mailimf_reply_to * mailimf_reply_to_new(mailimf_address_list * rt_addr_list);
	void mailimf_reply_to_free( mailimf_reply_to * reply_to);

	struct mailimf_to {
	 	mailimf_address_list * to_addr_list; /* != NULL */
	}

	struct mailimf_cc {
		mailimf_address_list * cc_addr_list; /* != NULL */
	}

	struct mailimf_bcc {
	 	mailimf_address_list * bcc_addr_list; /* can be NULL */
	}

	struct mailimf_message_id {
	  char * mid_value; /* != NULL */
	}
	
	mailimf_to * mailimf_to_new( mailimf_address_list * to_addr_list); 
	void mailimf_to_free( mailimf_to * to);
	mailimf_cc * mailimf_cc_new( mailimf_address_list * cc_addr_list);
	void mailimf_cc_free( mailimf_cc * cc);
	mailimf_bcc * mailimf_bcc_new( mailimf_address_list * bcc_addr_list);
	void mailimf_bcc_free(mailimf_bcc * bcc);
	mailimf_message_id * mailimf_message_id_new(char * mid_value);
	void mailimf_message_id_free( mailimf_message_id * message_id);

	struct mailimf_in_reply_to {
	  clist * mid_list; /* list of (char *), != NULL */
	};

	
	mailimf_in_reply_to * mailimf_in_reply_to_new(clist * mid_list);
	void mailimf_in_reply_to_free( mailimf_in_reply_to * in_reply_to);
	mailimf_references * mailimf_references_new(clist * mid_list);
	void mailimf_references_free( mailimf_references * references);

	struct mailimf_references {
	  clist * mid_list; /* list of (char *) */
	       /* != NULL */
	};


	struct mailimf_subject {
	  char * sbj_value; /* != NULL */
	};

	mailimf_subject * mailimf_subject_new(char * sbj_value);
	void mailimf_subject_free(mailimf_subject * subject);


	struct mailimf_comments {
	  char * cm_value; /* != NULL */
	};

	mailimf_comments * mailimf_comments_new(char * cm_value);
	void mailimf_comments_free(mailimf_comments * comments);


	/*
	  mailimf_keywords is the parsed Keywords field

	  - kw_list is the list of keywords
	*/

	struct mailimf_keywords {
	  clist * kw_list; /* list of (char *), != NULL */
	};

	mailimf_keywords * mailimf_keywords_new(clist * kw_list);
	void mailimf_keywords_free(mailimf_keywords * keywords);


	/*
	  mailimf_return is the parsed Return-Path field

	  - ret_path is the parsed value of Return-Path
	*/

	struct mailimf_return {
	 	mailimf_path * ret_path; /* != NULL */
	};

	
	mailimf_return * mailimf_return_new( mailimf_path * ret_path);

	
	void mailimf_return_free(mailimf_return * return_path);


	struct mailimf_path {
	  char * pt_addr_spec; /* can be NULL */
	}

	
	mailimf_path * mailimf_path_new(char * pt_addr_spec);
	void mailimf_path_free( mailimf_path * path);
	struct mailimf_optional_field {
	  char * fld_name;  /* != NULL */
	  char * fld_value; /* != NULL */
	};

	 mailimf_optional_field * mailimf_optional_field_new(char * fld_name, char * fld_value);

	
	void mailimf_optional_field_free( mailimf_optional_field * opt_field);

	struct mailimf_single_fields {
	  mailimf_orig_date * fld_orig_date;      /* can be NULL */
	  mailimf_from * fld_from;                /* can be NULL */
	  mailimf_sender * fld_sender;            /* can be NULL */
	  mailimf_reply_to * fld_reply_to;        /* can be NULL */
	  mailimf_to * fld_to;                    /* can be NULL */
	  mailimf_cc * fld_cc;                    /* can be NULL */
	  mailimf_bcc * fld_bcc;                  /* can be NULL */
	  mailimf_message_id * fld_message_id;    /* can be NULL */
	  mailimf_in_reply_to * fld_in_reply_to;  /* can be NULL */
	  mailimf_references * fld_references;    /* can be NULL */
	  mailimf_subject * fld_subject;          /* can be NULL */
	  mailimf_comments * fld_comments;        /* can be NULL */
	  mailimf_keywords * fld_keywords;        /* can be NULL */
	};

	void mailimf_atom_free(char * atom);
	void mailimf_dot_atom_free(char * dot_atom);
	void mailimf_dot_atom_text_free(char * dot_atom);
	void mailimf_quoted_string_free(char * quoted_string);
	void mailimf_word_free(char * word);
	void mailimf_phrase_free(char * phrase);
	void mailimf_unstructured_free(char * unstructured);
	void mailimf_angle_addr_free(char * angle_addr);
	void mailimf_display_name_free(char * display_name);
	void mailimf_addr_spec_free(char * addr_spec);
	void mailimf_local_part_free(char * local_part);
	void mailimf_domain_free(char * domain);
	void mailimf_domain_literal_free(char * domain);
	void mailimf_msg_id_free(char * msg_id);
	void mailimf_id_left_free(char * id_left);
	void mailimf_id_right_free(char * id_right);
	void mailimf_no_fold_quote_free(char * nfq);
	void mailimf_no_fold_literal_free(char * nfl);
	void mailimf_field_name_free(char * field_name);


	/* these are the possible returned error codes */

	enum {
	  MAILIMF_NO_ERROR = 0,
	  MAILIMF_ERROR_PARSE,
	  MAILIMF_ERROR_MEMORY,
	  MAILIMF_ERROR_INVAL,
	  MAILIMF_ERROR_FILE
	}

	int mailimf_string_write_driver(int function(void *, const char *, size_t) do_write, void * data, int * col, const char * str, size_t length);
	int mailimf_fields_write_driver(int function(void *, const char *, size_t) do_write, void * data, int * col, mailimf_fields * fields);
	int mailimf_envelope_fields_write_driver(int function(void *, const char *, size_t) do_write, void * data, int * col,  mailimf_fields * fields);
	int mailimf_field_write_driver(int function(void *, const char *, size_t) do_write, void * data, int * col,  mailimf_field * field);
	int mailimf_quoted_string_write_driver(int function(void *, const char *, size_t) do_write, void * data, int * col, const char * string, size_t len);
	int mailimf_address_list_write_driver(int function(void *, const char *, size_t) do_write, void * data, int * col, mailimf_address_list * addr_list);
	int mailimf_mailbox_list_write_driver(int function(void *, const char *, size_t) do_write, void * data, int * col, mailimf_mailbox_list * mb_list);
	int mailimf_header_string_write_driver(int function(void *, const char *, size_t) do_write, void * data, int * col, const char * str, size_t length);
	mailimf_mailbox_list * mailimf_mailbox_list_new_empty();
	int mailimf_mailbox_list_add( mailimf_mailbox_list * mailbox_list, mailimf_mailbox * mb);
	int mailimf_mailbox_list_add_parse(mailimf_mailbox_list * mailbox_list, const (char *) mb_str);
	int mailimf_mailbox_list_add_mb( mailimf_mailbox_list * mailbox_list, char * display_name, char * address);
	mailimf_address_list * mailimf_address_list_new_empty();
	int mailimf_address_list_add( mailimf_address_list * address_list, mailimf_address * addr);
	int mailimf_address_list_add_parse( mailimf_address_list * address_list, char * addr_str);
	int mailimf_address_list_add_mb( mailimf_address_list * address_list, char * display_name, char * address);
	int mailimf_resent_fields_add_data(mailimf_fields * fields, mailimf_date_time * resent_date,
	mailimf_mailbox_list * resent_from,  mailimf_mailbox * resent_sender,  mailimf_address_list * resent_to,
	mailimf_address_list * resent_cc,  mailimf_address_list * resent_bcc, char * resent_msg_id);
	mailimf_fields * mailimf_resent_fields_new_with_data_all( mailimf_date_time * resent_date,  mailimf_mailbox_list * resent_from,
	mailimf_mailbox * resent_sender,  mailimf_address_list * resent_to,  mailimf_address_list * resent_cc, mailimf_address_list * resent_bcc,
	char * resent_msg_id);
	mailimf_fields * mailimf_resent_fields_new_with_data( mailimf_mailbox_list * from, mailimf_mailbox * sender, mailimf_address_list * to, mailimf_address_list * cc, mailimf_address_list * bcc);
	mailimf_fields * mailimf_fields_new_empty();
	int mailimf_fields_add( mailimf_fields * fields,  mailimf_field * field);
	int mailimf_fields_add_data( mailimf_fields * fields,  mailimf_date_time * date, mailimf_mailbox_list * from, mailimf_mailbox * sender,  mailimf_address_list * reply_to,  mailimf_address_list * to,  mailimf_address_list * cc,  mailimf_address_list * bcc, char * msg_id, clist * in_reply_to, clist * references, char * subject);
	mailimf_fields * mailimf_fields_new_with_data_all( mailimf_date_time * date, mailimf_mailbox_list * from, mailimf_mailbox * sender,  mailimf_address_list * reply_to,  mailimf_address_list * to, mailimf_address_list * cc, mailimf_address_list * bcc, char * message_id, clist * in_reply_to, clist * references, char * subject);
	mailimf_fields * mailimf_fields_new_with_data( mailimf_mailbox_list * from,  mailimf_mailbox * sender, mailimf_address_list * reply_to, mailimf_address_list * to,  mailimf_address_list * cc,  mailimf_address_list * bcc, clist * in_reply_to, clist * references, char * subject);
	char * mailimf_get_message_id();
	mailimf_date_time * mailimf_get_current_date();
	mailimf_date_time * mailimf_get_date(time_t time);
	void mailimf_single_fields_init(mailimf_single_fields * single_fields,  mailimf_fields * fields);
	mailimf_single_fields * mailimf_single_fields_new( mailimf_fields * fields);
	void mailimf_single_fields_free( mailimf_single_fields * single_fields);
	mailimf_field * mailimf_field_new_custom(char * name, char * value);

	struct mailprivacy {
	  char * tmp_dir;               /* working tmp directory */
	  chash * msg_ref;              /* mailmessage => present or not */
	  chash * mmapstr;              /* mmapstring => present or not present */
	  chash * mime_ref;             /* mime => present or not */
	  carray * protocols;
	  int make_alternative;
	}

	struct mailprivacy_encryption {
	  char * name;
	  char * description;
	  
	  int function(mailprivacy *, mailmessage *, mailmime *, mailmime **) encrypt;
	}

	struct mailprivacy_protocol {
	  char * name;
	  char * description;
	  
	  /* introduced to easy the port to sylpheed */
	  int function( mailprivacy *, mailmessage *,  mailmime *)is_encrypted;
	  
	  int function( mailprivacy *, mailmessage *,  mailmime *, mailmime **) decrypt;
	  
	  int encryption_count;
	  mailprivacy_encryption * encryption_tab;
	};

	enum {
	  NO_ERROR_PASSPHRASE = 0,
	  ERROR_PASSPHRASE_COMMAND,
	  ERROR_PASSPHRASE_FILE
	};

	int mailprivacy_spawn_and_wait(char * command, char * passphrase, char * stdoutfile, char * stderrfile, int * bad_passphrase);
	void mailprivacy_mime_clear( mailmime * mime);
	FILE * mailprivacy_get_tmp_file( mailprivacy * privacy, char * filename, size_t size);
	int mailprivacy_get_tmp_filename( mailprivacy * privacy, char * filename, size_t size);
	mailmime * mailprivacy_new_file_part( mailprivacy * privacy, char * filename, char * default_content_type, int default_encoding);
	int mailmime_substitute(mailmime * old_mime,  mailmime * new_mime);
	int mailprivacy_fetch_mime_body_to_file(mailprivacy * privacy, char * filename, size_t size, mailmessage * msg, mailmime * mime);
	int mailprivacy_get_part_from_file( mailprivacy * privacy, int check_privacy, int reencode, char * filename, mailmime ** result_mime);
	int mail_quote_filename(char * result, size_t size, char * path);
	void mailprivacy_prepare_mime(mailmime * mime);
	char * mailprivacy_dup_imf_file(mailprivacy * privacy, char * source_filename);
	mailmime_fields * mailprivacy_mime_fields_dup(mailprivacy * privacy, mailmime_fields * mime_fields);
	mailmime_parameter * mailmime_parameter_dup(mailmime_parameter * param);
	mailmime_composite_type * mailmime_composite_type_dup( mailmime_composite_type * composite_type);
	mailmime_discrete_type * mailmime_discrete_type_dup( mailmime_discrete_type * discrete_type);
	mailmime_type * mailmime_type_dup( mailmime_type * type);
	mailmime_content * mailmime_content_dup( mailmime_content * content);
	int mailprivacy_fetch_decoded_to_file( mailprivacy * privacy, char * filename, size_t size, mailmessage * msg, mailmime * mime);
	int mailprivacy_get_mime( mailprivacy * privacy, int check_privacy, int reencode, char * content, size_t content_len, mailmime ** result_mime);
	int mailprivacy_smime_init(mailprivacy * privacy);
	void mailprivacy_smime_done( mailprivacy * privacy);
	void mailprivacy_smime_set_cert_dir(mailprivacy * privacy, char * directory);
	void mailprivacy_smime_set_CA_dir(mailprivacy * privacy, char * directory);
	void mailprivacy_smime_set_CA_check(mailprivacy * privacy, int enabled);
	void mailprivacy_smime_set_store_cert(mailprivacy * privacy, int enabled);
	void mailprivacy_smime_set_private_keys_dir( mailprivacy * privacy, char * directory);
	clist * mailprivacy_smime_encryption_id_list( mailprivacy * privacy, mailmessage * msg);
	void mailprivacy_smime_encryption_id_list_clear( mailprivacy * privacy, mailmessage * msg);
	int mailprivacy_smime_set_encryption_id(mailprivacy * privacy, char * user_id, char * passphrase);
	mailprivacy * mailprivacy_new(char * tmp_dir, int make_alternative);
	void mailprivacy_free(mailprivacy * privacy);
	int mailprivacy_msg_get_bodystructure( mailprivacy * privacy, mailmessage * msg_info, mailmime ** result);
	void mailprivacy_msg_flush( mailprivacy * privacy, mailmessage * msg_info);
	int mailprivacy_msg_fetch_section(mailprivacy * privacy, mailmessage * msg_info, mailmime * mime, char ** result, size_t * result_len);
	int mailprivacy_msg_fetch_section_header( mailprivacy * privacy, mailmessage * msg_info,  mailmime * mime, char ** result, size_t * result_len);
	int mailprivacy_msg_fetch_section_mime( mailprivacy * privacy, mailmessage * msg_info,  mailmime * mime, char ** result, size_t * result_len);
	int mailprivacy_msg_fetch_section_body(mailprivacy * privacy, mailmessage * msg_info, mailmime * mime, char ** result, size_t * result_len);
	void mailprivacy_msg_fetch_result_free(mailprivacy * privacy, mailmessage * msg_info, char * msg);
	int mailprivacy_msg_fetch( mailprivacy * privacy, mailmessage * msg_info, char ** result, size_t * result_len);
	int mailprivacy_msg_fetch_header( mailprivacy * privacy, mailmessage * msg_info, char ** result, size_t * result_len);
	int mailprivacy_register( mailprivacy * privacy,  mailprivacy_protocol * protocol);
	void mailprivacy_unregister(mailprivacy * privacy,  mailprivacy_protocol * protocol);
	char * mailprivacy_get_encryption_name(mailprivacy * privacy, char * privacy_driver, char * privacy_encryption);
	int mailprivacy_encrypt( mailprivacy * privacy, char * privacy_driver, char * privacy_encryption,  mailmime * mime, mailmime ** result);
	int mailprivacy_encrypt_msg( mailprivacy * privacy, char * privacy_driver, char * privacy_encryption, mailmessage * msg,  mailmime * mime, mailmime ** result);
	void mailprivacy_debug( mailprivacy * privacy, FILE * f);
	carray * mailprivacy_get_protocols( mailprivacy * privacy);
	int mailprivacy_is_encrypted( mailprivacy * privacy, mailmessage * msg, mailmime * mime);
	void mailprivacy_recursive_unregister_mime(mailprivacy * privacy,  mailmime * mime);
	int mailprivacy_gnupg_init(mailprivacy * privacy);
	void mailprivacy_gnupg_done( mailprivacy * privacy);
	clist * mailprivacy_gnupg_encryption_id_list( mailprivacy * privacy, mailmessage * msg);
	void mailprivacy_gnupg_encryption_id_list_clear( mailprivacy * privacy, mailmessage * msg);
	int mailprivacy_gnupg_set_encryption_id(mailprivacy * privacy, char * user_id, char * passphrase);

	mailengine * libetpan_engine_new( mailprivacy * privacy);
	void libetpan_engine_free( mailengine * engine);
	mailprivacy * libetpan_engine_get_privacy(mailengine * engine);
	int libetpan_message_ref( mailengine * engine, mailmessage * msg);
	int libetpan_message_unref( mailengine * engine, mailmessage * msg);
	int libetpan_message_mime_ref( mailengine * engine, mailmessage * msg);
	int libetpan_message_mime_unref( mailengine * engine, mailmessage * msg);
	int libetpan_folder_get_msg_list( mailengine * engine, mailfolder * folder,  mailmessage_list ** p_new_msg_list,  mailmessage_list ** p_lost_msg_list);
	int libetpan_folder_fetch_env_list( mailengine * engine, mailfolder * folder,  mailmessage_list * msg_list);
	void libetpan_folder_free_msg_list(mailengine * engine, mailfolder * folder,  mailmessage_list * env_list);
	int libetpan_storage_add( mailengine * engine,  mailstorage * storage);
	void libetpan_storage_remove( mailengine * engine,  mailstorage * storage);
	int libetpan_storage_connect( mailengine * engine,  mailstorage * storage);
	void libetpan_storage_disconnect( mailengine * engine, mailstorage * storage);
	int libetpan_storage_used(mailengine * engine,  mailstorage * storage);
	int libetpan_folder_connect(mailengine * engine,  mailfolder * folder);
	void libetpan_folder_disconnect(mailengine * engine,  mailfolder * folder);
	mailfolder * libetpan_message_get_folder( mailengine * engine, mailmessage * msg);
	mailstorage * libetpan_message_get_storage( mailengine * engine, mailmessage * msg);
	int libetpan_message_register( mailengine * engine,  mailfolder * folder, mailmessage * msg);
	void libetpan_engine_debug( mailengine * engine, FILE * f);
	void * engine_app;

	mailstream_low * mailstream_low_new(void * data, mailstream_low_driver * driver);
	ssize_t mailstream_low_write(mailstream_low * s, const void * buf, size_t count);
	ssize_t mailstream_low_read(mailstream_low * s, void * buf, size_t count);
	int mailstream_low_close(mailstream_low * s);
	int mailstream_low_get_fd(mailstream_low * s);
	mailstream_cancel * mailstream_low_get_cancel(mailstream_low * s);
	void mailstream_low_free(mailstream_low * s);
	void mailstream_low_cancel(mailstream_low * s);
	void mailstream_low_log_error(mailstream_low * s, const void * buf, size_t count);
	void mailstream_low_set_privacy(mailstream_low * s, int can_be_public);
	int mailstream_low_set_identifier(mailstream_low * s, char * identifier);
	const (char *) mailstream_low_get_identifier(mailstream_low * s);
	void mailstream_low_set_timeout(mailstream_low * s, time_t timeout);
	time_t mailstream_low_get_timeout(mailstream_low * s);
	void mailstream_low_set_logger(mailstream_low * s, void function(mailstream_low * s, int log_type, const char * str, size_t size, void * context) logger, void * logger_context);
	carray * mailstream_low_get_certificate_chain(mailstream_low * s);
	int mailstream_low_wait_idle(mailstream_low * low, mailstream_cancel * cancel, int max_idle_delay);
	int mailstream_low_setup_idle(mailstream_low * low);
	int mailstream_low_unsetup_idle(mailstream_low * low);
	int mailstream_low_interrupt_idle(mailstream_low * low);

	struct _mailstream_cancel {
	  int ms_cancelled;
	  int ms_fds[2];
	  void * ms_internal;
	};

	struct mailsem {
	  void * sem_sem;
	  int sem_kind;
	};

	
	mailsem * mailsem_new();
	void mailsem_free( mailsem * sem);
	int mailsem_up( mailsem * sem);
	int mailsem_down( mailsem * sem);
	enum USE_DEFLATE =1;
	__gshared mailstream_low_driver * mailstream_compress_driver;
	__gshared struct mailstream_compress_context;

	mailstream_low * mailstream_low_compress_open(mailstream_low * ms);
	int mailstream_low_compress_wait_idle(mailstream_low * low,  _mailstream_cancel * idle, int max_idle_delay);
	uint16_t mail_get_service_port(const char * name, char * protocol);
	int mail_tcp_connect(const char * server, uint16_t port);
	int mail_tcp_connect_timeout(const char * server, uint16_t port, time_t timeout);
	int mail_tcp_connect_with_local_address(const char * server, uint16_t port,
	    const char * local_address, uint16_t local_port);
	int mail_tcp_connect_with_local_address_timeout(const char * server, uint16_t port,
	    const char * local_address, uint16_t local_port, time_t timeout);


	struct carray_s {
	  void ** array;
	  uint len;
	  uint max;
	};

	alias carray=carray_s;

	carray *   carray_new(uint initsize);
	int       carray_add(carray * array, void * data, uint * indx);
	int carray_set_size(carray * array, uint new_size);
	int       carray_delete(carray * array, uint indx);
	int       carray_delete_slow(carray * array, uint indx);
	int carray_delete_fast(carray * array, uint indx);
	void **   carray_data(carray *);
	uint carray_count(carray *);
	void *    carray_get(carray * array, uint indx);
	void      carray_set(carray * array, uint indx, void * value);

	void ** carray_data(carray * array)
	{
	  return array.array;
	}

	uint carray_count(carray * array)
	{
	  return array.len;
	}

	void * carray_get(carray * array, uint indx)
	{
	  return array.array[indx];
	}

	void carray_set(carray * array, uint indx, void * value)
	{
	  array.array[indx] = value;
	}
	
	void carray_free(carray * array);
	time_t mail_mkgmtime( tm * tmp);
	char * encode_base64(const( char) * _in, int len);
	char * decode_base64(const (char )* _in, int len);

	void mailsasl_init_lock();
	void mailsasl_uninit_lock();
	struct MD5_CTX {
	  UINT4[4] state;                                   /* state (ABCD) */
	  UINT4[2] count;        /* number of bits, modulo 2^64 (lsb first) */
	  ubyte[64] buffer;                         /* input buffer */
	}
/* fixme

	void MD5Init PROTO_LIST (MD5_CTX *);
	void MD5Update PROTO_LIST(MD5_CTX *, const ubyte *, uint);
	void MD5Final PROTO_LIST (ubyte [16], MD5_CTX *);
	void hmac_md5 PROTO_LIST (const ubyte *, int, const ubyte *, int, ubyte *);
*/
	int mail_cache_db_open(const char * filename,  mail_cache_db ** pcache_db);
	void mail_cache_db_close( mail_cache_db * cache_db);
	int mail_cache_db_open_lock(const char * filename,  mail_cache_db ** pcache_db);
	void mail_cache_db_close_unlock(const char * filename,  mail_cache_db * cache_db);
	int mail_cache_db_put( mail_cache_db * cache_db, const void * key, size_t key_len, const void * value, size_t value_len);
	int mail_cache_db_get( mail_cache_db * cache_db, const void * key, size_t key_len, void ** pvalue, size_t * pvalue_len);
	int mail_cache_db_get_size( mail_cache_db * cache_db, const void * key, size_t key_len, size_t * pvalue_len);
	int mail_cache_db_del( mail_cache_db * cache_db, const void * key, size_t key_len);
	int mail_cache_db_clean_up( mail_cache_db * cache_db, chash * exist);
	int mail_cache_db_get_keys( mail_cache_db * cache_db, chash * keys);
	//struct _mailstream_low;
	alias _mailstream_low= mailstream_low;

	enum {
	  /* Buffer is a log text string. */
	  MAILSTREAM_LOG_TYPE_INFO_RECEIVED,
	  MAILSTREAM_LOG_TYPE_INFO_SENT,
	  
	  /* Buffer is data sent over the network. */
	  MAILSTREAM_LOG_TYPE_ERROR_PARSE,
	  MAILSTREAM_LOG_TYPE_ERROR_RECEIVED, /* no data */
	  MAILSTREAM_LOG_TYPE_ERROR_SENT, /* no data */
	  
	  /* Buffer is data sent over the network. */
	  MAILSTREAM_LOG_TYPE_DATA_RECEIVED,
	  MAILSTREAM_LOG_TYPE_DATA_SENT,
	  MAILSTREAM_LOG_TYPE_DATA_SENT_PRIVATE,  /* data is private, for example a password. */
	};

	struct _mailstream {
	  size_t buffer_max_size;

	  char * write_buffer;
	  size_t write_buffer_len;

	  char * read_buffer;
	  size_t read_buffer_len;

	  mailstream_low * low;
	  
	  _mailstream_cancel * idle;
	  int idling;
	  void function(mailstream * s, int log_type, const char * str, size_t size, void * logger_context) logger;
	  void * logger_context;
	}
	alias mailstream=_mailstream;

	struct mailstream_low_driver {
	  ssize_t function(mailstream_low *, void *, size_t) mailstream_read;
	  ssize_t function(mailstream_low *, const void *, size_t) mailstream_write;
	  int function(mailstream_low *) mailstream_close;
	  int function(mailstream_low *) mailstream_get_fd;
	  void function(mailstream_low *) mailstream_free;
	  void function(mailstream_low *) mailstream_cancel;
	  _mailstream_cancel * function(mailstream_low *) * mailstream_get_cancel;
	  /* Returns an array of MMAPString containing DER data or NULL if it's not a SSL connection */
	  carray * function(mailstream_low *) mailstream_get_certificate_chain;
	  /* Will be called from the main thread */
	  int function(mailstream_low *) mailstream_setup_idle;
	  int function(mailstream_low *) mailstream_unsetup_idle;
	  int function(mailstream_low *) mailstream_interrupt_idle;
	}


	struct mailstream_low {
	  void * data;
	  mailstream_low_driver * driver;
	  int privacy;
	  char * identifier;
	  ulong timeout; /* in seconds, 0 will use the global value */
	  void function(mailstream_low * s, int log_type, const char * str, size_t size, void * logger_context) logger;
	  void * logger_context;
	};

	alias  progress_function=void function(size_t current, size_t maximum);

	alias mailprogress_function=void function(size_t current, size_t maximum, void * context);

	enum {
	  MAILSTREAM_IDLE_ERROR,
	  MAILSTREAM_IDLE_INTERRUPTED,
	  MAILSTREAM_IDLE_HASDATA,
	  MAILSTREAM_IDLE_TIMEOUT,
	  MAILSTREAM_IDLE_CANCELLED
	};

	struct mail_cache_db {
	  void * internal_database;
	};
	void mailsasl_external_ref();
	void mailsasl_ref();
	void mailsasl_unref();

	void mailstream_ssl_init_lock();
	void mailstream_ssl_uninit_lock();

	struct clistcell_s {
	  void * data;
	  clistcell_s * previous;
	  clistcell_s * next;
	}
	alias clistcell=clistcell_s;

	struct clist_s {
	  clistcell * first;
	  clistcell * last;
	  int count;
	};

	alias clist=clist_s ;
	alias clistiter=clistcell_s ;
	clist *      clist_new();
	void        clist_free(clist *);
	int         clist_isempty(clist *);
	int         clist_count(clist *);
	clistiter *   clist_begin(clist *);
	clistiter *   clist_end(clist *);
	clistiter *   clist_next(clistiter *);
	clistiter *   clist_previous(clistiter *);
	void*       clist_content(clistiter *);
	int         clist_prepend(clist *, void *);
	int         clist_append(clist *, void *);
	int         clist_insert_before(clist *, clistiter *, void *);
	int         clist_insert_after(clist *, clistiter *, void *);
	clistiter *   clist_delete(clist *, clistiter *);
	alias clist_func=void function(void *, void *);
	void clist_foreach(clist * lst, clist_func func, void * data);
	void clist_concat(clist * dest, clist * src);
	void * clist_nth_data(clist * lst, int indx);
	clistiter * clist_nth(clist * lst, int indx);

	struct chashdatum
	{
	  void * data;
	  uint len;
	} 

	struct chash {
	  uint size;
	  uint count;
	  int copyvalue;
	  int copykey;
	  chashcell ** cells; 
	}

	
	struct chashcell {
	  uint func;
	  chashdatum key;
	  chashdatum value;
	  chashcell * next;
	}

	enum CHASH_COPYNONE    =0;
	enum CHASH_COPYKEY     =1;
	enum CHASH_COPYVALUE   =2;
	enum CHASH_COPYALL     =(CHASH_COPYKEY | CHASH_COPYVALUE);
	enum CHASH_DEFAULTSIZE=13;
	chash * chash_new(uint size, int flags);
	void chash_free(chash * hash);
	void chash_clear(chash * hash);
	int chash_set(chash * hash, chashdatum * key, chashdatum * value, chashdatum * oldvalue);
	int chash_get(chash * hash, chashdatum * key, chashdatum * result);
	int chash_delete(chash * hash, chashdatum * key, chashdatum * oldvalue);
	int chash_resize(chash * hash, uint size);
	chashiter * chash_begin(chash * hash);
	chashiter * chash_next(chash * hash, chashiter * iter);
	uint          chash_size(chash * hash);
	uint          chash_count(chash * hash);
	void chash_key(chashiter * iter, chashdatum * result);
	void chash_value(chashiter * iter, chashdatum * result);
	alias MMAPString =  _MMAPString;

	struct _MMAPString
	{
	  char * str;
	  size_t len;    
	  size_t allocated_len;
	  int fd;
	  size_t mmapped_size;
	  /*
	  char * old_non_mmapped_str;
	  */
	}

	void mmap_string_set_tmpdir(const char * directory);
	MMAPString * mmap_string_new (const char * init);
	MMAPString * mmap_string_new_len (const char * init, size_t len);
	MMAPString * mmap_string_sized_new (size_t dfl_size);
	void mmap_string_free (MMAPString * string);
	MMAPString * mmap_string_assign (MMAPString * string, const char * rval);
	MMAPString * mmap_string_truncate (MMAPString *string, size_t len);
	MMAPString * mmap_string_set_size (MMAPString * string, size_t len);
	MMAPString * mmap_string_insert_len (MMAPString * string, size_t pos, const char * val, size_t len);
	MMAPString * mmap_string_append (MMAPString * string, const char * val);
	MMAPString * mmap_string_append_len (MMAPString * string, const char * val, size_t len);
	MMAPString * mmap_string_append_c (MMAPString * string, char c);
	MMAPString * mmap_string_prepend (MMAPString * string, const char * val);
	MMAPString * mmap_string_prepend_c (MMAPString * string, char c);
	MMAPString * mmap_string_prepend_len (MMAPString * string, const char * val, size_t len);
	MMAPString * mmap_string_insert (MMAPString * string, size_t pos, const char * val);
	MMAPString * mmap_string_insert_c (MMAPString *string, size_t pos, char c);
	MMAPString * mmap_string_erase(MMAPString * string, size_t pos, size_t len);
	void mmap_string_set_ceil(size_t ceil);
	int mmap_string_ref(MMAPString * string);
	int mmap_string_unref(char * str);
	char * mailstream_read_line(mailstream * stream, MMAPString * line);
	char * mailstream_read_line_append(mailstream * stream, MMAPString * line);
	char * mailstream_read_line_remove_eol(mailstream * stream, MMAPString * line);
	char * mailstream_read_multiline(mailstream * s, size_t size, MMAPString * stream_buffer, MMAPString * multiline_buffer, size_t progr_rate, progress_function * progr_fun, mailprogress_function * body_progr_fun, void * context);
	int mailstream_is_end_multiline(const char * line);
	int mailstream_send_data_crlf(mailstream * s, const char * message, size_t size, size_t progr_rate, progress_function * progr_fun);
	int mailstream_send_data_crlf_with_context(mailstream * s, const char * message, size_t size, mailprogress_function * progr_fun, void * context);
	int mailstream_send_data(mailstream * s, const char * message, size_t size, size_t progr_rate, progress_function * progr_fun);
	int mailstream_send_data_with_context(mailstream * s, const char * message, size_t size, mailprogress_function * progr_fun, void * context);
	size_t mailstream_get_data_crlf_size(const char * message, size_t size);

	enum {
	  MAIL_CHARCONV_NO_ERROR = 0,
	  MAIL_CHARCONV_ERROR_UNKNOWN_CHARSET,
	  MAIL_CHARCONV_ERROR_MEMORY,
	  MAIL_CHARCONV_ERROR_CONV
	}

	//int function(const char * tocode, const char * fromcode, const char * str, size_t length, char * result, size_t* result_len) extended_charconv;
	int charconv(const char * tocode, const char * fromcode, const char * str, size_t length, char ** result);
	int charconv_buffer(const char * tocode, const char * fromcode, const char * str, size_t length, char ** result, size_t * result_len);
	void charconv_buffer_free(char * str);
	int maillock_read_lock(const char * filename, int fd);
	int maillock_read_unlock(const char * filename, int fd);
	int maillock_write_lock(const char * filename, int fd);
	int maillock_write_unlock(const char * filename, int fd);

	enum HMAC_MD5_SIZE=16;

	/* intermediate MD5 context */
	struct HMAC_MD5_CTX_s {
	    MD5_CTX ictx, octx;
	}
	alias HMAC_MD5_CTX=HMAC_MD5_CTX_s;

	struct HMAC_MD5_STATE {
	    UINT4[4] istate;
	    UINT4[4] ostate;
	}
	
	void hmac_md5(const ubyte *text, int text_len, const ubyte *key, int key_len, ubyte digest[HMAC_MD5_SIZE]);
	void hmac_md5_init(HMAC_MD5_CTX *hmac, const ubyte *key, int key_len);
	void hmac_md5_precalc(HMAC_MD5_STATE *hmac, const ubyte *key, int key_len);
	void hmac_md5_import(HMAC_MD5_CTX *hmac, HMAC_MD5_STATE *state);

	auto hmac_md5_update(T)(T hmac, T text, T text_len)
	{
		return MD5Update(&(hmac).ictx, (text), (text_len));
	}

	void hmac_md5_final(ubyte digest[HMAC_MD5_SIZE], HMAC_MD5_CTX *hmac);

	__gshared mailstream_low_driver * mailstream_ssl_driver;
	// mailstream_ssl_context;
	mailstream_low * mailstream_low_ssl_open(int fd);
	mailstream_low * mailstream_low_ssl_open_timeout(int fd, time_t timeout);
	mailstream_low * mailstream_low_tls_open(int fd);
	mailstream_low * mailstream_low_tls_open_timeout(int fd, time_t timeout);
	mailstream * mailstream_ssl_open(int fd);
	mailstream * mailstream_ssl_open_timeout(int fd, time_t timeout);
	mailstream * mailstream_ssl_open_with_callback(int fd, void function(mailstream_ssl_context * ssl_context, void * data) callback, void * data);
	mailstream * mailstream_ssl_open_with_callback_timeout(int fd, time_t timeout, void function( mailstream_ssl_context * ssl_context, void * data) callback, void * data);
	void mailstream_gnutls_init_not_required();
	void mailstream_openssl_init_not_required();
	void mailstream_ssl_init_not_required();
	ssize_t mailstream_ssl_get_certificate(mailstream *stream, ubyte **cert_DER);
	mailstream_low * mailstream_low_ssl_open_with_callback(int fd, void function( mailstream_ssl_context * ssl_context, void * data) callback, void * data);
	mailstream_low * mailstream_low_ssl_open_with_callback_timeout(int fd, time_t timeout, void function( mailstream_ssl_context * ssl_context, void * data) callback, void * data);
	mailstream_low * mailstream_low_tls_open_with_callback(int fd, void function( mailstream_ssl_context * ssl_context, void * data) callback, void * data);
	mailstream_low * mailstream_low_tls_open_with_callback_timeout(int fd, time_t timeout, void function( mailstream_ssl_context * ssl_context, void * data) callback, void * data);
	int mailstream_ssl_set_client_certicate(mailstream_ssl_context * ssl_context, char * file_name);
	int mailstream_ssl_set_client_certificate_data( mailstream_ssl_context * ssl_context, ubyte *x509_der, size_t len);
	int mailstream_ssl_set_client_private_key_data( mailstream_ssl_context * ssl_context, ubyte *pkey_der, size_t len);
	int mailstream_ssl_set_server_certicate( mailstream_ssl_context * ssl_context, char * CAfile, char * CApath);
	void * mailstream_ssl_get_openssl_ssl_ctx( mailstream_ssl_context * ssl_context);
	int mailstream_ssl_get_fd(mailstream_ssl_context * ssl_context);

	/* PROTOTYPES should be set to one if and only if the compiler supports
	  function argument prototyping.
	The following makes PROTOTYPES default to 0 if it has not already
	  been defined with C compiler flags.
	 */
	enum PROTOTYPES=1;

	/* POINTER defines a generic pointer type */
	alias POINTER= ubyte *;
	alias CONST_POINTER=const(ubyte)*;

	/* UINT2 defines a two byte word */
	alias UINT2= ushort;

	/* UINT4 defines a four byte word */
	alias UINT4= ulong;

/* fixme
	static if (PROTOTYPES==1)
	{
		alias enum PROTO_LIST(list) list;
	}
	else{
		alias  PROTO_LIST(list)=();
	}
*/
	void mmapstring_init_lock();
	void mmapstring_uninit_lock();
	__gshared int mailstream_cfstream_enabled;
	__gshared int mailstream_cfstream_voip_enabled;

	enum {
		MAILSTREAM_CFSTREAM_SSL_ALLOWS_EXPIRED_CERTIFICATES = 1 << 0,
		MAILSTREAM_CFSTREAM_SSL_ALLOWS_EXPIRED_ROOTS = 1 << 1,
		MAILSTREAM_CFSTREAM_SSL_ALLOWS_ANY_ROOT = 1 << 2,
		MAILSTREAM_CFSTREAM_SSL_DISABLE_VALIDATES_CERTIFICATE_CHAIN = 1 << 3,
		MAILSTREAM_CFSTREAM_SSL_NO_VERIFICATION = MAILSTREAM_CFSTREAM_SSL_ALLOWS_EXPIRED_CERTIFICATES | 
		   MAILSTREAM_CFSTREAM_SSL_ALLOWS_EXPIRED_ROOTS |
		   MAILSTREAM_CFSTREAM_SSL_ALLOWS_ANY_ROOT |
		   MAILSTREAM_CFSTREAM_SSL_DISABLE_VALIDATES_CERTIFICATE_CHAIN
	};

	enum {
		MAILSTREAM_CFSTREAM_SSL_LEVEL_NONE,
		MAILSTREAM_CFSTREAM_SSL_LEVEL_SSLv2,
		MAILSTREAM_CFSTREAM_SSL_LEVEL_SSLv3,
		MAILSTREAM_CFSTREAM_SSL_LEVEL_TLSv1,
		MAILSTREAM_CFSTREAM_SSL_LEVEL_NEGOCIATED_SSL
	};
	  
	__gshared mailstream_low_driver * mailstream_cfstream_driver;
	mailstream * mailstream_cfstream_open(const char * hostname, int16_t port);
	mailstream * mailstream_cfstream_open_timeout(const char * hostname, int16_t port, time_t timeout);
	mailstream * mailstream_cfstream_open_voip(const char * hostname, int16_t port, int voip_enabled);
	mailstream * mailstream_cfstream_open_voip_timeout(const char * hostname, int16_t port, int voip_enabled, time_t timeout);
	mailstream_low * mailstream_low_cfstream_open(const char * hostname, int16_t port);
	mailstream_low * mailstream_low_cfstream_open_timeout(const char * hostname, int16_t port, time_t timeout);
	mailstream_low * mailstream_low_cfstream_open_voip(const char * hostname, int16_t port, int voip_enabled);
	mailstream_low * mailstream_low_cfstream_open_voip_timeout(const char * hostname, int16_t port, int voip_enabled, time_t timeout);
	void mailstream_cfstream_set_ssl_verification_mask(mailstream * s, int verification_mask);
	void mailstream_cfstream_set_ssl_peer_name(mailstream * s, const char * peer_name);
	void mailstream_cfstream_set_ssl_is_server(mailstream * s, int is_server);
	void mailstream_cfstream_set_ssl_level(mailstream * s, int ssl_level);
	int mailstream_cfstream_set_ssl_enabled(mailstream * s, int ssl_enabled);
	int mailstream_cfstream_is_ssl_enabled(mailstream * s);
	int mailstream_cfstream_wait_idle(mailstream * s, int max_idle_delay);
	int mailstream_low_cfstream_wait_idle(mailstream_low * low, int max_idle_delay);
	mailstream * mailstream_new(mailstream_low * low, size_t buffer_size);
	ssize_t mailstream_write(mailstream * s, const void * buf, size_t count);
	ssize_t mailstream_read(mailstream * s, void * buf, size_t count);
	int mailstream_close(mailstream * s);
	int mailstream_flush(mailstream * s);
	ssize_t mailstream_feed_read_buffer(mailstream * s);
	void mailstream_log_error(mailstream * s, char * buf, size_t count);
	mailstream_low * mailstream_get_low(mailstream * s);
	void mailstream_set_low(mailstream * s, mailstream_low * low);
	alias mailstream_cancel=void function(mailstream * s);
	void mailstream_set_privacy(mailstream * s, int can_be_public);
	debug
	{
		int mailstream_debug;
		void function(int direction, const char * str, size_t size) mailstream_logger;
		void function(mailstream_low * s, int is_stream_data, int direction, const char * str, size_t size) mailstream_logger_id;
	}

	void mailstream_set_logger(mailstream * s, void function(mailstream * s, int log_type, const char * str, size_t size, void * context) logger, void * logger_context);
	int mailstream_wait_idle(mailstream * s, int max_idle_delay);
	int mailstream_setup_idle(mailstream * s);
	void mailstream_unsetup_idle(mailstream * s);
	void mailstream_interrupt_idle(mailstream * s);
	carray * mailstream_get_certificate_chain(mailstream * s);
	void mailstream_certificate_chain_free(carray * certificate_chain);
	enum LIBETPAN_MAILSTREAM_NETWORK_DELAY=1;
	__gshared timeval mailstream_network_delay;
	__gshared mailstream_cancel * mailstream_cancel_new();
	void mailstream_cancel_free( mailstream_cancel * cancel);
	int mailstream_cancel_cancelled( mailstream_cancel * cancel);
	void mailstream_cancel_notify( mailstream_cancel * cancel);
	void mailstream_cancel_ack( mailstream_cancel * cancel);
	int mailstream_cancel_get_fd( mailstream_cancel * cancel);
}


/**
libEtPan! -- a mail stuff library

Copyright (C) 2001 - 2005 - DINH Viet Hoa
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. Neither the name of the libEtPan! project nor the names of its
   contributors may be used to endorse or promote products derived
   from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.

This project contains code from sendmail, NetBSD,
RSA Data Security MD5 Message-Digest Algorithm, Cyrus IMAP.
*/