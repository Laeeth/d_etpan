module privacy;

struct ETPANPrivacy
{
  string tmp_dir;               /* working tmp directory */
  ETPanMessage msg_ref;        /* mailmessage => present or not  - chash*/
    chash * mmapstr;              /* mmapstring => present or not present */
    chash * mime_ref;             /* mime => present or not */
    carray * protocols;
    int make_alternative;
  }

  mailprivacy *privacy;

  this(string tmp,string certPath,string CAPath, string PrivateKeyPath, string[2] gnuID, string[2] smimeID)
  {
    privacy=mailprivacy_new(toStringz(tmp),1);
    if (isNull(privacy))
      throw new Exception("d_etpan:ETPANPrivacy unable to allocate memory");
    throwOnError(mailprivacy_gnupg_init(privacy),MAIL_NO_ERROR);
    throwOnError(mailprivacy_smime_init(privacy).MAIL_NO_ERROR); // not for pgp
    mailprivacy_smime_set_cert_dir(privacy, toStringz(certPath)); // not pgp
    mailprivacy_smime_set_CA_dir(privacy, toStringz(CAPath)); // not pgp
    mailprivacy_smime_set_private_keys_dir(privacy, toStringz(PrivateKeyPath));
    mailprivacy_gnupg_set_encryption_id(privacy, toStringz(gnuID[0]),toStringz(gnuID[1]));
    mailprivacy_smime_set_encryption_id(privacy, toStringz(smimeID[0]),toStringz(smimeID[1]));
  }

  ~this()
  {
    mailprivacy_free(privacy);
  }


  void decryptBuf(ubyte[] buf)
  {
    int col;
    mailmime *mime;
    mailmessage msg = data_message_init(cast(char*)buf, buf.length);
    throwOnError(mailprivacy_msg_get_bodystructure(privacy, msg, &mime),MAIL_NO_ERROR);
    mailmime_write(stdout, &col, mime);

    clist * id_list;
    clistiter * iter;
    
    id_list = mailprivacy_gnupg_encryption_id_list(privacy, msg);
    if (id_list != NULL) {
      for(iter = clist_begin(id_list) ; iter != NULL ; iter = clist_next(iter)) {
        char * str;
        
        str = clist_content(iter);
        fprintf(stderr, "%s\n", str);
      }
    }
  
    scope(exit) // not quite right!
    {
      mailprivacy_gnupg_done(privacy);
      mailmessage_free(msg); 
    }

    mailprivacy_gnupg_encryption_id_list_clear(privacy, msg);
    mailprivacy_smime_done(privacy);
    auto Message=ETPANMessage(msg);
    return Message;
  }


  // protocol = "smime";
  // encryption_method="signed";
  void encrypt(ubyte[] buf, string protocol, string encryption_method)
  {
    int r;
    int res;
    mailmime * mime;
    mailmime * encrypted_mime;
    mailmime * part_to_encrypt;
    
    msg = data_message_init(cast(char*)buf,buf.length);
    throwOnError(mailprivacy_msg_get_bodystructure(this.privacy, msg, &mime),MAIL_NO_ERROR);
    
    part_to_encrypt = mime.mm_data.mm_message.mm_msg_mime;
    
    throwOnError(mailprivacy_encrypt_msg(privacy, protocol, encryption_method, msg, part_to_encrypt, &encrypted_mime),MAIL_NO_ERROR);
    
    mime.mm_data.mm_message.mm_msg_mime = encrypted_mime;
    encrypted_mime.mm_parent = mime;
    part_to_encrypt.mm_parent = NULL;
    mailmime_free(part_to_encrypt);

  if (r != MAIL_NO_ERROR) {
    {
      clist * id_list;
      clistiter * iter;
      
      id_list = mailprivacy_smime_encryption_id_list(privacy, msg);
      if (id_list != NULL) {
        for(iter = clist_begin(id_list) ; iter != NULL ; iter = clist_next(iter)) {
          char * str;
          
          str = clist_content(iter);
          fprintf(stderr, "%s\n", str);
        }
      }
    }
    
    fprintf(stderr, "cannot encrypt\n");
    goto free_content;
  
    auto Message=ETPanMessage(msg);
    scope(exit)
    {
      mailmessage_free(msg);
      mailprivacy_gnupg_done(privacy);
      mailprivacy_free(privacy);
      mailprivacy_smime_done(privacy);
    }
  }
}
  

void encryptMessagePGP(ubyte[] content)
{
  char * content;
  size_t length;
  mailmessage * msg;
  int r;
  mailprivacy * privacy;
  int col;
  char* protocol="pgp";
  char* encryption_method="encrypted";
  throwOnException(msg = data_message_init(content, content.length));

  int res;
  mailmime * mime;
  mailmime * encrypted_mime;
  mailmime * part_to_encrypt;
  
  throwOnException(mailprivacy_msg_get_bodystructure(privacy, msg, &mime),MAIL_NO_ERROR);
  part_to_encrypt = mime.mm_data.mm_message.mm_msg_mime;
  throwOnException(mailprivacy_encrypt_msg(privacy, protocol, encryption_method, msg, part_to_encrypt, &encrypted_mime),MAIL_NO_ERROR);
  mime.mm_data.mm_message.mm_msg_mime = encrypted_mime;
  encrypted_mime.mm_parent = mime;
  part_to_encrypt.mm_parent = NULL;
  mailmime_free(part_to_encrypt); 

  col = 0;
  mailmime_write(stdout, &col, msg.msg_mime);
  
  scope(exit)
  {
    mailmessage_free(msg);
    free(content);
    mailprivacy_gnupg_done(privacy);
    mailprivacy_free(privacy);
  }
}

