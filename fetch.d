module fetch;

  ETPANMessage[] retrieve(ulong[] uuids], bool UUID)
  {
    ETPANMessage[] retmessages;
    foreach(uuid;uuids)
    {
      mailmessage * msg;
      ETPANMessage retmessage;
      char * data;
      size_t size;
      char * uid;
      
      scope(exit)
        mailmessage_free(msg);

      if (UUID)
        throwOnError(mailsession_get_message_by_uid(folder.fld_session, uuid, &msg),MAIL_NO_ERROR);
      else
        throwOnError(mailsession_get_message(folder.fld_session, uuid, &msg),MAIL_NO_ERROR);

      scope(exit)
      {
        mailmessage_fetch_result_free(msg, data);
        mailmessage_free(msg);
      }

      throwOnError(mailmessage_fetch(msg, &data, &size),MAIL_NO_ERROR),&maildriver_strerror);
      retmessage=ETPANMessage(data);
      retmessages~=retmessage;
    }
      
  }

  void updateRead(string[] readMessages)
  {
    msgIDs~=readMessages;
    msgIDs=msgIDs.sort!("a<b").uniq!("a == b").array;
  }

  // info.msg_index is number and .msg_uidl is uuid

  long download()
  {
    switch(this.ct.protocol)
    {
      case POP3_STORAGE:
        throwOnError(mailpop3_list(pop3, &list),MAILPOP3_NO_ERROR);
          foreach(i;0..carray_count(list))
          {
            mailpop3_msg_info * info;
            char * msg_content;
            size_t msg_size;
            long count=0;
          
            info = carray_get(list, i);
            
            if (info.msg_uidl == NULL)
              continue;
            
            msgID~=to!string(info.msg_uidl);
            if (msgIDs.indexOf(msgID)!=-1)
              continue;
            
            throwonError(mailpop3_retr(pop3, info.msg_index, &msg_content, &msg_size),MAILPOP3_NO_ERROR);
            messages~=cast(ubyte[0..msg_size])msg_content;
            mailpop3_retr_free(msg_content);
            count++;
          }
          return count;


      case IMAP_STORAGE:
          mailimap_set * set;
          mailimap_fetch_type * fetch_type;
          mailimap_fetch_att * fetch_att;
          clist * fetch_result;
          clistiter * cur;
          
          /* as improvement UIDVALIDITY should be read and the message cache should be cleaned
             if the UIDVALIDITY is not the same */
          
          set = mailimap_set_new_interval(1, 0); /* fetch in interval 1:* */
          fetch_type = mailimap_fetch_type_new_fetch_att_list_empty();
          fetch_att = mailimap_fetch_att_new_uid();
          mailimap_fetch_type_new_fetch_att_list_add(fetch_type, fetch_att);

          throwOnError(r = mailimap_fetch(imap, set, fetch_type, &fetch_result),imapErrorTable,"imap fetch");
          for(cur = clist_begin(fetch_result) ; cur != NULL ; cur = clist_next(cur))
          {
            mailimap_msg_att * msg_att;
            uint uid;
            msg_att = clist_content(cur);
            uid = get_uid(msg_att);
            if (uid == 0)
              continue;

            fetch_msg(imap, uid);
          }

          mailimap_fetch_list_free(fetch_result);
          break;
      default:
          break;
    }
  }


ubyte[] get_msg_att_msg_content(mailimap_msg_att * msg_att)
{
  ubyte[] retbuf;
  clistiter * cur;
  
  /* iterate on each result of one given message */
  for(cur = clist_begin(msg_att.att_list) ; cur != NULL ; cur = clist_next(cur))
  {
    mailimap_msg_att_item * item;
    
    item = clist_content(cur);
    if (item.att_type != MAILIMAP_MSG_ATT_ITEM_STATIC) {
      continue;
    }
    
    if (item.att_data.att_static.att_type != MAILIMAP_MSG_ATT_BODY_SECTION) {
      continue;
    }
    
    auto msgsize= item.att_data.att_static.att_data.att_body_section.sec_length;
    return cast(ubyte[0..msgsize])item.att_data.att_static.att_data.att_body_section.sec_body_part;
  }
  
  return NULL;
}

ubyte[] get_msg_content(clist * fetch_result)
{
  clistiter * cur;
  /* for each message (there will be probably only on message) */
  for(cur = clist_begin(fetch_result) ; cur != NULL ; cur = clist_next(cur)) {
    struct mailimap_msg_att * msg_att;
    size_t msg_size;
    char * msg_content;
    
    msg_att = clist_content(cur);
    msg_content = get_msg_att_msg_content(msg_att, &msg_size);
    if (msg_content == NULL) {
      continue;
    }
    
    auto p_msg_size = msg_size;
    return cast(ubyte[0..msgsize])msg_content);
  }
  
  return NULL;
}

ubyte[] fetch_msg(mailimap * imap, uint uid)
{
  ubyte[] buf;
  mailimap_set * set;
  mailimap_section * section;
  char[512] filename;
  size_t msg_len;
  char * msg_content;
  mailimap_fetch_type * fetch_type;
  mailimap_fetch_att * fetch_att;
  int r;
  clist * fetch_result;
  stat stat_info;
  
  set = mailimap_set_new_single(uid);
  fetch_type = mailimap_fetch_type_new_fetch_att_list_empty();
  section = mailimap_section_new(NULL);
  fetch_att = mailimap_fetch_att_new_body_peek_section(section);
  mailimap_fetch_type_new_fetch_att_list_add(fetch_type, fetch_att);

  r = mailimap_uid_fetch(imap, set, fetch_type, &fetch_result);
  check_error(r, "could not fetch");
  
  scope(exit)
    mailimap_fetch_list_free(fetch_result);

  throwOnError(msg_content = get_msg_content(fetch_result, &msg_len));
  buf=cast(ubyte[0..msg_len] msg_content);
  return buf;
}

uint get_uid(mailimap_msg_att * msg_att)
{
  clistiter * cur;
  /* iterate on each result of one given message */
  for(cur = clist_begin(msg_att.att_list) ; cur != NULL ; cur = clist_next(cur))
  {
    mailimap_msg_att_item * item;
    
    item = clist_content(cur);
    if ( (item.att_type != MAILIMAP_MSG_ATT_ITEM_STATIC)
      continue;
    
    if (item.att_data.att_static.att_type != MAILIMAP_MSG_ATT_UID)
      continue;
    
    return item.att_data.att_static.att_data.att_uid;
  }
  return 0;
}


/* get part of the from field to display */

void get_from_value(struct mailimf_single_fields * fields,
    char ** from, int * is_addr)
{
  struct mailimf_mailbox * mb;
  
  if (fields.fld_from == NULL) {
    * from = NULL;
    * is_addr = 0;
    return;
  }

  if (clist_isempty(fields.fld_from.frm_mb_list.mb_list)) {
    * from = NULL;
    * is_addr = 0;
    return;
  }

  mb = clist_begin(fields.fld_from.frm_mb_list.mb_list).data;

  if (mb.mb_display_name != NULL) {
    * from = mb.mb_display_name;
    * is_addr = 0;
  }
  else {
    * from = mb.mb_addr_spec;
    * is_addr = 1;
  }
}

/* remove all CR and LF of a string and replace them with SP */

void strip_crlf(ubyte[] str)
{
  char * p;
  
  for(p = str ; * p != '\0' ; p ++) {
    if ((* p == '\n') || (* p == '\r'))
      * p = ' ';
  }
}

enum MAX_OUTPUT=81;

/* display information for one message */

void print_mail_info(char * prefix, mailmessage * msg)
{
  char * from;
  char * subject;
  char * decoded_from;
  char * decoded_subject;
  size_t cur_token;
  int r;
  int is_addr;
  char * dsp_from;
  char * dsp_subject;
  char output[MAX_OUTPUT];
  struct mailimf_single_fields single_fields;
  
  is_addr = 0;
  from = NULL;
  subject = NULL;

  decoded_subject = NULL;
  decoded_from = NULL;

  /* from field */
  
  if (msg.msg_fields != NULL)
    mailimf_single_fields_init(&single_fields, msg.msg_fields);
  else
    memset(&single_fields, 0, sizeof(single_fields));
  
  get_from_value(&single_fields, &from, &is_addr);
  
  if (from == NULL)
    decoded_from = NULL;
  else {
    if (!is_addr) {
      cur_token = 0;
      r = mailmime_encoded_phrase_parse(DEST_CHARSET,
          from, strlen(from),
          &cur_token, DEST_CHARSET,
          &decoded_from);
      if (r != MAILIMF_NO_ERROR) {
        decoded_from = strdup(from);
        if (decoded_from == NULL)
          goto err;
      }
    }
    else {
      decoded_from = strdup(from);
      if (decoded_from == NULL) {
        goto err;
      }
    }
  }

  if (decoded_from == NULL)
    dsp_from = "";
  else {
    dsp_from = decoded_from;
    strip_crlf(dsp_from);
  }

  /* subject */

  if (single_fields.fld_subject != NULL)
    subject = single_fields.fld_subject.sbj_value;
    
  if (subject == NULL)
    decoded_subject = NULL;
  else {
    cur_token = 0;
    r = mailmime_encoded_phrase_parse(DEST_CHARSET,
        subject, strlen(subject),
        &cur_token, DEST_CHARSET,
        &decoded_subject);
    if (r != MAILIMF_NO_ERROR) {
      decoded_subject = strdup(subject);
      if (decoded_subject == NULL)
        goto free_from;
    }
  }

  if (decoded_subject == NULL)
    dsp_subject = "";
  else {
    dsp_subject = decoded_subject;
    strip_crlf(dsp_subject);
  }

  snprintf(output, MAX_OUTPUT, "%3i: %-21.21s %s%-53.53s",
      msg.msg_index, dsp_from, prefix, dsp_subject);
  
  writefln("%s", output);

  if (decoded_subject != NULL)
    free(decoded_subject);
  if (decoded_from != NULL)
    free(decoded_from);

  return;

 free_from:
  if (decoded_from)
    free(decoded_from);
 err:
  {}
}



